import { expect } from 'chai';
import supertest from 'supertest';

import defaultConf from '../../testDefaultConfig.js';
import middleware from '../../../lib/middleware.js';
import { Access } from '../../../lib/access.js';
import { STATE } from '../../../lib/openshift.js';
import { cleanAndCloseDb, initializeDb, testDbName as dbName, testURLCollectionName as urlColName } from '../../testMongoUtils.js';

const quiet = { info() {}, warn() {} };

const policy = `
g, sres, role:admin
g, devs, role:readonly
g, editors, role:editor
`;

// A stand-in for the OpenShift OAuth server (the client itself is tested in openshiftSpec).
const fakeOpenShift = (users, { available = true } = {}) => ({
  available: () => available,
  status: () => (available ? { state: STATE.available } : { state: STATE.unavailable, reason: 'unreachable' }),
  probe: async () => ({ state: available ? STATE.available : STATE.unavailable }),
  start() {},
  stop() {},
  begin: () => (available ? { url: 'https://oauth.test/oauth/authorize?x=1', state: 'the-state', verifier: 'v' } : null),
  exchange: async (code) => {
    if (!users[code]) {
      throw Object.assign(new Error('bad code'), { rejected: true });
    }
    return { token: `tok-${code}`, expiresInMs: 3_600_000 };
  },
  review: async (token) => users[token.replace('tok-', '')],
});

const serverWith = async (overrides, openshift) => {
  const config = defaultConf();
  Object.assign(config, overrides);
  config.openshift = { enabled: 'auto', revalidateMs: 300_000, maxStaleMs: 3_600_000 };
  config.rbac = { policy, defaultRole: 'role:readonly', localRole: 'role:admin' };
  config.access = new Access(config, { logger: quiet, openshiftAuth: openshift });
  const app = await middleware(config);
  const httpServer = app.listen();
  return { request: supertest.agent(httpServer), close: () => { httpServer.close(); config.access.close(); } };
};

const locationOf = async (request, url) => {
  const res = await request.get(url);
  return res.headers.location;
};

const signInWithOpenShift = async (request, code) => {
  const start = await request.get('/oauth/start?return=/');
  expect(start.status).to.equal(302);
  expect(start.headers.location).to.match(/^https:\/\/oauth\.test\//);
  return request.get(`/oauth/callback?code=${code}&state=the-state`);
};

describe('OpenShift login and RBAC', () => {
  let client;
  before(() => initializeDb().then((c) => { client = c; }));
  after(() => cleanAndCloseDb(client));

  const users = {
    alice: { name: 'alice', groups: ['sres'] },
    bob: { name: 'bob', groups: ['devs'] },
    eve: { name: 'eve', groups: ['other'] },
  };

  it('sends anonymous visitors to the sign-in page with the OpenShift button', async () => {
    const s = await serverWith({ useBasicAuth: true, basicAuth: { username: 'local', password: 'pw' } }, fakeOpenShift(users));
    try {
      const home = await s.request.get('/');
      expect(home.status).to.equal(302);
      expect(home.headers.location).to.equal('/login');
      const page = await s.request.get('/login');
      expect(page.text).to.include('Log in with OpenShift');
      expect(page.text).to.include('name="password"');
      // No basic-auth prompt with OpenShift login.
      expect(home.headers['www-authenticate']).to.equal(undefined);
    } finally {
      s.close();
    }
  });

  it('signs in with OpenShift and maps groups to roles', async () => {
    const s = await serverWith({}, fakeOpenShift(users));
    try {
      const cb = await signInWithOpenShift(s.request, 'alice');
      expect(cb.status).to.equal(302);
      expect(cb.headers.location).to.equal('/');
      const home = await s.request.get('/');
      expect(home.status).to.equal(200);
      expect(home.text).to.include('alice');
      expect(home.text).to.include('role:admin');
      expect(home.text).to.include('Create database');
    } finally {
      s.close();
    }
  });

  it('enforces read-only roles on the server and hides write controls', async () => {
    const s = await serverWith({}, fakeOpenShift(users));
    try {
      await signInWithOpenShift(s.request, 'bob');
      const home = await s.request.get('/');
      expect(home.status).to.equal(200);
      expect(home.text).to.not.include('Create database');
      const create = await s.request.post('/').type('form').send({ database: 'not_allowed' });
      expect(create.status).to.equal(403);
      expect(create.text).to.include('Not permitted');
      const add = await s.request.post(`/db/${dbName}/${urlColName}`).send({ document: '{rbac:true}' });
      expect(add.status).to.equal(403);
      const view = await s.request.get(`/db/${dbName}/${urlColName}`);
      expect(view.status).to.equal(200);
    } finally {
      s.close();
    }
  });

  it('rejects a forged or replayed OAuth state and failed exchanges', async () => {
    const s = await serverWith({}, fakeOpenShift(users));
    try {
      expect(await locationOf(s.request, '/oauth/callback?code=alice&state=the-state')).to.equal('/login?sso=expired');
      await s.request.get('/oauth/start');
      expect(await locationOf(s.request, '/oauth/callback?code=alice&state=wrong')).to.equal('/login?sso=failed');
      await s.request.get('/oauth/start');
      expect(await locationOf(s.request, '/oauth/callback?code=unknown&state=the-state')).to.equal('/login?sso=failed');
      await s.request.get('/oauth/start');
      expect(await locationOf(s.request, '/oauth/callback?error=access_denied&state=the-state')).to.equal('/login?sso=denied');
      const home = await s.request.get('/');
      expect(home.status).to.equal(302);
    } finally {
      s.close();
    }
  });

  it('falls back to the local account when OpenShift is unavailable (no error)', async () => {
    const s = await serverWith({ useBasicAuth: true, basicAuth: { username: 'local', password: 'pw' } }, fakeOpenShift(users, { available: false }));
    try {
      const page = await s.request.get('/login');
      expect(page.status).to.equal(200);
      expect(page.text).to.not.include('Log in with OpenShift');
      expect(page.text).to.include('not available right now');
      expect(await locationOf(s.request, '/oauth/start')).to.equal('/login?sso=unavailable');
      const login = await s.request.post('/login').type('form').send({ username: 'local', password: 'pw' });
      expect(login.status).to.equal(302);
      const home = await s.request.get('/');
      expect(home.status).to.equal(200);
      expect(home.text).to.include('Local account');
      expect(home.text).to.include('role:admin');
    } finally {
      s.close();
    }
  });

  it('applies the default role to unmapped OpenShift users', async () => {
    const s = await serverWith({}, fakeOpenShift(users));
    try {
      await signInWithOpenShift(s.request, 'eve');
      const home = await s.request.get('/');
      expect(home.status).to.equal(200);
      expect(home.text).to.include('role:readonly');
      const create = await s.request.post('/').type('form').send({ database: 'x' });
      expect(create.status).to.equal(403);
    } finally {
      s.close();
    }
  });
});
