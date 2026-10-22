import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect } from 'chai';

import { OpenShiftAuth, STATE, openshiftConfigFromEnv, serviceAccountSubject } from '../../lib/openshift.js';

const quiet = { info() {}, warn() {} };
const API = 'https://api.test';

// eslint-disable-next-line unicorn/prefer-uint8array-base64 -- Uint8Array base64 needs Node 25; engines allow Node 22
const base64url = (text) => btoa(text).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const jwt = (claims) => `e30.${base64url(JSON.stringify(claims))}.sig`;

// A fake OpenShift API + OAuth server behind the injectable request function.
const fakeCluster = (over = {}) => {
  const calls = [];
  const users = { 'tok-alice': { name: 'alice', groups: ['sres', 'system:authenticated'] } };
  const request = async (url, opts = {}) => {
    calls.push({ url, opts });
    if (over.down) {
      throw new Error('connect ECONNREFUSED');
    }
    if (url === `${API}/.well-known/oauth-authorization-server`) {
      if (over.noOAuth) {
        return { status: 404, json: null };
      }
      return { status: 200, json: { issuer: 'https://oauth.test', authorization_endpoint: 'https://oauth.test/oauth/authorize', token_endpoint: 'https://oauth.test/oauth/token', code_challenge_methods_supported: ['S256'] } };
    }
    if (url === 'https://oauth.test/healthz') {
      return { status: 200, json: null };
    }
    if (url === 'https://oauth.test/oauth/token') {
      const body = new URLSearchParams(opts.body);
      const basic = opts.headers.Authorization;
      if (basic && over.rejectBasic) {
        return { status: 401, json: { error: 'invalid_client' } };
      }
      const id = basic
        // eslint-disable-next-line unicorn/prefer-uint8array-base64 -- see lib/openshift.js
        ? decodeURIComponent(atob(basic.slice(6)).split(':', 1)[0])
        : body.get('client_id');
      if (id !== 'system:serviceaccount:ns1:mongo-express') {
        return { status: 401, json: { error: 'invalid_client' } };
      }
      if (body.get('code') !== 'good' || !body.get('code_verifier')) {
        return { status: 400, json: { error: 'invalid_grant' } };
      }
      return { status: 200, json: { access_token: 'tok-alice', expires_in: 3600 } };
    }
    if (url === `${API}/apis/user.openshift.io/v1/users/~`) {
      const u = users[(opts.headers.Authorization || '').replace('Bearer ', '')];
      return u ? { status: 200, json: { metadata: { name: u.name }, groups: u.groups } } : { status: 401, json: null };
    }
    return { status: 404, json: null };
  };
  return { request, calls };
};

describe('OpenShift login client', () => {
  let dir;
  let cfg;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'me-os-'));
    fs.writeFileSync(path.join(dir, 'token'), jwt({ sub: 'system:serviceaccount:ns1:mongo-express' }));
    cfg = { ...openshiftConfigFromEnv({ ME_CONFIG_OPENSHIFT_OAUTH: 'auto' }), apiUrl: API, tokenFile: path.join(dir, 'token'), caFile: '' };
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('reads its configuration from the environment', () => {
    expect(openshiftConfigFromEnv({}).enabled).to.equal('false');
    expect(openshiftConfigFromEnv({ ME_CONFIG_OPENSHIFT_OAUTH: 'AUTO' }).enabled).to.equal('auto');
    expect(openshiftConfigFromEnv({ ME_CONFIG_OPENSHIFT_OAUTH: 'bogus' }).enabled).to.equal('false');
    expect(serviceAccountSubject(jwt({ sub: 'system:serviceaccount:a:b' }))).to.equal('system:serviceaccount:a:b');
    expect(serviceAccountSubject('nope')).to.equal('');
  });

  it('runs the authorization code flow with PKCE', async () => {
    const { request } = fakeCluster();
    const os1 = new OpenShiftAuth(cfg, { request, logger: quiet });
    const st = await os1.probe();
    expect(st.state).to.equal(STATE.available);
    const attempt = os1.begin('https://me.apps/oauth/callback');
    const q = new URL(attempt.url).searchParams;
    expect(q.get('client_id')).to.equal('system:serviceaccount:ns1:mongo-express');
    expect(q.get('code_challenge_method')).to.equal('S256');
    expect(q.get('state')).to.equal(attempt.state);
    const { token, expiresInMs } = await os1.exchange('good', attempt.verifier, 'https://me.apps/oauth/callback');
    expect(token).to.equal('tok-alice');
    expect(expiresInMs).to.equal(3_600_000);
    expect(await os1.review(token)).to.deep.equal({ name: 'alice', groups: ['sres', 'system:authenticated'] });
    try {
      await os1.review('tok-unknown');
      expect.fail('should have thrown');
    } catch (error) {
      expect(error.rejected).to.equal(true);
    }
  });

  it('falls back to body credentials when Basic is rejected', async () => {
    const { request } = fakeCluster({ rejectBasic: true });
    const os1 = new OpenShiftAuth(cfg, { request, logger: quiet });
    await os1.probe();
    const attempt = os1.begin('https://me.apps/oauth/callback');
    const { token } = await os1.exchange('good', attempt.verifier, 'https://me.apps/oauth/callback');
    expect(token).to.equal('tok-alice');
  });

  it('is passive when OpenShift is missing or unreachable', async () => {
    const stateOf = async (c, cluster) => {
      const st = await new OpenShiftAuth(c, { request: cluster.request, logger: quiet }).probe();
      return st.state;
    };
    const noToken = { ...cfg, tokenFile: path.join(dir, 'missing') };
    expect(await stateOf(cfg, fakeCluster({ down: true }))).to.equal(STATE.unavailable);
    expect(await stateOf(cfg, fakeCluster({ noOAuth: true }))).to.equal(STATE.disabled);
    expect(await stateOf(noToken, fakeCluster())).to.equal(STATE.disabled);
    expect(await stateOf({ ...noToken, enabled: 'true' }, fakeCluster())).to.equal(STATE.unavailable);
    expect(await stateOf({ ...cfg, enabled: 'false' }, fakeCluster())).to.equal(STATE.disabled);
    const off = new OpenShiftAuth({ ...cfg, enabled: 'false' }, { request: fakeCluster().request, logger: quiet });
    expect(off.begin('x')).to.equal(null);
  });
});
