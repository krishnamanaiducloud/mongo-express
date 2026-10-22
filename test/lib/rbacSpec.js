import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect } from 'chai';

import { glob, Policy, PolicyStore, subjectsOf } from '../../lib/rbac.js';

const quiet = { info() {}, warn() {} };

describe('RBAC policy', () => {
  const policy = new Policy(`
g, devs, role:readonly
g, editors, role:editor
g, sres, role:admin
p, role:orders, documents, *, shop/orders*, allow
p, role:orders, documents, delete, shop/orders_archive, deny
g, group:payments, role:orders
`, '');

  const cases = [
    [['devs'], 'documents', 'get', 'app/x', true],
    [['devs'], 'documents', 'create', 'app/x', false],
    [['devs'], 'databases', 'create', 'new', false],
    [['editors'], 'documents', 'delete', 'app/x', true],
    [['editors'], 'collections', 'delete', 'app/x', false],
    [['editors'], 'gridfs', 'create', 'app/fs', true],
    [['sres'], 'databases', 'delete', 'app', true],
    [['sres'], 'server', 'update', '*', true],
    [['group:payments'], 'documents', 'update', 'shop/orders', true],
    [['group:payments'], 'documents', 'update', 'shop/customers', false],
    [['group:payments'], 'documents', 'delete', 'shop/orders_archive', false],
    [['nobody'], 'documents', 'get', 'app/x', false],
  ];
  for (const [subjects, resource, action, object, want] of cases) {
    it(`${subjects} ${action} ${resource} ${object} -> ${want}`, () => {
      expect(policy.allowed(subjects, resource, action, object)).to.equal(want);
    });
  }

  it('applies the default role and extra roles', () => {
    const p = new Policy('', 'role:readonly');
    expect(p.allowed(['anyone'], 'documents', 'get', 'a/b')).to.equal(true);
    expect(p.allowed(['anyone'], 'documents', 'update', 'a/b')).to.equal(false);
    expect(p.allowed(['anyone'], 'documents', 'update', 'a/b', ['role:admin'])).to.equal(true);
  });

  it('rejects invalid lines', () => {
    for (const line of ['p, admin, documents, get, *', 'p, role:x, nothing, get, *', 'p, role:x, documents, use, *',
      'p, role:x, documents, get, *, maybe', 'g, devs', 'g, devs, admins', 'x, y, z']) {
      expect(() => new Policy(line, '')).to.throw();
    }
    expect(() => new Policy('', 'readonly')).to.throw();
  });

  it('matches globs', () => {
    expect(glob('app/*', 'app/orders')).to.equal(true);
    expect(glob('app/*', 'apps/orders')).to.equal(false);
    expect(glob('a?c', 'abc')).to.equal(true);
    expect(glob('*/logs', 'x/logs2')).to.equal(false);
  });

  it('derives subjects', () => {
    expect(subjectsOf({ name: 'alice', groups: ['sres'], source: 'openshift' })).to.deep.equal(['alice', 'user:alice', 'sres', 'group:sres']);
    expect(subjectsOf({ name: 'admin', source: 'local' })).to.deep.equal(['local:admin']);
  });
});

describe('RBAC policy store', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'me-rbac-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('loads the directory and keeps the last good policy after a bad edit', () => {
    const store = new PolicyStore({ dir, defaultRole: 'role:readonly', logger: quiet });
    expect(store.source).to.equal('built-in');
    fs.writeFileSync(path.join(dir, 'policy.csv'), 'g, sres, role:admin\n');
    fs.writeFileSync(path.join(dir, 'policy.default'), '');
    store.reload();
    expect(store.source).to.equal('file');
    expect(store.policy.allowed(['sres'], 'databases', 'delete', 'x')).to.equal(true);
    expect(store.policy.allowed(['other'], 'documents', 'get', 'a/b')).to.equal(false);

    fs.writeFileSync(path.join(dir, 'policy.csv'), 'garbage\n');
    store.reload();
    expect(store.error).to.not.equal('');
    expect(store.policy.allowed(['sres'], 'databases', 'delete', 'x')).to.equal(true);
  });

  it('refuses an invalid inline policy', () => {
    expect(() => new PolicyStore({ inline: 'p, broken', logger: quiet })).to.throw();
  });
});
