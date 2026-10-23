import fs from 'node:fs';
import path from 'node:path';

/*
 * Argo CD-style role-based access control.
 *
 * A policy is CSV with two kinds of lines:
 *
 *   p, <role>, <resource>, <action>, <object>[, allow|deny]
 *   g, <subject>, <role>
 *
 * Roles are "role:<name>". Subjects are OpenShift user or group names (matched as
 * given, like Argo CD), "user:<name>" / "group:<name>", or "local:<name>" for the
 * mongo-express local account (basic or form sign-in). A "g" line may also make one
 * role inherit another. Objects are globs ('*' any text, '?' one character) over
 * "<database>" or "<database>/<collection>".
 *
 * A request is allowed when a rule of the subject's roles allows it and none denies
 * it. mongo-express connects with one shared connection string, so RBAC is what
 * separates what different users may do here; MongoDB still limits that account.
 */

export const ACTIONS = {
  databases: ['get', 'create', 'delete'],
  collections: ['get', 'create', 'update', 'delete'],
  documents: ['get', 'create', 'update', 'delete'],
  indexes: ['get', 'create', 'delete'],
  gridfs: ['get', 'create', 'delete'],
  // server: the connection settings form shown when MongoDB is unreachable.
  server: ['get', 'update'],
};

export const BUILTIN_POLICY = `
p, role:readonly, databases, get, *, allow
p, role:readonly, collections, get, *, allow
p, role:readonly, documents, get, *, allow
p, role:readonly, indexes, get, *, allow
p, role:readonly, gridfs, get, *, allow
p, role:readonly, server, get, *, allow

g, role:editor, role:readonly
p, role:editor, documents, create, *, allow
p, role:editor, documents, update, *, allow
p, role:editor, documents, delete, *, allow
p, role:editor, indexes, create, *, allow
p, role:editor, indexes, delete, *, allow
p, role:editor, collections, create, *, allow
p, role:editor, gridfs, create, *, allow
p, role:editor, gridfs, delete, *, allow

p, role:admin, *, *, *, allow
`;

/** Glob match where '*' matches any text (including '/') and '?' one character. */
export const glob = function (pattern, value) {
  if (pattern === '*') {
    return true;
  }
  const p = [...pattern];
  const t = [...value];
  let pi = 0;
  let ti = 0;
  let star = -1;
  let mark = 0;
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) {
      pi++;
      ti++;
    } else if (pi < p.length && p[pi] === '*') {
      star = pi;
      mark = ti;
      pi++;
    } else if (star >= 0) {
      pi = star + 1;
      mark++;
      ti = mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') {
    pi++;
  }
  return pi === p.length;
};

const match = (pattern, value) => pattern === '*' || pattern === value;

export class Policy {
  constructor(csv = '', defaultRole = '') {
    this.rules = new Map();
    this.grants = new Map();
    this.defaultRole = String(defaultRole || '').trim();
    const errors = [...this.#add(BUILTIN_POLICY, 'built-in policy'), ...this.#add(csv, 'policy')];
    if (this.defaultRole && !this.defaultRole.startsWith('role:')) {
      errors.push(`default role "${this.defaultRole}" must start with "role:"`);
    }
    if (errors.length > 0) {
      throw new Error(errors.join('; '));
    }
  }

  #add(csv, name) {
    const errors = [];
    const lines = String(csv || '').split(/\r?\n/);
    for (const [i, raw] of lines.entries()) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) {
        continue;
      }
      const err = this.#addLine(line.split(',').map((x) => x.trim()));
      if (err) {
        errors.push(`${name} line ${i + 1}: ${err}`);
      }
    }
    return errors;
  }

  #addLine(f) {
    if (f[0] === 'p') {
      if (f.length !== 5 && f.length !== 6) {
        return '"p" lines need: p, role, resource, action, object[, allow|deny]';
      }
      const [, role, resource, action, object] = f;
      if (role === 'role:' || !role.startsWith('role:')) {
        return `role "${role}" must be named role:<name>`;
      }
      const effect = (f[5] || 'allow').toLowerCase();
      if (effect !== 'allow' && effect !== 'deny') {
        return `effect "${effect}" must be allow or deny`;
      }
      if (resource !== '*') {
        if (!Object.hasOwn(ACTIONS, resource)) {
          return `unknown resource "${resource}"`;
        }
        if (action !== '*' && !ACTIONS[resource].includes(action)) {
          return `action "${action}" is not valid for ${resource}`;
        }
      }
      if (!object) {
        return 'object must not be empty (use * for all)';
      }
      if (!this.rules.has(role)) {
        this.rules.set(role, []);
      }
      this.rules.get(role).push({ role, resource, action, object, effect });
      return null;
    }
    if (f[0] === 'g') {
      if (f.length !== 3) {
        return '"g" lines need: g, subject, role';
      }
      if (!f[1] || !f[2].startsWith('role:')) {
        return 'g line must map a subject to a role:<name>';
      }
      if (!this.grants.has(f[1])) {
        this.grants.set(f[1], []);
      }
      if (!this.grants.get(f[1]).includes(f[2])) {
        this.grants.get(f[1]).push(f[2]);
      }
      return null;
    }
    return `line must start with p or g, not "${f[0]}"`;
  }

  /**
   * Roles of subjects, including inherited roles and extra roles granted outside the
   * policy (the configured role of the local account). The default role applies only
   * when no g line maps any of the subjects.
   */
  roles(subjects, extra = []) {
    const seen = new Set();
    const walk = (role) => {
      if (seen.has(role)) {
        return;
      }
      seen.add(role);
      const inherited = this.grants.get(role) || [];
      for (const r of inherited) {
        walk(r);
      }
    };
    for (const s of subjects) {
      const granted = this.grants.get(s) || [];
      for (const r of granted) {
        walk(r);
      }
    }
    // The default role is for subjects no g line maps, so a mapping restricts.
    if (seen.size === 0 && this.defaultRole) {
      walk(this.defaultRole);
    }
    for (const r of extra) {
      if (r) {
        walk(r);
      }
    }
    return [...seen].sort();
  }

  allowed(subjects, resource, action, object, extra = []) {
    const rules = this.roles(subjects, extra).flatMap((role) => this.rules.get(role) || []);
    const matching = rules.filter((r) => match(r.resource, resource) && match(r.action, action) && glob(r.object, object));
    // Deny wins over allow.
    return matching.length > 0 && matching.every((r) => r.effect !== 'deny');
  }

  /** Subjects named in g lines (not roles): the groups worth remembering. */
  subjects() {
    return this.grants.keys().filter((s) => !s.startsWith('role:')).toArray();
  }
}

/** RBAC subjects of a principal { name, groups, source }. */
export const subjectsOf = function (principal) {
  if (!principal) {
    return [];
  }
  if (principal.source === 'local') {
    return [`local:${principal.name}`];
  }
  const out = [principal.name, `user:${principal.name}`];
  const groups = principal.groups || [];
  for (const g of groups) {
    out.push(g, `group:${g}`);
  }
  return out;
};

/**
 * Holds the active policy and re-reads an optional policy directory (the keys of an
 * Argo CD-style RBAC ConfigMap: policy.csv, policy.default). An invalid update is
 * rejected and the previous policy stays active, so a bad edit never locks people out.
 */
export class PolicyStore {
  constructor({ inline = '', defaultRole = 'role:readonly', dir = '', logger = console } = {}) {
    this.inline = inline;
    this.configDefault = defaultRole;
    this.dir = dir;
    this.logger = logger;
    this.error = '';
    this.digest = '';
    // The inline policy is configuration: an error there is fatal.
    this.policy = new Policy(inline, defaultRole);
    this.source = inline.trim() ? 'config' : 'built-in';
    this.reload();
  }

  #read() {
    let csv = this.inline;
    let def = this.configDefault;
    let fromFile = false;
    if (this.dir) {
      for (const [file, apply] of [
        ['policy.csv', (v) => { csv += `\n${v}`; }],
        ['policy.default', (v) => { def = v.trim(); }],
      ]) {
        try {
          apply(fs.readFileSync(path.join(this.dir, file), 'utf8'));
          fromFile = true;
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw error;
          }
        }
      }
    }
    return { csv, def, fromFile };
  }

  reload() {
    try {
      const { csv, def, fromFile } = this.#read();
      const digest = `${csv}\0${def}\0${fromFile}`;
      if (digest === this.digest && !this.error) {
        return;
      }
      this.digest = digest;
      this.policy = new Policy(csv, def);
      this.source = fromFile ? 'file' : (this.inline.trim() ? 'config' : 'built-in');
      if (this.error) {
        this.logger.info?.('RBAC policy update accepted');
      }
      this.error = '';
    } catch (error) {
      if (this.error !== error.message) {
        this.logger.warn?.(`RBAC policy update rejected; keeping the previous policy: ${error.message}`);
      }
      this.error = error.message;
    }
  }

  watch(intervalMs = 30_000) {
    if (!this.dir || intervalMs <= 0) {
      return () => {};
    }
    const t = setInterval(() => this.reload(), intervalMs);
    t.unref?.();
    return () => clearInterval(t);
  }
}
