import { timingSafeEqual } from 'node:crypto';
import { OpenShiftAuth, STATE } from './openshift.js';
import { PolicyStore, subjectsOf } from './rbac.js';
import { verifyCredentials } from './auth.js';

/*
 * Who is using mongo-express and what they may do.
 *
 * Principals:
 *   - openshift: signed in with the built-in OpenShift login (session based);
 *   - oidc:      signed in with OpenID Connect (express-openid-connect);
 *   - local:     the configured local account (basic auth or the sign-in form), or
 *                nobody when no authentication is configured (upstream behaviour).
 *
 * Every route is authorized with the RBAC policy (lib/rbac.js), and the templates
 * receive per-request settings so they only offer what the user may do.
 */

const STATE_TTL_MS = 10 * 60_000;

const sameString = (a, b) => {
  const x = Buffer.from(String(a ?? ''));
  const y = Buffer.from(String(b ?? ''));
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
};

const safeReturn = (p, base) => (typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !p.startsWith('/\\') && !/[\r\n]/.test(p) ? p : base);

export class Access {
  constructor(config, { logger = console, openshiftAuth } = {}) {
    this.config = config;
    this.logger = logger;
    this.base = config.site.baseUrl || '/';
    const rbac = config.rbac || {};
    this.store = new PolicyStore({
      inline: rbac.policy || '',
      defaultRole: rbac.defaultRole ?? 'role:readonly',
      dir: rbac.policyDir || '',
      logger,
    });
    this.stopWatch = this.store.watch(rbac.reloadIntervalMs ?? 30_000);
    this.localRole = rbac.localRole ?? 'role:admin';
    const os = config.openshift || { enabled: 'false' };
    this.openshift = openshiftAuth || (os.enabled === 'false' ? null : new OpenShiftAuth(os, { logger }));
    this.openshift?.start();
  }

  #extra(p) {
    return p?.source === 'local' ? [this.localRole] : [];
  }

  /** Groups worth keeping in a session: the ones the policy mentions. */
  #keepGroups(groups) {
    const subjects = new Set(this.store.policy.subjects());
    return groups.filter((g) => subjects.has(g) || subjects.has(`group:${g}`)).slice(0, 64);
  }

  #redirectUri(req) {
    const origin = this.config.openshift?.publicUrl || `${req.protocol}://${req.get('host')}`;
    return `${origin}${this.base}oauth/callback`;
  }

  /** True when the built-in OpenShift login is configured (auto or true). */
  get ssoConfigured() {
    return Boolean(this.openshift);
  }

  close() {
    this.stopWatch?.();
    this.openshift?.stop();
  }

  // ---- principals ----

  principal(req) {
    if (this.ssoConfigured) {
      return req.session?.principal || null;
    }
    const user = req.oidc?.user;
    if (user) {
      const name = user.preferred_username || user.email || user.sub;
      return { name: String(name), groups: Array.isArray(user.groups) ? user.groups.map(String) : [], source: 'oidc' };
    }
    return { name: this.config.useBasicAuth ? this.config.basicAuth.username : 'anonymous', groups: [], source: 'local' };
  }

  roles(req) {
    const p = this.principal(req);
    return p ? this.store.policy.roles(subjectsOf(p), this.#extra(p)) : [];
  }

  allowed(req, resource, action, object) {
    const p = this.principal(req);
    return Boolean(p) && this.store.policy.allowed(subjectsOf(p), resource, action, object, this.#extra(p));
  }

  // ---- OpenShift login routes ----

  loginPath() {
    return `${this.base}login`;
  }

  /** Registers sign-in, OpenShift OAuth and sign-out routes, then the session gate. */
  mountSSO(router, limiter) {
    const login = this.loginPath();
    const localLogin = this.config.useBasicAuth === true;
    const open = new Set([login, `${this.base}oauth/start`, `${this.base}oauth/callback`, this.config.healthCheck.path]);

    router.use(login, limiter);
    router.use(`${this.base}oauth`, limiter);

    router.get(login, (req, res) => {
      const sso = req.query.sso;
      res.render('signin', {
        baseHref: this.base,
        loginUrl: login,
        csrfToken: req.csrfToken(),
        openshift: this.openshift.status(),
        openshiftAvailable: this.openshift.available(),
        openshiftUrl: `${this.base}oauth/start`,
        localLogin,
        ssoMessage: {
          unavailable: 'OpenShift sign-in is not available right now.',
          failed: 'OpenShift sign-in did not complete. Please try again.',
          denied: 'OpenShift sign-in was cancelled.',
          expired: 'The OpenShift sign-in took too long. Please start again.',
        }[sso] || '',
        messageError: req.session.error,
        signedOut: req.query.signedout === '1',
      });
      delete req.session.error;
    });

    router.post(login, (req, res) => {
      if (!localLogin) {
        req.session.error = 'Local sign-in is not enabled.';
        return res.redirect(login);
      }
      const { username, password } = req.body;
      if (!verifyCredentials(this.config, username, password)) {
        req.session.error = 'Invalid username or password.';
        return res.redirect(login);
      }
      return req.session.regenerate((error) => {
        if (error) {
          req.session.error = 'Could not start a session. Please try again.';
          return res.redirect(login);
        }
        req.session.authenticated = true;
        req.session.principal = { name: String(username), groups: [], source: 'local' };
        return res.redirect(this.base);
      });
    });

    router.get(`${this.base}oauth/start`, async (req, res) => {
      // Re-check a stale "unavailable" result, at most every 15s, so anonymous
      // requests cannot drive probe traffic.
      const st = this.openshift.status();
      const lastCheck = st.checkedAt ? Date.parse(st.checkedAt) : 0;
      if (st.state === 'unavailable' && Date.now() - lastCheck > 15_000) {
        await this.openshift.probe().catch(() => {});
      }
      const attempt = this.openshift.available() ? this.openshift.begin(this.#redirectUri(req)) : null;
      if (!attempt) {
        return res.redirect(`${login}?sso=unavailable`);
      }
      req.session.oauth = {
        state: attempt.state, verifier: attempt.verifier, redirectUri: this.#redirectUri(req),
        ret: safeReturn(req.query.return, this.base), at: Date.now(),
      };
      return res.redirect(attempt.url);
    });

    router.get(`${this.base}oauth/callback`, async (req, res) => {
      const pending = req.session.oauth;
      delete req.session.oauth;
      const fail = (reason, detail) => {
        this.logger.warn?.(`OpenShift sign-in failed: ${detail}`);
        res.redirect(`${login}?sso=${reason}`);
      };
      if (!pending || Date.now() - pending.at > STATE_TTL_MS) {
        return fail('expired', 'missing or expired login state');
      }
      if (!sameString(req.query.state, pending.state)) {
        return fail('failed', 'state mismatch');
      }
      if (req.query.error) {
        return fail(req.query.error === 'access_denied' ? 'denied' : 'failed', `OAuth error ${String(req.query.error).slice(0, 64)}`);
      }
      const code = String(req.query.code || '');
      if (!code || code.length > 4096) {
        return fail('failed', 'missing authorization code');
      }
      try {
        const { token, expiresInMs } = await this.openshift.exchange(code, pending.verifier, pending.redirectUri);
        const user = await this.openshift.review(token);
        const now = Date.now();
        return req.session.regenerate((error) => {
          if (error) {
            return fail('failed', 'session regeneration failed');
          }
          req.session.authenticated = true;
          req.session.principal = {
            name: user.name, groups: this.#keepGroups(user.groups), source: 'openshift',
            token, validatedAt: now, expiresAt: now + expiresInMs,
          };
          this.logger.info?.(`OpenShift sign-in: ${user.name}`);
          return res.redirect(safeReturn(pending.ret, this.base));
        });
      } catch (error) {
        return fail(error.rejected ? 'failed' : 'unavailable', error.message);
      }
    });

    router.get(`${this.base}logout`, limiter, (req, res) => {
      req.session.destroy(() => res.redirect(`${login}?signedout=1`));
    });

    // Gate: everything else needs a signed-in principal; OpenShift sign-ins are
    // re-checked periodically and tolerate a temporarily unreachable API.
    router.use(async (req, res, next) => {
      const path = req.originalUrl.split('?', 1)[0];
      if (open.has(path)) {
        return next();
      }
      const p = req.session?.principal;
      if (!p) {
        req.session.error = undefined;
        return res.redirect(login);
      }
      if (p.source === 'openshift') {
        const now = Date.now();
        if (now >= p.expiresAt) {
          return req.session.destroy(() => res.redirect(`${login}?sso=expired`));
        }
        const cfg = this.config.openshift;
        if (now - p.validatedAt >= cfg.revalidateMs) {
          try {
            const user = await this.openshift.review(p.token);
            if (user.name !== p.name) {
              throw Object.assign(new Error('token owner changed'), { rejected: true });
            }
            p.groups = this.#keepGroups(user.groups);
            p.validatedAt = now;
          } catch (error) {
            if (error.rejected || now - p.validatedAt >= cfg.maxStaleMs) {
              return req.session.destroy(() => res.redirect(login));
            }
          }
        }
      }
      return next();
    });
  }

  // ---- authorization ----

  /**
   * Route middleware: checks resource/action on the object of the current request
   * (database, or database/collection) and sets the template permissions.
   */
  authz(resource, action, objectOf) {
    return (req, res, next) => {
      const object = objectOf ? objectOf(req) : (req.collectionName ? `${req.dbName}/${req.collectionName}` : (req.dbName || '*'));
      if (!this.allowed(req, resource, action, object)) {
        return this.deny(req, res, `${action} ${resource} on ${object}`);
      }
      this.decorate(req, res);
      return next();
    };
  }

  deny(req, res, what) {
    const p = this.principal(req);
    this.logger.warn?.(`RBAC denied ${p ? `${p.source}:${p.name}` : 'anonymous'}: ${what}`);
    res.status(403);
    return res.render('denied', {
      baseHref: res.locals.baseHref || this.base,
      what,
      roles: this.roles(req),
      user: p,
      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : '',
    });
  }

  /** Per-request template settings: only offer what this user may do here. */
  decorate(req, res) {
    const db = req.dbName;
    const ns = req.collectionName ? `${db}/${req.collectionName}` : (db ? `${db}/*` : '*');
    const can = (r, a, o) => this.allowed(req, r, a, o);
    let readOnly;
    let noDelete;
    if (!db) {
      readOnly = !can('databases', 'create', '*');
      noDelete = !can('databases', 'delete', '*');
    } else if (!req.collectionName && !req.bucketName) {
      readOnly = !(can('collections', 'create', ns) || can('gridfs', 'create', `${db}/*`));
      noDelete = !can('collections', 'delete', ns);
    } else if (req.bucketName) {
      readOnly = !can('gridfs', 'create', `${db}/${req.bucketName}`);
      noDelete = !can('gridfs', 'delete', `${db}/${req.bucketName}`);
    } else {
      readOnly = !(can('documents', 'create', ns) || can('documents', 'update', ns));
      noDelete = !can('documents', 'delete', ns);
    }
    const appSettings = req.app.settings;
    res.locals.settings = {
      ...appSettings,
      read_only: appSettings.read_only || readOnly,
      no_delete: appSettings.no_delete || noDelete,
    };
  }

  /** Identity and SSO details for the navbar. */
  locals(req, res) {
    const p = this.principal(req);
    res.locals.currentUser = p ? { name: p.name, source: p.source } : null;
    res.locals.currentRoles = this.roles(req);
    res.locals.ssoLogout = this.ssoConfigured && Boolean(req.session?.principal);
    res.locals.rbacError = this.store.error;
  }

  filterDatabases(req, names) {
    return names.filter((n) => this.allowed(req, 'databases', 'get', n));
  }

  filterCollections(req, byDb) {
    const out = {};
    const entries = Object.entries(byDb || {});
    for (const [db, colls] of entries) {
      out[db] = (colls || []).filter((c) => this.allowed(req, 'collections', 'get', `${db}/${c}`));
    }
    return out;
  }

  status() {
    return {
      openshift: this.openshift ? this.openshift.status() : { state: STATE.disabled, reason: 'not configured' },
      rbac: { source: this.store.source, defaultRole: this.store.policy.defaultRole, error: this.store.error },
    };
  }
}
