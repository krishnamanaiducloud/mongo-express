import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';

/*
 * Built-in OpenShift login, like Argo CD's OpenShift connector: the pod's service
 * account is the OAuth client (client id system:serviceaccount:<ns>:<name>, client
 * secret = its token) and the user's name and groups are read from the OpenShift API
 * with the user's own token (users/~), so no cluster permissions are needed.
 *
 * It is passive: when the pod does not run in OpenShift, or the API or OAuth server
 * cannot be reached, status() says why and OpenShift login is simply not offered.
 * Nothing here throws into a request.
 */

export const STATE = { available: 'available', unavailable: 'unavailable', disabled: 'disabled' };

const SA_DIR = '/var/run/secrets/kubernetes.io/serviceaccount';

const getBoolean = (v) => String(v || '').toLowerCase();

export const openshiftConfigFromEnv = (env = process.env) => {
  const enabled = getBoolean(env.ME_CONFIG_OPENSHIFT_OAUTH) || 'false';
  return {
    enabled: ['auto', 'true', 'false'].includes(enabled) ? enabled : 'false',
    apiUrl: (env.ME_CONFIG_OPENSHIFT_API_URL || 'https://kubernetes.default.svc').replace(/\/+$/, ''),
    caFile: env.ME_CONFIG_OPENSHIFT_CA_FILE || `${SA_DIR}/ca.crt`,
    extraCaFiles: (env.ME_CONFIG_OPENSHIFT_EXTRA_CA_FILES || '').split(',').map((s) => s.trim()).filter(Boolean),
    tokenFile: env.ME_CONFIG_OPENSHIFT_TOKEN_FILE || `${SA_DIR}/token`,
    clientId: env.ME_CONFIG_OPENSHIFT_CLIENT_ID || '',
    scopes: (env.ME_CONFIG_OPENSHIFT_SCOPES || 'user:info').split(/[ ,]+/).filter(Boolean),
    // Public origin used for the OAuth redirect URI (default: the request's host).
    publicUrl: (env.ME_CONFIG_OPENSHIFT_PUBLIC_URL || '').replace(/\/+$/, ''),
    probeIntervalMs: 60_000,
    revalidateMs: 5 * 60_000,
    maxStaleMs: 60 * 60_000,
    timeoutMs: 5000,
  };
};

const readCAs = (files) => {
  const out = [...tls.rootCertificates];
  for (const f of files) {
    if (!f) {
      continue;
    }
    try {
      out.push(fs.readFileSync(f, 'utf8'));
    } catch {
      // Optional; a missing CA file only means fewer trusted roots.
    }
  }
  return out;
};

/** Minimal JSON-over-HTTPS client with certificate verification always on. */
export const httpsRequest = (url, { method = 'GET', headers = {}, body, ca, timeoutMs = 5000 } = {}) => new Promise((resolve, reject) => {
  const req = https.request(url, { method, headers, ca, timeout: timeoutMs, rejectUnauthorized: true }, (res) => {
    const chunks = [];
    let size = 0;
    res.on('data', (c) => {
      size += c.length;
      if (size > 4 * 1024 * 1024) {
        req.destroy(new Error('response too large'));
        return;
      }
      chunks.push(c);
    });
    res.on('end', () => {
      resolve({ status: res.statusCode, json: parseJson(Buffer.concat(chunks).toString('utf8')) });
    });
  });
  req.on('timeout', () => req.destroy(new Error('request timed out')));
  req.on('error', reject);
  if (body) {
    req.write(body);
  }
  req.end();
});

const parseJson = (text) => {
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

const shortError = (error) => String(error?.cause?.message || error?.message || error).slice(0, 160);

/** "sub" claim of the pod's own service account token (parsed, not verified). */
export const serviceAccountSubject = (token) => {
  const parts = String(token).split('.');
  if (parts.length !== 3) {
    return '';
  }
  try {
    // eslint-disable-next-line unicorn/prefer-uint8array-base64 -- Uint8Array base64 needs Node 25; engines allow Node 22
    return JSON.parse(atob(parts[1].replaceAll('-', '+').replaceAll('_', '/'))).sub || '';
  } catch {
    return '';
  }
};

const isControl = (ch) => {
  const c = ch.codePointAt(0);
  return c <= 0x1F || c === 0x7F;
};

export const validName = (s) => typeof s === 'string' && s.length > 0 && s.length <= 256 && ![...s].some(isControl);

export class OpenShiftAuth {
  constructor(cfg, { request = httpsRequest, logger = console, now = () => Date.now() } = {}) {
    this.cfg = cfg;
    this.request = request;
    this.logger = logger;
    this.now = now;
    this.meta = null;
    this.timer = null;
    this.state = cfg.enabled === 'false'
      ? { state: STATE.disabled, reason: 'OpenShift login is turned off' }
      : { state: STATE.unavailable, reason: 'not checked yet' };
  }

  #ca() {
    return readCAs([this.cfg.caFile, ...this.cfg.extraCaFiles]);
  }

  #credentials() {
    let secret;
    try {
      secret = fs.readFileSync(this.cfg.tokenFile, 'utf8').trim();
    } catch {
      return null;
    }
    const id = this.cfg.clientId || serviceAccountSubject(secret);
    return id.startsWith('system:serviceaccount:') ? { id, secret } : null;
  }

  async #call(url, opts = {}) {
    return this.request(url, { ca: this.#ca(), timeoutMs: this.cfg.timeoutMs, ...opts });
  }

  async #checkOAuthServer(issuer) {
    try {
      const h = await this.#call(`${issuer.replace(/\/+$/, '')}/healthz`);
      if (h.status >= 500) {
        return { state: STATE.unavailable, reason: `the OAuth server returned HTTP ${h.status}` };
      }
      if (this.#credentials()) {
        return { state: STATE.available, issuer };
      }
      return { state: STATE.unavailable, reason: 'cannot determine the OAuth client id from the service account token' };
    } catch (error) {
      return { state: STATE.unavailable, reason: `the OAuth server is not reachable: ${shortError(error)}` };
    }
  }

  status() {
    return { ...this.state };
  }

  available() {
    return this.state.state === STATE.available;
  }

  async probe() {
    if (this.cfg.enabled === 'false') {
      return this.status();
    }
    const notOffered = (reason) => (this.cfg.enabled === 'true'
      ? { state: STATE.unavailable, reason }
      : { state: STATE.disabled, reason });
    let next;
    let meta = null;
    if (fs.existsSync(this.cfg.tokenFile)) {
      try {
        const r = await this.#call(`${this.cfg.apiUrl}/.well-known/oauth-authorization-server`, { headers: { Accept: 'application/json' } });
        if (r.status === 404) {
          next = notOffered('the cluster has no OpenShift OAuth server');
        } else if (r.status !== 200 || !r.json) {
          next = { state: STATE.unavailable, reason: `OAuth discovery returned HTTP ${r.status}` };
        } else {
          meta = r.json;
          const urls = [meta.issuer, meta.authorization_endpoint, meta.token_endpoint];
          next = urls.every((u) => typeof u === 'string' && u.startsWith('https://'))
            ? await this.#checkOAuthServer(meta.issuer)
            : { state: STATE.unavailable, reason: 'OAuth discovery returned an invalid endpoint' };
        }
      } catch (error) {
        next = { state: STATE.unavailable, reason: `the Kubernetes API server is not reachable: ${shortError(error)}` };
      }
    } else {
      next = notOffered('no service account token is mounted (not running in an OpenShift pod)');
    }
    next.checkedAt = new Date(this.now()).toISOString();
    const prev = this.state;
    this.state = next;
    if (next.state === STATE.available) {
      this.meta = meta;
    }
    if (prev.state !== next.state || prev.reason !== next.reason) {
      const msg = `OpenShift login ${next.state}${next.reason ? `: ${next.reason}` : ''}`;
      if (next.state === STATE.unavailable && this.cfg.enabled === 'true') {
        this.logger.warn?.(`${msg} (local sign-in remains available)`);
      } else {
        this.logger.info?.(msg);
      }
    }
    return this.status();
  }

  /** Probes now and then periodically (more often while unavailable). */
  start() {
    if (this.cfg.enabled === 'false' || this.timer) {
      return;
    }
    const loop = async () => {
      const st = await this.probe().catch(() => this.status());
      let wait = this.cfg.probeIntervalMs;
      if (st.state === STATE.available) {
        wait *= 5;
      } else if (st.state === STATE.disabled) {
        wait *= 10;
      }
      this.timer = setTimeout(loop, wait);
      this.timer.unref?.();
    };
    this.timer = setTimeout(loop, 0);
    this.timer.unref?.();
  }

  stop() {
    clearTimeout(this.timer);
    this.timer = null;
  }

  /** Creates a login attempt: { url, state, verifier }. */
  begin(redirectUri) {
    if (!this.available() || !this.meta) {
      return null;
    }
    const cred = this.#credentials();
    if (!cred) {
      return null;
    }
    const state = randomBytes(32).toString('hex');
    // RFC 7636: 43-128 characters from the unreserved set; hex qualifies.
    const verifier = randomBytes(48).toString('hex');
    const q = new URLSearchParams({
      client_id: cred.id,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: this.cfg.scopes.join(' '),
      state,
    });
    if ((this.meta.code_challenge_methods_supported || []).includes('S256')) {
      q.set('code_challenge', createHash('sha256').update(verifier).digest('base64url'));
      q.set('code_challenge_method', 'S256');
    }
    const sep = this.meta.authorization_endpoint.includes('?') ? '&' : '?';
    return { url: `${this.meta.authorization_endpoint}${sep}${q}`, state, verifier };
  }

  /** Redeems a code for the user's token: { token, expiresInMs } or throws. */
  async exchange(code, verifier, redirectUri) {
    if (!this.meta) {
      throw new Error('OpenShift login is not available');
    }
    const cred = this.#credentials();
    if (!cred) {
      throw new Error('OAuth client credentials are not available');
    }
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri });
    if ((this.meta.code_challenge_methods_supported || []).includes('S256')) {
      form.set('code_verifier', verifier);
    }
    const send = (basic) => {
      const body = new URLSearchParams(form);
      const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
      if (basic) {
        // RFC 6749 2.3.1: form-encode the credentials before Basic encoding.
        // eslint-disable-next-line unicorn/prefer-uint8array-base64 -- Uint8Array base64 needs Node 25; engines allow Node 22
        headers.Authorization = `Basic ${btoa(`${encodeURIComponent(cred.id)}:${encodeURIComponent(cred.secret)}`)}`;
      } else {
        body.set('client_id', cred.id);
        body.set('client_secret', cred.secret);
      }
      return this.#call(this.meta.token_endpoint, { method: 'POST', headers, body: body.toString() });
    };
    let r = await send(true);
    if (r.status === 401 || (r.status === 400 && r.json?.error === 'invalid_client')) {
      r = await send(false);
    }
    if (r.status !== 200 || !r.json?.access_token) {
      const error = new Error(`token exchange failed (HTTP ${r.status}${r.json?.error ? `, ${r.json.error}` : ''})`);
      error.rejected = r.status === 400 || r.status === 401;
      throw error;
    }
    const expiresInMs = Number(r.json.expires_in) > 0 ? Number(r.json.expires_in) * 1000 : 24 * 60 * 60_000;
    return { token: r.json.access_token, expiresInMs };
  }

  /** The user of a token: { name, groups }; throws with .rejected for invalid tokens. */
  async review(token) {
    const r = await this.#call(`${this.cfg.apiUrl}/apis/user.openshift.io/v1/users/~`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
    if (r.status === 401 || r.status === 403) {
      const error = new Error('the OpenShift token is not valid');
      error.rejected = true;
      throw error;
    }
    if (r.status !== 200 || !validName(r.json?.metadata?.name)) {
      throw new Error(`user review returned HTTP ${r.status}`);
    }
    const groups = [...new Set((r.json.groups || []).filter(validName))].sort();
    return { name: r.json.metadata.name, groups };
  }
}
