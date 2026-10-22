# Architecture

```
Browser ──HTTPS──▶ OpenShift Route (re-encrypt)
                      │  TLS to service-CA certificate
                      ▼
          ┌────────── Pod ─────────────────────────────────────┐
          │ oauth-proxy :8443   ──HTTP 127.0.0.1──▶ portal :8080 │  UI + REST API
          │  (OpenShift OAuth)                       portal :9090 │  /healthz /readyz /metrics
          └───────────────────────────────────────────┬────────┘
                                                      │ one MongoDB client per user session,
                                                      │ authenticated with that user's credentials
                                                      ▼  (TLS or plaintext, per profile)
                                        Existing MongoDB replica set (unchanged)
```

## Components

| Component | Technology | Responsibility |
| --- | --- | --- |
| OAuth proxy sidecar | `openshift/oauth-proxy` | Corporate SSO through the cluster OAuth server; forwards user name and access token |
| Portal backend | Go 1.26+, `mongo-driver/v2`, `net/http`, `slog`, Prometheus, OpenTelemetry | Identity verification, sessions, authorization, validated MongoDB operations, audit |
| Web UI | React 19, TypeScript, Vite, PatternFly 6, TanStack Query | Explorer, document browser/editor, query console, shell, indexes, session/audit views |
| Images | Chainguard `static` (production), Wolfi rootfs (debug) | Same binary in both; debug adds troubleshooting tools and `mongosh` |

The UI is compiled and embedded in the Go binary; the pod has no other
runtime dependency (no Redis, no database of its own).

## Authentication: two independent stages

**Stage A – SSO.** The OAuth proxy authenticates the browser against the
OpenShift OAuth server. For every request it forwards `X-Forwarded-User` and
`X-Forwarded-Access-Token`. The portal:

1. accepts identity headers only from the trusted proxy address (loopback); the
   API listener binds to `127.0.0.1`, so nothing else in the cluster can reach it;
2. validates the access token against `GET /apis/user.openshift.io/v1/users/~`
   and requires the returned user to equal the forwarded user (anti-spoofing);
3. reads the configured OpenShift `Group` objects with its own ServiceAccount
   (RBAC limited to `get` on exactly those group names) and maps membership to a
   portal role: `sre` > `developer` > none. No role → HTTP 403, audit event.

Results are cached briefly (tokens 1 min, groups 1 min, stale groups usable up
to 5 min while the API is unreachable, then fail closed).

**Stage B – MongoDB.** The user picks an administrator-defined connection
profile and enters MongoDB username, password and authentication database. The
backend builds a client from the profile (hosts and TLS settings come only from
configuration), authenticates with SCRAM-SHA-256/SCRAM-SHA-1, pings the server
and confirms the principal with `connectionStatus`. Only then is a session
created. The password is passed to the driver and kept only in process memory
for re-authenticating new pool connections (for example after failover). It is
never logged, persisted or returned.

## Sessions

* Server-side, in-memory, per pod. The browser holds a random 256-bit bearer
  token in a `__Host-` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`).
* Bound to the SSO user: presenting the cookie under another SSO identity
  destroys the session.
* New identifier on every login (rotation, fixation protection), idle timeout
  (default 15 min), absolute timeout (default 8 h), per-user and global caps,
  explicit logout and termination of one's other sessions.
* Expired/closed sessions disconnect their MongoDB client.
* **Multi-replica strategy:** the Route uses cookie-based affinity. If a request
  reaches a pod that does not own the session (pod restart, rescheduling,
  affinity loss), the API returns `mongo_session_required` and the UI asks the
  user to sign in to MongoDB again. Credentials are never shared between pods.

## Authorization: two boundaries

1. **Portal role** (from SSO groups), enforced server-side on every request:
   developers are read-only regardless of their MongoDB privileges; write and
   administrative endpoints return 403 `portal_role_forbidden` for them.
2. **MongoDB privileges** of the authenticated user: every operation runs as that
   user, so MongoDB is the final authority. An SRE with a read-only MongoDB user
   cannot write; MongoDB `Unauthorized` errors are returned as 403 and audited.

`connectionStatus` privileges are used only to hide UI controls the user cannot
use; they are never trusted for enforcement.

## Query safety

All query input is MongoDB Extended JSON parsed by the driver (no JavaScript
evaluation anywhere, including the mongosh-style shell, which is a fixed
grammar parsed in the browser into API calls). The validator:

* rejects `$where`, `$function`, `$accumulator` and JavaScript BSON values anywhere;
* allows only an allowlist of aggregation stages; `$out`/`$merge` are refused for
  developers and allowed for SREs only when `query.allowWriteStagesForSRE: true`,
  and only as the final top-level stage;
* bounds nesting depth, element count, regex length, pipeline length;
* enforces `limit`, `skip`, server-side `maxTimeMS` (via context deadlines /
  CSOT) and a response size cap;
* addresses single-document writes by `_id` only; id tokens containing operators
  are rejected so an id can never widen into a filter.

Destructive operations (drop collection, drop index, delete document) require
an `X-Confirm` header naming the target; the UI collects a typed confirmation.

## Transport security to MongoDB

Each profile declares `tls.mode: enabled | disabled` explicitly (no default):

* **enabled:** certificate and hostname verification are always on (disabling is
  rejected at startup), custom CA bundle, optional client certificate, TLS 1.2/1.3
  minimum. Certificate files are re-read for each new login; client key pairs are
  reloaded when the mounted Secret changes.
* **disabled:** plaintext, logged as a warning at startup and on each login, and
  shown as a permanent red banner in the UI. With `environment: production` the
  portal refuses to start unless `plaintextApproved: true` is recorded with a
  `securityExceptionRef`.

There is no fallback between the modes, and TLS options in profile URIs are
rejected so verification cannot be weakened through the URI. HTTPS on the Route
does **not** encrypt portal→MongoDB traffic; only `tls.mode: enabled` does.

## Observability

* JSON logs (stdout) with request id, route pattern, status, latency, trace id and
  SSO user. Query contents, document contents, passwords and tokens are never logged.
* Audit events (`"audit": true`) for logins, logouts, denials and every write.
* Prometheus metrics on `:9090/metrics` (`mongo_portal_*`): HTTP requests/latency,
  auth attempts by stage/result, authorization denials by source/reason,
  active sessions, open MongoDB connections, MongoDB operation latency, build info.
* OpenTelemetry traces (OTLP/HTTP) when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; span
  attributes carry route patterns and operation names only.

## Repository layout

```
portal/
  cmd/portal/            main, graceful shutdown, healthcheck subcommand
  internal/api/          HTTP server, middleware, handlers, openapi.yaml (embedded)
  internal/identity/     OpenShift / header / dev identity resolvers
  internal/mongoconn/    client options, TLS, error classification, privileges
  internal/query/        Extended JSON parsing and validation
  internal/session/      in-memory session store
  internal/ratelimit/    login throttling and lockout
  internal/audit|metrics|telemetry|config|webui/
  web/                   React application
  test/integration/      real MongoDB tests (run.sh starts disposable containers)
  test/container/        image smoke tests
  scripts/               security scanning
  Dockerfile             production + debug targets
deploy/
  base/                  Deployment, Service, Route, SA, RBAC, NetworkPolicies, PDB, config
  components/monitoring/ ServiceMonitor
  overlays/{dev,test,prod}/
  argocd/application.yaml
```
