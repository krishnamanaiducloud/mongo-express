# Security threat model

## Assets

| Asset | Where it lives |
| --- | --- |
| MongoDB user passwords | Browser form → portal process memory (driver credential) only |
| Data in MongoDB | MongoDB; transiently in portal responses |
| Portal session bearer token | `__Host-` HttpOnly cookie; SHA-256 hash in pod memory |
| SSO access token | OAuth proxy cookie; forwarded per request; SHA-256 hash cached 1 min |
| Portal ServiceAccount token | Pod (projected); can only `get` the configured Group objects |
| Session/proxy keys | Kubernetes Secrets |

## Trust boundaries

Browser ↔ Route (TLS) ↔ OAuth proxy (TLS, service CA) ↔ portal (loopback) ↔
MongoDB (TLS or plaintext per profile) and portal ↔ Kubernetes API (TLS).

## Threats and mitigations (STRIDE)

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| **Spoofing** identity headers | Loopback listener; trusted-proxy CIDR check; token validated against `users/~` and must match the header | `identity_test` (spoof, untrusted peer), `api_test TestSSOStage` |
| Unauthorized SSO user | Group membership checked server-side every request; fail closed when API unavailable beyond max staleness | `TestOpenShiftResolver`, `TestOpenShiftFailsClosed…` |
| Session hijack / fixation | 256-bit random token, HttpOnly/Secure/SameSite=Strict `__Host-` cookie, rotation on login, SSO-identity binding destroys cross-user use, idle/absolute expiry | `TestSessionRotationOnLogin`, `TestCrossUserCookieRejected`, `TestSessionExpiry` |
| CSRF (incl. login CSRF) | Per-session token / HMAC pre-login token bound to SSO user; Origin and Sec-Fetch-Site checks; JSON-only bodies | `TestLoginCSRFAndOrigin`, `TestSREWriteNeedsCSRF…` |
| **Tampering**: developer writes | Portal-role gate on all write routes, independent of UI; `$out`/`$merge` blocked | `TestDeveloperCannotWriteViaDirectAPI`, integration `TestDeveloperReadOnlyEndToEnd` |
| Privilege beyond MongoDB grants | Every operation runs as the user; MongoDB enforces | integration `TestSRERespectsMongoDBRoles` |
| NoSQL injection | Extended JSON parsed by the driver (no string concatenation); operator-free `_id` tokens; JS operators rejected; strict JSON decoding | `validate_test`, `TestDecodeIDRejectsOperators` |
| Server-side JavaScript | `$where`, `$function`, `$accumulator`, Code values rejected at any depth; no `runCommand`/`eval` API; shell grammar never evaluates JS | `TestFilterRejectsDangerousInput`, `shell.test.ts` |
| SSRF via connection settings | Hosts only from admin profiles; login accepts a profile *name*; URIs with credentials/TLS/auth options rejected | `TestLoginFailureAndLockout`, `config_test` |
| TLS downgrade / MITM to MongoDB | Explicit mode, no fallback, verification cannot be disabled, hostname checked, custom CA | integration `TestTLSAuthentication` (wrong CA, hostname mismatch, both downgrade directions) |
| **Repudiation** | Structured audit events for logins, denials, writes with SSO + MongoDB identities and request id | `audit_test`; log review |
| **Information disclosure**: credentials | Passwords never logged/stored/returned; telemetry has no query/document content; hosts hidden from UI | `TestLoginSessionCookieAndLogout`, smoke test "password not in logs" |
| Error leakage | Classified, generic error messages; no stack traces to clients | `mongoconn` classification tests |
| XSS | React escaping, no `dangerouslySetInnerHTML` (lint rule), strict CSP (`script-src 'self'`, no inline), `nosniff` | `components.test.tsx`, header tests |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | header tests |
| **DoS**: brute force | Per-SSO-user rate limit, per-account lockout with backoff (only on server-confirmed failures), concurrent login cap | `TestLoginFailureAndLockout`, `limiter_test` |
| Resource exhaustion | Body limits, query limits/skip cap, server-side `maxTimeMS`, response byte cap, session caps, pool size per session, container limits | `TestQueryLimitsAndTimeouts`, `TestSecurityHeadersAndBodyLimit` |
| **Elevation**: container escape | Non-root arbitrary UID, read-only rootfs, all capabilities dropped, no privilege escalation, RuntimeDefault seccomp, restricted-v2 SCC, no shell/package manager in production image | smoke test, manifest checks |
| Lateral movement | NetworkPolicies: ingress only router + monitoring; egress DNS, MongoDB pods, API | manifest review (cluster test pending) |
| Supply chain | Base images pinned by digest (Chainguard), lockfiles, `go mod verify`, `npm ci --ignore-scripts`, mongosh checksum-pinned, SBOMs, vulnerability scans, Dependabot | security scan reports |

## Residual risks

1. **Plaintext MongoDB traffic** in the current environment (TLS disabled on the
   server). Credentials and data can be read by anyone with network access between
   pod and MongoDB. Mitigation: NetworkPolicy, production start-up gate requiring a
   recorded exception. Remediation: enable MongoDB TLS and switch profiles.
2. Passwords are held in process memory for the session lifetime (required for
   driver re-authentication). A memory dump of the pod would expose them.
3. Sessions are per pod; pod loss logs users out of MongoDB (by design).
4. In-memory audit buffer and rate limiter are per pod; durable audit relies on
   log forwarding (Splunk). Rate limits are per replica (effective limit ×replicas).
5. Kubernetes API egress rule is port-based by default; narrow it to the API
   endpoint IPs per cluster.
6. The debug image contains a shell and network tools; restrict its use to
   troubleshooting windows.
7. Base `origin-oauth-proxy` is a community image; use the Red Hat build in production.
