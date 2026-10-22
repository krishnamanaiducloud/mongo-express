# Testing and validation report

Release: **0.1.0** · Date: 2026-10-22 · Environment: Windows 10 + WSL2 Ubuntu,
Docker 29.6, Go 1.27.3 (Chainguard), Node 24/26, MongoDB 8.0 test containers.
No OpenShift cluster was available; cluster-level items are listed under
"Not environment-validated".

## Results

| Area | Command | Result |
| --- | --- | --- |
| Go format / vet | `gofmt -l`, `go vet ./...` (+ `-tags integration`) | clean |
| Go unit tests | `go test -race ./internal/...` | **pass** (9 packages) |
| Web lint / types | `npm run lint`, `npm run typecheck` | clean |
| Web unit tests | `npm test` (Vitest) | **18/18 pass** |
| Web build | `npm run build` | pass |
| OpenAPI contract | `TestOpenAPIContract` (routes ⇔ `openapi.yaml`) | pass |
| Integration (real MongoDB) | `test/integration/run.sh` | **9/9 tests pass** |
| Container smoke | `test/container/smoke.sh` (3 UIDs × 2 images) | **73/73 checks pass** |
| Kustomize + schema | `kubectl kustomize` + `kubeconform -strict` (K8s 1.31, OpenShift 4.18 Route, CRDs) | dev/test/prod 11/11 valid each; Argo CD 4/4 valid |
| Manifest guardrails | no StatefulSet/PVC/Secret, no runAsUser/fsGroup/privileged | pass |

### Integration tests (disposable 3-member replica set + TLS replica set)

| Test | Covers |
| --- | --- |
| `TestNonTLSAuthentication` | valid login, wrong password, unknown user, **auth-database mismatch**, SCRAM-SHA-1 legacy user, mechanism restriction |
| `TestTLSAuthentication` | TLS with **custom CA + client certificate**, client cert required by server, **untrusted CA**, **hostname mismatch**, no plaintext→TLS or TLS→plaintext downgrade |
| `TestUnavailableAndTimeout` | unreachable host, blackhole address, bounded timeouts |
| `TestConcurrentSessionsAreIndependent` | 15 parallel logins as 3 users, each connection authenticated as its own principal |
| `TestDeveloperReadOnlyEndToEnd` | developer with a write-capable MongoDB user still cannot insert/index/drop; `$out` blocked and verified not written; Decimal128 round-trip |
| `TestSRERespectsMongoDBRoles` | SRE portal role + read-only MongoDB user → MongoDB denies insert/index/drop (403) |
| `TestSRECrudEndToEnd` (TLS and non-TLS) | create collection, insert (Long/Date/ObjectId), get, replace, `_id` immutability, unique index + duplicate (409), confirmation required for drop, count, `$where` rejected, delete, stats, drop, server info, logout |
| `TestQueryLimitsAndTimeouts` | pagination/hasMore, server-side `maxTimeMS` |
| `TestReplicaSetFailover` | primary step-down (rs1→rs3); existing session keeps working (driver re-authentication) |

### Unit / API security tests (selection)

SSO required; identity headers from untrusted peers ignored; group → role
mapping; OpenShift token/user mismatch (spoofing) rejected; API outage fails
closed after max staleness; CSRF (missing, forged, other user's token, cross
origin, cross site, form posts); lockout after failures and `Retry-After`; SSRF
attempt via profile; unknown JSON fields; cookie flags; session rotation and
fixation; cross-user cookie reuse destroys the session; developer write denial
on every write route; confirmation headers; `_id_` and `system.*` protection;
idle expiry; **backend restart requires re-authentication**; security headers
and CSP; body limits; operator injection via document id; error classification
(timeouts during SASL never count as bad credentials); TLS config (no
`InsecureSkipVerify`, CA required, client cert reload on rotation); query
validator (JS operators, nested write stages, regex/nesting/element limits).

### Container smoke test (production and debug, UIDs 1000680000, 123456, 65532, GID 0)

Read-only root filesystem, all capabilities dropped, `no-new-privileges`:
ready, built-in healthcheck, UI served with CSP, SSO identity accepted,
unauthenticated → 401, MongoDB login sets `__Host-` cookie with `HttpOnly;
Secure; SameSite=Strict`, authenticated query, invalid password → 401,
password absent from logs. Production image has no shell; neither image has a
package manager; `mongosh` runs and connects from the debug image as an
arbitrary UID; debug tools (sh, curl, dig, nslookup, openssl, ss, ip, ps, top,
jq) present and executable.

## Defects found by testing and fixed

| Defect | Found by | Fix |
| --- | --- | --- |
| Network timeouts during SCRAM handshake were classified as bad credentials (would trigger lockout) | integration (concurrency) | classify only server-reported `AuthenticationFailed` as auth failure |
| HTTP mux pattern conflict between `GET /` (UI) and `/api/` caused a startup panic | container smoke | register UI on `/` with method check; added `TestServerWithUI` |
| Debug image lacked busybox applet links (`--no-scripts`) | container smoke | create links from the package's applet list at build time |
| Overlay image overrides did not apply; ConfigMap not content-hashed | kustomize render | match full image names; base `configMapGenerator` |
| Web lockfile excluded by repository `.gitignore` | staging review | scoped un-ignore for `portal/web/package-lock.json` |

## Security scans (final images)

| Scanner | Scope | Result |
| --- | --- | --- |
| govulncheck v1.9.0 (Go 1.27.3) | reachable Go vulnerabilities | **0 affecting**; 1 module-level advisory not reachable (below) |
| gosec | Go SAST | 0 issues (5 reviewed: 2 bounded int conversions, 2 cookie `Secure` from validated config, 1 local health URL — annotated with justification) |
| npm audit | runtime and all deps | **0 vulnerabilities** |
| gitleaks | working tree (portal/, deploy/) | **no leaks** |
| hadolint | Dockerfile | clean (justified inline ignores: root in build-only stage, rolling Wolfi pins via base digest, pipefail via SHELL) |
| Trivy image | production | **0 Critical / 0 High / 0 Medium / 0 Low**, 1 Unknown |
| Trivy image | debug | **0 Critical / 0 High / 0 Medium / 0 Low**, 1 Unknown |
| Grype (from Syft SBOM) | both | 1 Unknown (same advisory) |
| Trivy config | rendered prod manifests | 0 High/Critical; 2 Medium KSV-0125 "untrusted registry" (site registry allowlist policy) |
| Syft | SBOM SPDX + CycloneDX | production 42 packages, debug 114 packages |

Initial scans found `golang.org/x/net` v0.59.0 (1 Critical, several High,
fixed in 0.60.0) and Go standard-library issues in the local 1.26 toolchain.
Remediated by upgrading x/net to 0.61.0 (and x/crypto, x/sys, x/text) and
pinning `toolchain go1.27.3`.

A clean scan result means no **known** vulnerabilities were found by these
tools at scan time; it is not proof of absence of vulnerabilities.

### Exceptions

| ID | Component | Severity | Exploitability | Why no remediation | Mitigation | Review |
| --- | --- | --- | --- | --- | --- | --- |
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 (`openpgp` package) | Unknown (advisory: package unmaintained, unsafe by design) | Not reachable: the portal never imports `x/crypto/openpgp` (govulncheck symbol analysis) | No fixed version exists; the module is required transitively by the MongoDB driver | Keep x/crypto current (Dependabot); govulncheck gate in CI fails if it becomes reachable | 2027-01-22 |
| KSV-0125 | Deployment images (docker.io, quay.io) | Medium | Policy finding, not a vulnerability | Registry choice is site policy | Production pins digests; mirror to an approved registry and configure the allowlist | at production onboarding |

## Published images

Built from a clean `git archive` of commit `b8f25d23b6311c3888798a7e9b3a41b640788e72`
with BuildKit (cross-compiled, no emulation), SBOM and `mode=max` provenance
attestations attached. Existing tags were checked first and not overwritten;
`latest` was not changed.

| Image | Index digest | Platforms | Verified |
| --- | --- | --- | --- |
| `docker.io/mohankrishna999/mongo-express:0.1.0` | `sha256:7592c5d020168ffc2c11f5a49d6efc51f3d94901e9b4de1aab1ef52adc978918` | linux/amd64, linux/arm64 | revision label + provenance = b8f25d2, user 65532:0, arm64 binary is aarch64, pulled image runs, Trivy: 1 Unknown |
| `docker.io/mohankrishna999/mongo-express:0.1.0-debug` | `sha256:b97e4bbd6a5a3f37cfc86374e0e54fb20d396845b32a87882a39425b42c1ea0e` | linux/amd64, linux/arm64 | same; mongosh 2.13.0 runs as arbitrary UID, Trivy: 1 Unknown |

Not done: cosign signatures (no signing key/identity configured locally; the CI
release job signs keylessly). arm64 images were inspected but not executed
(no arm64 host or emulator available).

## Not environment-validated (requires an OpenShift cluster)

* OpenShift OAuth proxy flow end to end (redirect, callback, token forwarding)
  — the portal side is unit-tested against a fake OpenShift API.
* Group lookup with the real `user.openshift.io` API and ClusterRole.
* restricted-v2 SCC admission and UID-range assignment (emulated: arbitrary
  UIDs, read-only rootfs, dropped capabilities; Pod Security "restricted" kind
  test script provided in `portal/test/container/restricted-k8s.sh`).
* Route re-encrypt with the service CA, cookie affinity across replicas.
* NetworkPolicy enforcement (rendered and schema-validated only).
* ServiceMonitor scraping by user-workload monitoring; Splunk forwarding.
* Argo CD sync behaviour (manifests validated against the Argo CD CRD schemas).
* Connectivity to the existing production MongoDB (never contacted).
