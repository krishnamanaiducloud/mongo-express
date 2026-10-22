# Troubleshooting

| Symptom | Likely cause | Check / fix |
| --- | --- | --- |
| Pod `CrashLoopBackOff`, log `invalid configuration` | Config validation failed | `oc logs … -c portal`; the message lists every problem. Validate locally with `mongo-portal --check-config --config config.yaml`. |
| `tls.mode=disabled in production requires plaintextApproved=true` | Production plaintext gate | Enable MongoDB TLS, or record the approved exception in the overlay. |
| `identity.mode=openshift requires … loopback` | `listenAddress` not 127.0.0.1 | Keep the portal behind the proxy sidecar. |
| Browser loops between portal and OAuth login | Redirect reference / Route mismatch, cookie secret length | Route name must match the SA annotation; `cookie-secret` must be 16/24/32 bytes. `oc logs … -c oauth-proxy`. |
| "Access denied" for a valid user | Not in a configured group, or ClusterRole lacks the group name | `oc get group <name> -o yaml`; check `resourceNames` in the overlay's `patch-cluster-scope.yaml`; logs show `openshift group refresh failed` on RBAC errors. |
| "Identity verification is temporarily unavailable" (503) | Kubernetes API unreachable from the pod | Egress NetworkPolicy rule for 6443/443; API health. |
| "Authentication failed" at MongoDB login | Wrong password, wrong authentication database, mechanism not allowed | Try the user's auth DB (often `admin`); `db.getUser()` shows mechanisms; check `authMechanisms` in the profile. |
| "Too many login attempts" | Rate limit / lockout | Wait for `Retry-After`; lockout doubles up to `maxLockDuration`. |
| "TLS certificate verification with MongoDB failed" | Wrong/missing CA, hostname not in SAN, TLS profile against a plaintext server | `oc rsh` into the debug image: `openssl s_client -connect host:27017 -CAfile /etc/mongo-portal/mongodb-ca/ca.crt -servername host`. Never disable verification; fix the CA or certificate. |
| "MongoDB is unreachable" | DNS, NetworkPolicy egress, MongoDB down, wrong `replicaSet` name | Debug image: `dig +short host`, `curl -v telnet://host:27017`; check `hello` via `mongosh`. |
| Users keep being asked to sign in to MongoDB | Requests reaching different pods; idle timeout; pod restarts | Route cookie affinity annotations; `session.idleTimeout`; pod restarts in `oc get pods`. |
| `403 portal_role_forbidden` | Developer role attempting a write | Expected. Use an SRE account if the change is legitimate. |
| `403 mongo_unauthorized` | MongoDB user lacks the privilege | Expected; grant the specific role in MongoDB if justified. |
| `504` on queries | `maxTimeMS` exceeded | Add an index, narrow the filter, or raise `maxTimeMS` (≤ `query.maxMaxTime`). |
| Results "truncated" | Response byte cap | Use a projection or smaller page size. |
| Shell: "SyntaxError: … JavaScript expressions are not evaluated" | Shell input is JSON-only | Write literal values; use `ObjectId("…")`, `ISODate("…")` helpers. |
| Metrics not scraped | User-workload monitoring disabled or NetworkPolicy | Enable UWM; namespace label `network.openshift.io/policy-group: monitoring` must exist on the monitoring namespace. |
