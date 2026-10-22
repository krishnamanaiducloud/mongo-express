# Secret configuration reference

No Secret is stored in Git and none is managed by Argo CD (the AppProject
blacklists `Secret`). Create them out of band (or with your secret operator,
e.g. External Secrets / Vault) in the portal namespace.

| Name | Type | Keys | Used by | Required |
| --- | --- | --- | --- | --- |
| `mongo-portal-proxy` | Opaque | `cookie-secret` – exactly 16, 24 or 32 bytes | OAuth proxy cookie encryption | yes |
| `mongo-portal-session` | Opaque | `session-key` – ≥ 32 bytes, random | Portal pre-login CSRF HMAC; identical for all replicas | yes |
| `mongo-portal-tls` | kubernetes.io/tls | `tls.crt`, `tls.key` | OAuth proxy serving cert | created by the service CA |
| `mongo-portal-mongodb-ca` | **ConfigMap** | `ca.crt` – PEM bundle | MongoDB TLS verification | TLS profiles only |
| `mongo-portal-mongodb-client` | kubernetes.io/tls | `tls.crt`, `tls.key` | MongoDB mutual TLS | when MongoDB requires client certs |

Creation:

```bash
NS=<portal namespace>
oc create secret generic mongo-portal-proxy -n "$NS" \
  --from-literal=cookie-secret="$(openssl rand -base64 24 | head -c 32)"
oc create secret generic mongo-portal-session -n "$NS" \
  --from-literal=session-key="$(openssl rand -hex 32)"
oc create configmap mongo-portal-mongodb-ca -n "$NS" --from-file=ca.crt=ca-bundle.pem
oc create secret tls mongo-portal-mongodb-client -n "$NS" --cert=portal-client.crt --key=portal-client.key
```

Rotation:

* `mongo-portal-session`: rotate, then `oc rollout restart deploy/mongo-portal`.
  Users re-authenticate to MongoDB (sessions are in memory anyway).
* `mongo-portal-proxy`: rotate and restart; users repeat SSO.
* MongoDB CA / client certificate: update the ConfigMap/Secret. Kubelet
  refreshes the files; new logins use the new CA, the client key pair is
  reloaded automatically when it changes. Existing sessions keep their current
  connections until they reconnect or expire.

What is deliberately **not** a Secret: MongoDB user passwords. Users type them at
login; the portal never stores them.
