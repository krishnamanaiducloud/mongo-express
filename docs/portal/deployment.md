# Deployment on OpenShift

This deploys **only** the portal. It never creates, modifies or restarts the
existing MongoDB StatefulSet, Services, PVCs or replica-set configuration.

## 1. Discover the existing MongoDB deployment

Do not guess these values; read them from the cluster.

```bash
# Where MongoDB runs
oc get statefulsets -A | grep -i mongo
MONGO_NS=<namespace from above>
MONGO_STS=<statefulset name>

# Service DNS names (headless service gives per-member names)
oc get svc -n "$MONGO_NS"
oc get sts "$MONGO_STS" -n "$MONGO_NS" -o jsonpath='{.spec.serviceName}{"\n"}'
oc get sts "$MONGO_STS" -n "$MONGO_NS" -o jsonpath='{.spec.selector.matchLabels}{"\n"}'
oc get pods -n "$MONGO_NS" -o wide
#   member DNS: <pod>.<serviceName>.<MONGO_NS>.svc.cluster.local:27017

# Pod labels (for the NetworkPolicy egress selector)
oc get pods -n "$MONGO_NS" --show-labels | grep -i mongo

# Replica-set name and members (read-only commands; run with an existing admin account)
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'const s = rs.status(); print(s.set); s.members.forEach(m => print(m.name, m.stateStr))'

# TLS status (expected today: disabled)
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'printjson(db.adminCommand({getCmdLineOpts:1}).parsed.net)'

# Authentication database of existing users (usually "admin")
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'db.getSiblingDB("admin").system.users.find({}, {user:1, db:1, _id:0}).forEach(printjson)'
```

## 2. Prerequisites

* OpenShift 4.x with the integrated OAuth server (corporate IdP configured).
* Two OpenShift Groups, e.g. `mongo-portal-developers-prod` and
  `mongo-portal-sre-prod` (`oc adm groups new â€¦` or LDAP/OIDC group sync).
* A namespace for the portal (`oc new-project mongo-portal-prod`), with network
  access to the MongoDB pods on 27017.
* Individual MongoDB users for every portal user ([mongodb-rbac.md](mongodb-rbac.md)).
* Pull access to `docker.io/mohankrishna999/mongo-express` and to an OAuth proxy
  image (Red Hat `ose-oauth-proxy` recommended in production).

## 3. Apply the SecurityContextConstraints (once per cluster)

The portal pods run under the dedicated `mongo-portal-restricted` SCC
(restricted-v2 plus a mandatory read-only root filesystem and a minimal
volume allowlist), requested with the `openshift.io/required-scc` annotation.
A cluster administrator applies it once:

```bash
oc apply -k deploy/cluster
oc get scc mongo-portal-restricted
```

The namespace grants the portal ServiceAccount `use` of it with the RoleBinding
in `deploy/base/rbac-scc.yaml`. See [mongo-express-openshift.md](../mongo-express-openshift.md#securitycontextconstraints).

## 4. Create the Secrets (once per namespace)

See [secrets.md](secrets.md). Minimum:

```bash
NS=mongo-portal-prod
oc create secret generic mongo-portal-proxy   -n $NS --from-literal=cookie-secret="$(openssl rand -base64 32 | tr -d '\n' | head -c 32)"
oc create secret generic mongo-portal-session -n $NS --from-literal=session-key="$(openssl rand -hex 32)"
# Only for TLS profiles:
oc create configmap mongo-portal-mongodb-ca -n $NS --from-file=ca.crt=./mongodb-ca.pem
oc create secret tls mongo-portal-mongodb-client -n $NS --cert=client.crt --key=client.key   # mutual TLS only
```

`mongo-portal-tls` is created automatically by the service CA.

## 5. Configure the overlay

Edit `deploy/overlays/<env>/`:

| File | What to set |
| --- | --- |
| `kustomization.yaml` | `namespace`, image tag/digest, cluster-scoped object names |
| `config.yaml` | groups, MongoDB hosts (`uri`), `replicaSet`, `defaultAuthSource`, TLS block |
| `patch-cluster-scope.yaml` | group names in the ClusterRole, ServiceAccount namespace |
| `patch-networkpolicy.yaml` | MongoDB namespace and pod labels; optionally narrow API egress |

Production additionally requires a TLS decision in `config.yaml`: enable MongoDB
TLS, or record an approved exception (`plaintextApproved: true`,
`securityExceptionRef`). Without one, the portal refuses to start.

Render and review before applying:

```bash
oc kustomize deploy/overlays/prod | less
oc kustomize deploy/overlays/prod | oc apply --dry-run=server -f -
```

## 6. Deploy

GitOps (recommended): see [gitops.md](gitops.md). Manual:

```bash
oc apply -k deploy/overlays/prod
oc rollout status deploy/mongo-portal -n mongo-portal-prod
oc get route mongo-portal -n mongo-portal-prod -o jsonpath='https://{.spec.host}{"\n"}'
```

## 7. Verify

```bash
oc get pods -n $NS -l app.kubernetes.io/name=mongo-portal \
  -o custom-columns=NAME:.metadata.name,SCC:.metadata.annotations.openshift\\.io/scc,UID:.spec.securityContext.runAsUser
#   SCC must be mongo-portal-restricted
oc logs deploy/mongo-portal -c portal -n $NS | grep '"mongo portal started"'
oc exec deploy/mongo-portal -c portal -n $NS -- /usr/bin/mongo-portal healthcheck && echo healthy
```

Then browse to the Route: SSO login â†’ MongoDB login â†’ databases. Check that a
member of neither group gets "Access denied", that a developer sees no write
controls, and that `POST`/`DELETE` calls with a developer session return 403.

## Debug image

Use `â€¦:0.1.0-debug` (dev overlay default) or `oc debug`-style ephemeral
access:

```bash
oc set image deploy/mongo-portal portal=docker.io/mohankrishna999/mongo-express:0.1.0-debug -n $NS   # temporary
oc rsh -c portal deploy/mongo-portal
  dig +short <mongo-host>; curl -sv telnet://<mongo-host>:27017; openssl s_client -connect <host>:27017 -CAfile /etc/mongo-portal/mongodb-ca/ca.crt
  mongosh "mongodb://<host>:27017/?replicaSet=<rs>" -u <your-user> --authenticationDatabase admin
```

The debug image has no package manager and runs under the same restricted
security context; revert to the production image afterwards.
