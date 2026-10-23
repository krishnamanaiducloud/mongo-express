# Plain OpenShift manifests (no Kustomize)

The same resources as `examples/openshift/<app>/overlays/prod`, as one plain
YAML file per resource, like [`examples/kubernetes`](../../kubernetes). Use
these if you do not want Kustomize (`oc apply -k`) or Argo CD.

* No namespace is written in the files; you choose it with `oc apply -n <namespace>`.
* Files are numbered in apply order. `oc apply -f <dir>/` applies them all
  (not the `cluster/` and `optional/` subfolders, which are applied separately).
* `secrets.yml.example` is a template. Its extension keeps it from being applied
  by accident.
* These files are generated from the Kustomize overlays. After editing the
  overlays, regenerate them, or keep editing these copies directly.

```
plain/
├── mongo-express/        mongo-express web admin (shared MongoDB connection, local account fallback)
│   └── cluster/          SCC + ClusterRole (cluster-admin, once per cluster)
└── mongo-portal/         multi-user portal (each user signs in with their own MongoDB account)
    ├── cluster/          SCC + ClusterRole (cluster-admin, once per cluster)
    └── optional/         ServiceMonitor (only with user-workload monitoring)
```

## mongo-express

### 1. Edit before applying

| File | Set |
| --- | --- |
| `60-networkpolicy-mongo-express-egress.yml` | `REPLACE-mongodb-namespace` and `REPLACE-mongodb-pod-label`: the namespace and `app.kubernetes.io/name` label of your MongoDB pods (`oc get pods -n <mongodb-ns> --show-labels`). If your pods use another label key, change the key too |
| `21-configmap-mongo-express-rbac.yml` | Your OpenShift group names → roles (`oc get groups`) |
| `40-deployment-mongo-express.yml` | Optional: `replicas` (2), image (pinned by digest to `0.0.2`) |
| `20-configmap-mongo-express-config.yml` | Optional settings, for example `ME_CONFIG_OPENSHIFT_OAUTH` (`auto`/`false`) |

### 2. Apply

```bash
NS=mongo-express                                            # your namespace
oc new-project $NS                                          # if it does not exist

# Once per cluster, as cluster-admin (SCC + ClusterRole that permits using it):
oc apply -f examples/openshift/plain/mongo-express/cluster/

# Secrets (once):
oc create secret generic mongo-express-url -n $NS \
  --from-literal=ME_CONFIG_MONGODB_URL='mongodb://<user>:<password>@<host-0>:27017,<host-1>:27017/?replicaSet=<rs>&authSource=admin' \
  --from-literal=ME_CONFIG_SITE_COOKIESECRET="$(openssl rand -hex 32)" \
  --from-literal=ME_CONFIG_SITE_SESSIONSECRET="$(openssl rand -hex 32)"
oc create secret generic mongo-express-basicauth -n $NS \
  --from-literal=username=<ui-user> --from-literal=password="$(openssl rand -base64 24)"

# The application (namespace-scoped; any project admin):
oc apply -n $NS -f examples/openshift/plain/mongo-express/
oc rollout status deploy/mongo-express -n $NS
oc get route mongo-express -n $NS -o jsonpath='https://{.spec.host}{"\n"}'
```

`mongo-express-tls` (the HTTPS certificate) is created automatically by the
OpenShift service CA from the annotation in `30-service-mongo-express.yml`.

## mongo-portal

### 1. Edit before applying

| File | Set |
| --- | --- |
| `20-configmap-mongo-portal-config.yml` | MongoDB hosts (`uri`), `replicaSet`, `defaultAuthSource`. **TLS decision:** with `environment: production` the portal refuses to start on a plaintext profile until you either enable MongoDB TLS (`tls.mode: enabled` + CA) or record an approved exception (`plaintextApproved: true`, `securityExceptionRef`). For a non-production namespace, set `environment` to something else, for example `dev` |
| `60-networkpolicy-mongo-portal-egress.yml` | `REPLACE-mongodb-namespace`, `REPLACE-mongodb-pod-label` |
| `21-configmap-mongo-portal-rbac.yml` | Your OpenShift group names → roles; optional `mongodb:<user>@admin` lines |

### 2. Apply

```bash
NS=mongo-portal
oc new-project $NS

oc apply -f examples/openshift/plain/mongo-portal/cluster/            # cluster-admin, once
oc create secret generic mongo-portal-session -n $NS --from-literal=session-key="$(openssl rand -hex 32)"
# Only for TLS profiles:
#   oc create configmap mongo-portal-mongodb-ca -n $NS --from-file=ca.crt=./mongodb-ca.pem
#   oc create secret tls mongo-portal-mongodb-client -n $NS --cert=client.crt --key=client.key

oc apply -n $NS -f examples/openshift/plain/mongo-portal/
oc apply -n $NS -f examples/openshift/plain/mongo-portal/optional/    # only with user-workload monitoring
oc rollout status deploy/mongo-portal -n $NS
oc get route mongo-portal -n $NS -o jsonpath='https://{.spec.host}{"\n"}'
```

## Changing configuration later

The main ConfigMaps (`mongo-express-config`, `mongo-portal-config`) are read at
start-up. After editing them run `oc rollout restart deploy/<app> -n $NS`. The
Kustomize overlays do this automatically with hashed names; plain files do not.

The RBAC ConfigMaps (`*-rbac`) are re-read every 30 seconds. Apply the change
and wait; no restart is needed, and an invalid edit is rejected while the
previous policy stays active.

## Without the custom SCCs

If a cluster-admin cannot apply `cluster/scc.yml`, the pods also run under the
built-in `restricted-v2` SCC. Before applying, delete
`11-rolebinding-*-scc.yml` and remove the
`openshift.io/required-scc: …` annotation from `40-deployment-*.yml`.

More detail: [docs/mongo-express-openshift.md](../../../docs/mongo-express-openshift.md),
[docs/portal/deployment.md](../../../docs/portal/deployment.md),
[docs/portal/rbac.md](../../../docs/portal/rbac.md).
