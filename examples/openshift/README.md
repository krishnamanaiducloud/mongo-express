# OpenShift manifests

Kustomize bases, per-environment overlays and Argo CD resources for running
both applications of this repository on OpenShift. Nothing here creates,
changes or deletes an existing MongoDB StatefulSet, Service, PVC or Secret.

```
examples/openshift/
├── cluster/            SecurityContextConstraints (+ "use" ClusterRoles). Cluster-admin, once per cluster.
├── mongo-portal/       Multi-user MongoDB portal (per-user MongoDB login, in-browser mongosh)
│   ├── base/           Deployment, Service, re-encrypt Route, ServiceAccount (OAuth client),
│   │                   SCC RoleBinding, config, RBAC policy ConfigMap, NetworkPolicies, PDB
│   ├── components/     monitoring (ServiceMonitor)
│   └── overlays/       dev, test, prod (config.yaml, patch-rbac.yaml, patch-networkpolicy.yaml)
├── mongo-express/      The mongo-express web admin (shared MongoDB connection)
│   ├── base/           same building blocks
│   └── overlays/       dev, prod
└── argocd/             AppProjects + Applications (prod syncs manually)
```

## What both applications provide

| | mongo-portal | mongo-express |
| --- | --- | --- |
| OpenShift login (like Argo CD) | built in, passive (offered only when reachable) | built in, passive |
| Without OpenShift | users sign in with their own MongoDB credentials | local account sign-in |
| RBAC | Argo CD-style policy (`mongo-portal-rbac` ConfigMap) on top of each user's own MongoDB privileges | Argo CD-style policy (`mongo-express-rbac` ConfigMap) over the shared connection |
| Pod security | `mongo-portal-restricted` SCC | `mongo-express-restricted` SCC |
| Service account permissions | none (token used only as the OAuth client secret) | none |

"Passive" means an unavailable integration never breaks the application.
OpenShift login is not offered while the OAuth server cannot be reached, and
a missing RBAC ConfigMap falls back to the built-in default role. MongoDB
health is reported in the UI instead of failing requests.

## Order of operations

```bash
oc apply -k examples/openshift/cluster                          # cluster-admin, once
# create the Secrets (docs/portal/secrets.md, docs/mongo-express-openshift.md)
oc apply -k examples/openshift/mongo-portal/overlays/prod       # or Argo CD: argocd/application.yaml
oc apply -k examples/openshift/mongo-express/overlays/prod      # or Argo CD: argocd/mongo-express.yaml
```

Replace every `REPLACE-…` value (MongoDB hosts and labels, group names) with
values discovered from your cluster first. See
[docs/portal/deployment.md](../../docs/portal/deployment.md),
[docs/portal/rbac.md](../../docs/portal/rbac.md) and
[docs/mongo-express-openshift.md](../../docs/mongo-express-openshift.md).
