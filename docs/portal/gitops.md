# GitOps with Argo CD

## Resources

`deploy/argocd/application.yaml` contains:

* **AppProject `mongo-portal`** – source repo restricted to this repository,
  destinations restricted to the three portal namespaces, and a resource
  *allowlist*: ServiceAccount, ConfigMap, Service, Deployment, Route,
  NetworkPolicy, PodDisruptionBudget, ServiceMonitor, plus ClusterRole and
  ClusterRoleBinding. StatefulSets, PVCs and Secrets are explicitly blacklisted,
  so Argo CD cannot create, adopt, modify or prune MongoDB workloads even if a
  manifest were added by mistake.
* **Applications** `mongo-portal-dev`, `mongo-portal-test` (automated sync with
  prune and self-heal) and `mongo-portal-prod` (manual sync only, no cascading
  finalizer).

Pruning only ever affects objects that Argo CD created from the Application's
own path (tracked via its instance label/annotation). Existing resources in the
namespace are never adopted unless they are rendered from the overlay.

```bash
ARGO_NS=openshift-gitops       # or your Argo CD namespace
# Adjust destination namespaces / repoURL / targetRevision first.
oc apply -n "$ARGO_NS" -f deploy/argocd/application.yaml
# The Argo CD application controller needs rights in the portal namespaces:
oc label namespace mongo-portal-prod argocd.argoproj.io/managed-by="$ARGO_NS"
```

ClusterRole/ClusterRoleBinding management requires the Argo CD instance to
have cluster-scoped permission for those two kinds. If your Argo CD is
namespace-scoped, apply `rbac.yaml` (rendered) once by a cluster admin and
remove it from the overlay.

## Release flow

1. CI (`.github/workflows/portal-ci.yml`) runs lint, tests, integration tests,
   scans, builds both images and renders/validates all overlays on every PR.
2. A maintainer pushes a tag `portal-vX.Y.Z`. The `release` job (protected
   GitHub environment, manual approval) builds multi-arch images, scans them,
   pushes `X.Y.Z` and `X.Y.Z-debug`, generates SBOM + provenance, and opens a PR
   that pins `deploy/overlays/prod` to the new digest.
3. Dev/test sync automatically from `master`; production is synced manually in
   Argo CD after the digest PR is reviewed and merged.

Rollback: revert the digest commit (or sync the previous revision in Argo CD).
Rollouts are zero-downtime (`maxUnavailable: 0`), but users on replaced pods
must sign in to MongoDB again.

## Drift

`ignoreDifferences` covers the cluster-assigned `Route.spec.host`. The
generated ConfigMap name carries a content hash, so configuration edits roll the
Deployment and old ConfigMaps are pruned after the sync.
