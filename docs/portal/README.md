# MongoDB Management Portal

A Mongo Express–style web portal for MongoDB on OpenShift, where every database
operation runs as the signed-in user's **own MongoDB account**.

The portal lives in [`portal/`](../../portal) (Go backend + React UI) and is
deployed with [`examples/openshift/`](../../examples/openshift) (Kustomize + Argo CD). It is separate from
the Node.js mongo-express application at the repository root ([docs](../mongo-express-openshift.md)).

| Document | Contents |
| --- | --- |
| [architecture.md](architecture.md) | Components, request flow, authentication and authorization model |
| [configuration.md](configuration.md) | Every configuration key, TLS and non-TLS profiles |
| [deployment.md](deployment.md) | Step-by-step OpenShift deployment, discovery commands |
| [oauth.md](oauth.md) | Built-in OpenShift login (Argo CD style), passive behaviour, troubleshooting |
| [rbac.md](rbac.md) | Argo CD-style RBAC: policy format, roles, examples, where it is enforced |
| [mongodb-rbac.md](mongodb-rbac.md) | Creating developer and SRE MongoDB users |
| [secrets.md](secrets.md) | Required Secrets and keys (no values) |
| [gitops.md](gitops.md) | Argo CD setup, scoping, release flow |
| [threat-model.md](threat-model.md) | Assets, threats, mitigations, residual risks |
| [runbook.md](runbook.md) | Operations: monitoring, rotation, scaling, incidents |
| [troubleshooting.md](troubleshooting.md) | Symptoms and fixes |
| [disaster-recovery.md](disaster-recovery.md) | Recovery considerations |
| [testing-report.md](testing-report.md) | What was tested, results, gaps |

## Quick start (local, disposable MongoDB)

```bash
cd portal
docker build --target debug -t mongo-portal:debug .
bash test/container/smoke.sh mongo-portal:production mongo-portal:debug   # needs both images
bash test/integration/run.sh                                               # real MongoDB replica sets, TLS + non-TLS
```
