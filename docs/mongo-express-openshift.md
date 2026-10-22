# mongo-express on OpenShift

Container images and OpenShift manifests for the Node.js mongo-express web
admin in this repository. For the multi-user portal with OpenShift SSO and
per-user MongoDB authentication, see [docs/portal](portal/README.md).

## Images (Chainguard / Wolfi)

| File | Tag | Contents |
| --- | --- | --- |
| `Dockerfile` | `docker.io/mohankrishna999/mongo-express:<version>` | The exact Chainguard/Wolfi package versions of the pinned `cgr.dev/chainguard/node` image (Node.js 26, glibc, OpenSSL, ICU, `dumb-init`, CA bundle) **without** its shell (busybox) and package managers (npm, node-gyp), plus the application. |
| `Dockerfile.debug` | `…:<version>-debug` | The same packages at the same versions (including busybox and npm) plus troubleshooting tools: bash, coreutils, curl, wget, bind-tools (dig/nslookup/host), openssl, iproute2 (ip/ss), net-tools (netstat), iputils (ping), mtr, traceroute, netcat, socat, tcpdump, ngrep, tshark, procps/htop/psmisc/sysstat, lsof, strace, ltrace, gdb, jq, yq, vim, less, file, diffutils, git, python3, the official checksum-verified **mongosh**, and the **MongoDB Database Tools** 100.19.1 (mongodump, mongorestore, mongoexport, mongoimport, mongostat, mongotop, bsondump, mongofiles) built from the verified release commit with a current Go toolchain and patched `golang.org/x/net` / `x/crypto` (MongoDB's prebuilt binaries use Go 1.26.8 and x/net 0.59.0, which have known CVEs). |

Both images run the identical application with the identical entrypoint
(`dumb-init -- node app.js`), environment, user and working directory; the
debug tools are only extra files on `PATH`. `scripts/test-images.sh` verifies
this (same functional tests on both, identical Node.js and base package
versions, identical application files and image configuration).

Both run as any UID with GID 0, need only `/tmp` writable, and are built for
`linux/amd64` and `linux/arm64`. In the debug image, tools that need extra
capabilities (`tcpdump`, `tshark` capture, `strace`/`gdb` attach) work only
if the pod is granted those capabilities, which the restricted SCCs do not do.

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t <image>:<tag> .
docker buildx build -f Dockerfile.debug --platform linux/amd64,linux/arm64 -t <image>:<tag>-debug .
bash scripts/test-images.sh <image>:<tag> <image>:<tag>-debug
```

### Vulnerability status

Scanned with Trivy, Grype (`--only-fixed`), govulncheck and `yarn npm audit`.
A scanner reporting nothing is not proof that no vulnerability exists; rebuild
regularly to pick up new Wolfi package releases.

| Image | Result |
|---|---|
| minimal | Trivy: no findings. Grype: no fixable findings. |
| debug | Trivy: 8 × UNKNOWN, all GO-2026-5932 (below). Grype: no fixable findings. |

`nmap` is deliberately not in the debug image: Wolfi ships only 7.94, which is
affected by a Medium CVE with no fixed package. Use `nc -zv <host> <port>` or
`socat` for connectivity checks.

Reviewed exceptions (not suppressed in any scanner configuration):

| ID | Component | Severity | Exploitability | Reason / mitigation | Review by |
|---|---|---|---|---|---|
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 in the debug image's MongoDB Database Tools | Unknown (deprecation advisory: `x/crypto/openpgp` is unmaintained) | Not reachable: no tool imports any `openpgp` package (`go list -deps` of all eight tools), and govulncheck source mode reports 0 reachable or imported vulnerabilities. Scanners flag it at module level only. | No fixed version exists; the advisory covers the whole package. Debug image only; the minimal image does not contain these tools. | 2027-01-31 |
| csurf deprecation | `csurf` 1.11.0 (mongo-express application dependency) | Moderate (npm audit: package archived, not a CVE) | No known vulnerability; CSRF protection works and is covered by `scripts/test-images.sh`. | Replacing it is an upstream mongo-express application change, outside the image work. Track upstream. | 2027-01-31 |

## SecurityContextConstraints

`deploy/cluster` (apply once per cluster, cluster-admin) creates:

| SCC | Used by | Policy |
| --- | --- | --- |
| `mongo-express-restricted` | mongo-express pods | restricted-v2 (namespace UID range, SELinux MustRunAs, no privilege escalation, all capabilities dropped, RuntimeDefault seccomp) **plus** mandatory read-only root filesystem and only configMap/downwardAPI/emptyDir/projected/secret volumes |
| `mongo-portal-restricted` | MongoDB portal pods | same |

and a `…-scc-use` ClusterRole for each. Each application namespace grants its
ServiceAccount `use` with a RoleBinding, and pods request the SCC explicitly
with the `openshift.io/required-scc` annotation (OpenShift 4.14+), so
admission fails loudly instead of silently choosing another SCC.

```bash
oc apply -k deploy/cluster                       # cluster-admin, once
oc get scc mongo-express-restricted mongo-portal-restricted
# after deploying, confirm the SCC used by the pods:
oc get pods -n mongo-express-prod -o custom-columns=NAME:.metadata.name,SCC:.metadata.annotations.openshift\\.io/scc
```

The pods are also valid under the built-in `restricted-v2` SCC; if you prefer
not to create custom SCCs, remove the `openshift.io/required-scc` annotation
and the RoleBinding.

## Deploying mongo-express

```
deploy/mongo-express/
  base/       Deployment, Service (service-CA TLS), re-encrypt Route,
              ServiceAccount + SCC RoleBinding, ConfigMap, NetworkPolicies, PDB
  overlays/dev   0.0.1-debug image
  overlays/prod  0.0.1 image (pin by digest), 2 replicas
deploy/argocd/mongo-express.yaml   AppProject + Applications (prod: manual sync)
deploy/argocd/cluster.yaml         SCC prerequisites (manual sync, cluster-admin Argo CD)
```

Existing Secrets (never stored in Git):

```bash
NS=mongo-express-prod
oc create secret generic mongo-express-url -n $NS \
  --from-literal=ME_CONFIG_MONGODB_URL='mongodb://<user>:<password>@<host-0>:27017,<host-1>:27017/?replicaSet=<rs>&authSource=admin' \
  --from-literal=ME_CONFIG_SITE_COOKIESECRET="$(openssl rand -hex 32)" \
  --from-literal=ME_CONFIG_SITE_SESSIONSECRET="$(openssl rand -hex 32)"
oc create secret generic mongo-express-basicauth -n $NS \
  --from-literal=username=<ui-user> --from-literal=password="$(openssl rand -base64 24)"
```

`mongo-express-tls` is created automatically by the service CA. The app reads
the certificate at start-up; after the service CA renews it, roll the
Deployment (`oc rollout restart deploy/mongo-express`).

Set the MongoDB namespace and pod labels in `overlays/*/patch-networkpolicy.yaml`,
then:

```bash
oc apply -k deploy/mongo-express/overlays/prod
oc rollout status deploy/mongo-express -n mongo-express-prod
oc get route mongo-express -n mongo-express-prod -o jsonpath='https://{.spec.host}{"\n"}'
```

Note: mongo-express connects to MongoDB with one shared account from
`ME_CONFIG_MONGODB_URL`; every UI user acts with that account's privileges.
Use a least-privilege MongoDB user, or use the portal for per-user access.
For MongoDB TLS set `ME_CONFIG_MONGODB_TLS=true` and
`ME_CONFIG_MONGODB_TLS_CA_FILE` (mount the CA from a ConfigMap and add it to
the Deployment).

## Troubleshooting with the debug image

```bash
oc set image deploy/mongo-express mongo-express=docker.io/mohankrishna999/mongo-express:0.0.1-debug -n $NS
oc rsh deploy/mongo-express bash
  dig +short <mongo-host>; curl -kv https://localhost:8081/status
  mongosh "$ME_CONFIG_MONGODB_URL" --eval 'db.adminCommand({ping:1})'
  mongostat --uri "$ME_CONFIG_MONGODB_URL" -n 3
# revert to the minimal image afterwards
```
