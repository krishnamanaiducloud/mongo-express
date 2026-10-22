# mongo-portal

Enterprise MongoDB management portal: OpenShift SSO, individual MongoDB
authentication, MongoDB-native RBAC, TLS and non-TLS connection profiles.

Full documentation: [docs/portal](../docs/portal/README.md).

## Develop

```bash
# backend
go test -race ./internal/...
# frontend
cd web && npm ci --ignore-scripts && npm run lint && npm test && npm run build
# run locally against a local MongoDB (insecure dev identity, never in a cluster)
PORTAL_ALLOW_INSECURE_DEV_IDENTITY=true go run ./cmd/portal --config config/dev.example.yaml
cd web && npm run dev    # http://localhost:5173, proxies /api to :8080
```

## Test

```bash
make test               # unit tests (Go + web)
make integration        # disposable MongoDB replica sets (TLS + non-TLS), failover
make images smoke       # build both images, run them as arbitrary UIDs with a read-only rootfs
make scan               # govulncheck, gosec, npm audit, gitleaks, hadolint, trivy, grype, SBOMs
```

## Images

| Variant | Tag | Base | Contents |
| --- | --- | --- | --- |
| production | `docker.io/mohankrishna999/mongo-express:<version>` | `cgr.dev/chainguard/static` | portal binary, CA bundle, tzdata |
| debug | `docker.io/mohankrishna999/mongo-express:<version>-debug` | Wolfi packages on `scratch` | same binary + busybox, curl, bind-tools, openssl, iproute2, procps, jq, mongosh |

Both run as any UID with GID 0, need no writable path other than `/tmp`,
contain no package manager, and are built for `linux/amd64` and `linux/arm64`.

## mongosh

* **In the UI (both images):** the Shell page runs the real mongosh runtime in
  the browser, isolated in an opaque-origin sandbox and worker; every database
  operation goes through `/api/v1/shell` and is checked like the rest of the API.
  See [architecture](../docs/portal/architecture.md#in-browser-mongosh-shell).
* **CLI (debug image only):** `mongosh` binary for operators using `oc rsh`.

Browser end-to-end test: `bash test/e2e/run.sh mongo-portal:production`.
