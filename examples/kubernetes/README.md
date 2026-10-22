# Kubernetes example

This example shows how to run mongo-express in a Kubernetes cluster.
The manifests in the example don't include MongoDB installation. The MongoDB service name used in [url-secret.yml](./url-secret.yml) must resolve from the mongo-express pod.

In [deployment.yml](./deployment.yml), `docker.io/mohankrishna999/mongo-express:0.0.1` is preconfigured for basic authentication and admin access.

The pod security settings are compatible with the OpenShift `restricted-v2` SCC: OpenShift can assign its namespace-specific UID, all Linux capabilities are dropped, privilege escalation is disabled, the default seccomp profile is used, and the root filesystem is read-only. A memory-backed `/tmp` volume provides temporary writable space without weakening the image filesystem.

## ConfigMap

Environment variables are configured in [configmap.yml](./configmap.yml).

## Secrets

Additional environment variables are read from [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
defined in [url-secret.yml](./url-secret.yml) and [basicauth-secret.yml](./basicauth-secret.yml). Even though taking credential values from a secret is
technically optional, it is often a recommended approach.

`url-secret.yml` contains the MongoDB connection string and the cookie/session secrets required by the application. Replace every sample value before applying the manifest; use different random values of at least 32 bytes for the cookie and session secrets. For example, generate each value separately with `openssl rand -hex 32`. Do not commit production credentials.

If you use the root user created by the official MongoDB image, include `authSource=admin` in the connection string. `basicauth-secret.yml` contains only the mongo-express web login credentials.
