# OpenShift OAuth integration

## How it works

```
browser ─▶ Route ─▶ oauth-proxy (:8443, service-CA cert)
                     │ 1. no cookie → redirect to OpenShift OAuth server (corporate IdP)
                     │ 2. callback /oauth/callback, token exchange with the SA OAuth client
                     │ 3. sets _oauth_proxy cookie (Secure, HttpOnly)
                     ▼
                 portal (127.0.0.1:8080)  headers: X-Forwarded-User, X-Forwarded-Access-Token
```

* The ServiceAccount `mongo-portal` is the OAuth client
  (`--openshift-service-account=mongo-portal`). Its annotation
  `serviceaccounts.openshift.io/oauth-redirectreference.primary` points at the
  Route, so the only accepted redirect URI is the Route host + `/oauth/callback`.
* Requested scopes: `user:info user:check-access` (no API access on behalf of
  the user beyond identity).
* The proxy authenticates; **it does not authorize**. Any cluster user can pass
  the proxy. The portal then authorizes server-side:
  1. validates `X-Forwarded-Access-Token` via `GET /apis/user.openshift.io/v1/users/~`
     and checks it belongs to `X-Forwarded-User`;
  2. reads the configured Group objects (ClusterRole `get` on those names only);
  3. no membership → 403 page and audit event.

## Header spoofing

* The portal listener binds to `127.0.0.1`; the Service exposes only the proxy
  port; NetworkPolicy admits only the router. Nothing but the proxy can deliver
  requests to the portal.
* Even with headers forged inside the pod network namespace, the token check
  fails unless the attacker holds that user's valid OAuth token.
* Identity headers from any peer outside `identity.trustedProxyCIDRs` are rejected.

## Groups

```bash
oc adm groups new mongo-portal-developers-prod
oc adm groups new mongo-portal-sre-prod
oc adm groups add-users mongo-portal-sre-prod alice
# or sync from LDAP: oc adm groups sync --sync-config=ldap-sync.yaml --confirm
```

Changes take effect within `identity.openshift.groupCacheTTL` (default 1 minute).
Removing a user from all groups blocks them on the next request even if they
still hold a MongoDB session.

## Logout

* "Disconnect from MongoDB" ends the portal session and closes the connection.
* SSO sign-out depends on the proxy/IdP; set `identity.ssoLogoutURL` (for example
  the IdP's logout endpoint) to show a link. The `_oauth_proxy` cookie expires
  after `--cookie-expire` (8 h) and refreshes every hour.

## Proxy image

`deploy/base` uses `quay.io/openshift/origin-oauth-proxy:4.18` (community build).
For production use the Red Hat supported `registry.redhat.io/openshift4/ose-oauth-proxy-rhel9`
matching your cluster version, mirrored to your registry and pinned by digest:

```bash
oc get is oauth-proxy -n openshift -o jsonpath='{.status.tags[*].items[0].dockerImageReference}'
```
