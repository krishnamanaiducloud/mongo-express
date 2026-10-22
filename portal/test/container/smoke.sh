#!/usr/bin/env bash
# Container smoke test for the production and debug images.
#
# For each image and several arbitrary UIDs (GID 0, as assigned by OpenShift
# restricted-v2) the portal runs with a read-only root filesystem, all
# capabilities dropped and no-new-privileges. It must become healthy, serve
# the UI with security headers, and complete an SSO -> MongoDB login -> query
# flow against a disposable MongoDB container.
#
# Usage: smoke.sh <production-image> <debug-image>
set -euo pipefail
PROD="${1:?production image}"
DEBUG="${2:?debug image}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"
NET="portal-smoke-$$"
WORK="$(mktemp -d)"
PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
pass=0; fail=0
ok()  { echo "  PASS $*"; pass=$((pass+1)); }
bad() { echo "  FAIL $*"; fail=$((fail+1)); }

cleanup() {
  docker ps -aq --filter "label=portal-smoke=$$" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run -d --label "portal-smoke=$$" --name "smoke-mongo-$$" --network "$NET" --network-alias mongo \
  -e MONGO_INITDB_ROOT_USERNAME=smoke -e MONGO_INITDB_ROOT_PASSWORD="$PW" "$MONGO_IMAGE" --wiredTigerCacheSizeGB 0.25 >/dev/null

cat > "$WORK/config.yaml" <<'EOF'
environment: smoke
server:
  listenAddress: 127.0.0.1:8080
  opsListenAddress: 0.0.0.0:9090
identity:
  mode: header
  developerGroups: [devs]
  sreGroups: [sres]
profiles:
  - name: local
    uri: mongodb://mongo:27017/
    tls:
      mode: disabled
EOF
chmod 0644 "$WORK/config.yaml"; chmod 0755 "$WORK"

for _ in $(seq 1 60); do docker exec "smoke-mongo-$$" mongosh --quiet -u smoke -p "$PW" --eval 'db.adminCommand({ping:1})' >/dev/null 2>&1 && break; sleep 1; done

# curl runs from the debug image inside the portal's network namespace, which
# is the only place the loopback-bound API is reachable (as in the pod).
curl_in() { local c="$1"; shift; docker run --rm --label "portal-smoke=$$" --network "container:$c" --entrypoint curl "$DEBUG" -sS "$@"; }

run_case() { # image label uid
  local img="$1" label="$2" uid="$3"
  local c="smoke-$label-$uid-$$"
  echo "== $label as uid $uid"
  docker run -d --label "portal-smoke=$$" --name "$c" --network "$NET" \
    --user "$uid:0" --read-only --tmpfs /tmp:rw,size=16m --cap-drop ALL --security-opt no-new-privileges \
    -v "$WORK/config.yaml:/etc/mongo-portal/config.yaml:ro" "$img" >/dev/null
  local healthy=""
  for _ in $(seq 1 30); do
    if curl_in "$c" -fs http://127.0.0.1:9090/readyz >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
  done
  if [ -n "$healthy" ]; then ok "ready"; else bad "not ready"; docker logs "$c" | tail -20; return; fi
  docker exec "$c" /usr/bin/mongo-portal healthcheck >/dev/null 2>&1 && ok "built-in healthcheck" || bad "built-in healthcheck"
  [ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] && ok "running non-root uid $uid" || bad "not running"

  local hdrs; hdrs="$(curl_in "$c" -s -D - -o /dev/null http://127.0.0.1:8080/)"
  grep -qi "content-security-policy: default-src 'self'" <<<"$hdrs" && ok "UI served with CSP" || bad "CSP missing"
  curl_in "$c" -s http://127.0.0.1:8080/ | grep -q '<div id="root">' && ok "UI index.html" || bad "UI index"

  local H=(-H "X-Forwarded-User: smoke-sre" -H "X-Forwarded-Groups: sres")
  local me; me="$(curl_in "$c" -s "${H[@]}" http://127.0.0.1:8080/api/v1/me)"
  local tok; tok="$(sed -n 's/.*"csrfToken":"\([^"]*\)".*/\1/p' <<<"$me")"
  [ -n "$tok" ] && ok "SSO identity accepted" || { bad "me: $me"; return; }
  [ "$(curl_in "$c" -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/v1/me)" = 401 ] && ok "no identity -> 401" || bad "no identity"

  local login; login="$(curl_in "$c" -s -c /tmp/jar -D - "${H[@]}" -H 'Content-Type: application/json' -H "X-CSRF-Token: $tok" \
    -d "{\"profile\":\"local\",\"username\":\"smoke\",\"password\":\"$PW\"}" http://127.0.0.1:8080/api/v1/session)"
  grep -qi 'set-cookie: __Host-mongo_portal_session=.*HttpOnly.*Secure.*SameSite=Strict' <<<"$login" && ok "login: secure session cookie" || bad "login: $(tail -1 <<<"$login")"
  local cookie; cookie="$(sed -n 's/.*[Ss]et-[Cc]ookie: \(__Host-mongo_portal_session=[^;]*\).*/\1/p' <<<"$login" | head -1)"
  local dbs; dbs="$(curl_in "$c" -s "${H[@]}" -H "Cookie: $cookie" http://127.0.0.1:8080/api/v1/databases)"
  grep -q '"admin"' <<<"$dbs" && ok "authenticated MongoDB query" || bad "databases: $dbs"
  local badlogin; badlogin="$(curl_in "$c" -s -o /dev/null -w '%{http_code}' "${H[@]}" -H 'Content-Type: application/json' -H "X-CSRF-Token: $tok" \
    -d '{"profile":"local","username":"smoke","password":"wrong"}' http://127.0.0.1:8080/api/v1/session)"
  [ "$badlogin" = 401 ] && ok "invalid password -> 401" || bad "invalid password -> $badlogin"
  docker logs "$c" 2>&1 | grep -q "$PW" && bad "password found in logs" || ok "password not in logs"
  docker rm -f "$c" >/dev/null
}

for uid in 1000680000 123456 65532; do
  run_case "$PROD" production "$uid"
  run_case "$DEBUG" debug "$uid"
done

echo "== image properties"
if docker run --rm --entrypoint /bin/sh "$PROD" -c true >/dev/null 2>&1; then bad "production image contains a shell"; else ok "production image has no shell"; fi
pm=""
for b in apk apt yum dnf; do
  if docker run --rm --entrypoint "$b" "$PROD" --version >/dev/null 2>&1 || docker run --rm --entrypoint "$b" "$DEBUG" --version >/dev/null 2>&1; then pm="$pm $b"; fi
done
[ -z "$pm" ] && ok "no package manager in either image" || bad "package manager present:$pm"
docker run --rm --user 1000680000:0 --read-only --tmpfs /tmp --entrypoint mongosh "$DEBUG" --version >/dev/null 2>&1 && ok "mongosh runs in debug image (arbitrary uid, read-only rootfs)" || bad "mongosh"
docker run --rm --network "$NET" --user 1000680000:0 --read-only --tmpfs /tmp --entrypoint mongosh "$DEBUG" --quiet "mongodb://smoke:$PW@mongo:27017/?authSource=admin" --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1 \
  && ok "mongosh connects to MongoDB from debug image" || bad "mongosh connect"
missing=""
for t in sh curl dig nslookup openssl ss ip ps top jq; do
  docker run --rm --user 1000680000:0 --read-only --entrypoint sh "$DEBUG" -c "command -v $t" >/dev/null 2>&1 || missing="$missing $t"
done
[ -z "$missing" ] && ok "debug tools present (sh curl dig nslookup openssl ss ip ps top jq)" || bad "debug tools missing:$missing"
docker run --rm --user 1000680000:0 --read-only --entrypoint sh "$DEBUG" -c 'openssl version && curl --version | head -1 && dig -v 2>&1' >/dev/null 2>&1 \
  && ok "debug tools execute as arbitrary uid" || bad "debug tools fail to execute"
[ "$(docker inspect -f '{{.Config.User}}' "$PROD")" = "65532:0" ] && ok "default user 65532:0" || bad "default user"

echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
