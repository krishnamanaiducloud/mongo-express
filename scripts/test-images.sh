#!/usr/bin/env bash
# Functional and property tests for the mongo-express images.
#
# Runs the same functional assertions against the minimal and the debug image
# (both as an arbitrary UID with a read-only root filesystem), proves the
# debug image's extra tools do not change the runtime (identical Node.js and
# base package versions), and checks the image properties.
#
# Usage: scripts/test-images.sh <minimal-image> <debug-image>
set -uo pipefail
MIN="${1:?minimal image}"
DBG="${2:?debug image}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"
CURL_IMAGE="${CURL_IMAGE:-cgr.dev/chainguard/curl:latest}"
NET="me-test-$$"
WORK="$(mktemp -d)"
PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
UI_PW="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
pass=0; fail=0
ok()  { echo "  PASS $*"; pass=$((pass+1)); }
bad() { echo "  FAIL $*"; fail=$((fail+1)); }
cleanup() {
  docker ps -aq --filter "label=me-test=$$" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run -d --label "me-test=$$" --name "me-mongo-$$" --network "$NET" --network-alias mongo \
  -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD="$PW" "$MONGO_IMAGE" --wiredTigerCacheSizeGB 0.25 >/dev/null
# The mongo image runs a temporary mongod to create the root user and then
# restarts it, so wait for the init marker before seeding, and retry the seed.
for _ in $(seq 1 120); do docker logs "me-mongo-$$" 2>&1 | grep -q 'MongoDB init process complete' && break; sleep 1; done
seeded=""
for _ in $(seq 1 60); do
  if docker exec "me-mongo-$$" mongosh --quiet -u root -p "$PW" --eval '
       const o = db.getSiblingDB("app").orders; o.deleteMany({});
       o.insertMany(Array.from({ length: 30 }, (_, n) => ({ n, sku: "S" + n })));
       if (o.countDocuments() !== 30) quit(1)' >/dev/null 2>&1; then seeded=1; break; fi
  sleep 1
done
[ -n "$seeded" ] || { echo "test MongoDB could not be seeded"; docker logs --tail 20 "me-mongo-$$"; exit 2; }

# Self-signed certificate for the HTTPS mode test (generated in a throwaway container).
docker run --rm -u "$(id -u):$(id -g)" -v "$WORK:/out" --entrypoint sh cgr.dev/chainguard/wolfi-base:latest -c \
  'apk add -q --no-cache openssl >/dev/null 2>&1 || true; openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout /out/tls.key -out /out/tls.crt >/dev/null 2>&1' \
  || docker run --rm -v "$WORK:/out" --entrypoint openssl "$DBG" req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout /out/tls.key -out /out/tls.crt >/dev/null 2>&1
chmod 0644 "$WORK"/tls.* 2>/dev/null; chmod 0755 "$WORK"

curl_in() { local c="$1"; shift; docker run --rm --label "me-test=$$" --network "container:$c" "$CURL_IMAGE" -sS "$@"; }

start() { # name image extra-env...
  local name="$1" img="$2"; shift 2
  docker run -d --label "me-test=$$" --name "$name" --network "$NET" \
    --user 1000680000:0 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges \
    -e ME_CONFIG_MONGODB_URL="mongodb://root:$PW@mongo:27017/?authSource=admin" \
    -e ME_CONFIG_BASICAUTH_ENABLED=true -e ME_CONFIG_BASICAUTH_USERNAME=admin -e ME_CONFIG_BASICAUTH_PASSWORD="$UI_PW" \
    -e ME_CONFIG_SITE_COOKIESECRET="cookie-$PW" -e ME_CONFIG_SITE_SESSIONSECRET="session-$PW" \
    -v "$WORK:/certs:ro" "$@" "$img" >/dev/null
}

functional() { # label image
  local label="$1" img="$2" c="me-app-$1-$$"
  echo "== functional: $label ($img)"
  start "$c" "$img"
  local up=""
  for _ in $(seq 1 40); do [ "$(curl_in "$c" -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/status 2>/dev/null)" = 200 ] && up=1 && break; sleep 1; done
  if [ -n "$up" ]; then ok "starts as uid 1000680000 with read-only rootfs; /status 200"; else bad "app not healthy"; docker logs "$c" 2>&1 | tail -20; return; fi
  [ "$(curl_in "$c" -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/)" = 401 ] && ok "anonymous request rejected (401)" || bad "anonymous not rejected"
  local A=(-u "admin:$UI_PW")
  # Capture first, then match (grep -q on a pipe would SIGPIPE the producer under pipefail).
  local body
  body="$(curl_in "$c" "${A[@]}" http://127.0.0.1:8081/)"; grep -q '/db/app/' <<<"$body" && ok "database list shows 'app'" || bad "database list"
  body="$(curl_in "$c" "${A[@]}" 'http://127.0.0.1:8081/db/app/orders')"; grep -q 'S7' <<<"$body" && ok "collection view renders documents" || bad "collection view"
  body="$(curl_in "$c" "${A[@]}" 'http://127.0.0.1:8081/db/app/expArr/orders')"; grep -q 'S29' <<<"$body" && ok "JSON export works" || bad "JSON export"
  # Write through the UI: create a collection with the CSRF-protected form.
  local page csrf
  # The curl container runs as root only to write the cookie jar into the test directory.
  page="$(docker run --rm --label "me-test=$$" --network "container:$c" -u 0 -v "$WORK:/w" "$CURL_IMAGE" -sS -c "/w/jar-$label" "${A[@]}" http://127.0.0.1:8081/db/app)"
  csrf="$(echo "$page" | grep -oE 'name="_csrf" value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)"/\1/')"
  code="$(docker run --rm --label "me-test=$$" --network "container:$c" -u 0 -v "$WORK:/w" "$CURL_IMAGE" -sS -o /dev/null -w '%{http_code}' \
    -b "/w/jar-$label" -c "/w/jar-$label" "${A[@]}" --data-urlencode "_csrf=$csrf" --data-urlencode "collection=created_by_$label" http://127.0.0.1:8081/db/app)"
  [ "$(docker exec "me-mongo-$$" mongosh --quiet -u root -p "$PW" --eval "db.getSiblingDB('app').getCollectionNames().includes('created_by_$label') ? 'yes' : 'no'")" = yes ] \
    && ok "create collection through the UI (HTTP $code)" || bad "create collection through the UI (HTTP $code, csrf=${csrf:+set})"
  docker logs "$c" 2>&1 | grep -q "$PW" && bad "database password appears in logs" || ok "password not in logs"
  for _ in $(seq 1 45); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$c")" = healthy ] && break; sleep 1; done
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$c")" = healthy ] && ok "image HEALTHCHECK healthy" || bad "HEALTHCHECK not healthy"
  local t0=$SECONDS; docker stop -t 20 "$c" >/dev/null; local dt=$((SECONDS - t0))
  [ "$dt" -lt 10 ] && ok "stops on SIGTERM in ${dt}s (dumb-init forwards signals)" || bad "slow shutdown (${dt}s)"
  # HTTPS mode (as used on OpenShift with the service-CA certificate).
  start "$c-tls" "$img" -e ME_CONFIG_SITE_SSL_ENABLED=true -e ME_CONFIG_SITE_SSL_CRT_PATH=/certs/tls.crt -e ME_CONFIG_SITE_SSL_KEY_PATH=/certs/tls.key
  up=""; for _ in $(seq 1 40); do [ "$(curl_in "$c-tls" -k -o /dev/null -w '%{http_code}' https://127.0.0.1:8081/status 2>/dev/null)" = 200 ] && up=1 && break; sleep 1; done
  [ -n "$up" ] && ok "HTTPS mode serves /status" || { bad "HTTPS mode"; docker logs "$c-tls" 2>&1 | tail -5; }
}

functional minimal "$MIN"
functional debug "$DBG"

echo "== same runtime in both images"
vmin="$(docker run --rm --entrypoint /usr/bin/node "$MIN" --version)"; vdbg="$(docker run --rm --entrypoint /usr/bin/node "$DBG" --version)"
[ -n "$vmin" ] && [ "$vmin" = "$vdbg" ] && ok "identical Node.js ($vmin)" || bad "node versions differ: $vmin vs $vdbg"
pkgs() { local id; id=$(docker create "$1"); docker export "$id" | tar -xO usr/lib/apk/db/installed | awk '/^P:/{p=substr($0,3)} /^V:/{print p"="substr($0,3)}' | sort; docker rm "$id" >/dev/null; }
pkgs "$MIN" > "$WORK/min.pkgs"; pkgs "$DBG" > "$WORK/dbg.pkgs"
missing="$(comm -23 "$WORK/min.pkgs" "$WORK/dbg.pkgs")"
[ -z "$missing" ] && ok "every minimal-image package is in the debug image at the same version ($(wc -l < "$WORK/min.pkgs") packages)" || bad "packages differ: $missing"
for f in /opt/mongo-express/app.js /opt/mongo-express/package.json; do
  a=$(docker run --rm --entrypoint /usr/bin/node "$MIN" -e "process.stdout.write(require('crypto').createHash('sha256').update(require('fs').readFileSync('$f')).digest('hex'))")
  b=$(docker run --rm --entrypoint /usr/bin/node "$DBG" -e "process.stdout.write(require('crypto').createHash('sha256').update(require('fs').readFileSync('$f')).digest('hex'))")
  [ "$a" = "$b" ] && ok "identical $f" || bad "$f differs"
done
for i in "$MIN" "$DBG"; do
  docker image inspect "$i" --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{.Config.User}} {{.Config.WorkingDir}}' >> "$WORK/cfg"
done
[ "$(sort -u "$WORK/cfg" | wc -l)" = 1 ] && ok "identical entrypoint, command, user and workdir" || { bad "image configs differ"; cat "$WORK/cfg"; }

echo "== minimal image properties"
for b in sh bash busybox npm apk yarn curl; do
  docker run --rm --entrypoint "$b" "$MIN" --version >/dev/null 2>&1 && bad "minimal image contains $b"
done; ok "no shell, package manager or network tools in the minimal image"
echo "  packages: $(tr '\n' ' ' < "$WORK/min.pkgs")"

echo "== debug image tools (arbitrary uid, read-only rootfs)"
missing=""
for t in sh bash ash curl wget dig nslookup host openssl ss ip netstat ping traceroute mtr nc socat tcpdump ngrep tshark \
         ps top htop pstree pidof iostat lsof strace ltrace gdb jq yq vim less file diff git python3 npm node mongosh \
         mongodump mongorestore mongoexport mongoimport mongostat mongotop bsondump mongofiles; do
  docker run --rm --user 1000680000:0 --read-only --tmpfs /tmp --entrypoint sh "$DBG" -c "command -v $t" >/dev/null 2>&1 || missing="$missing $t"
done
[ -z "$missing" ] && ok "all debug tools present" || bad "debug tools missing:$missing"
docker run --rm --user 1000680000:0 --read-only --tmpfs /tmp --entrypoint bash "$DBG" -c \
  'set -e; curl --version >/dev/null; dig -v 2>/dev/null; openssl version >/dev/null; jq --version >/dev/null; git --version >/dev/null; python3 --version >/dev/null; npm --version >/dev/null; mongosh --version >/dev/null; mongodump --version | grep -q 100.19.1;  gdb --version >/dev/null; tcpdump --version >/dev/null 2>&1; tshark --version >/dev/null; mtr --version >/dev/null; strace -V >/dev/null; lsof -v >/dev/null 2>&1; htop --version >/dev/null; vim --version >/dev/null; yq --version >/dev/null' \
  && ok "debug tools execute as arbitrary uid" || bad "debug tools fail to execute"
[ "$(docker run --rm --network "$NET" --user 1000680000:0 --read-only --tmpfs /tmp --entrypoint mongosh "$DBG" --quiet \
  "mongodb://root:$PW@mongo:27017/?authSource=admin" --eval 'db.getSiblingDB("app").orders.countDocuments()')" = 30 ] \
  && ok "mongosh in the debug image connects to MongoDB" || bad "mongosh connection"
docker run --rm --network "$NET" --user 1000680000:0 --read-only --tmpfs /tmp --workdir /tmp --entrypoint mongodump "$DBG" \
  --uri "mongodb://root:$PW@mongo:27017/?authSource=admin" --db app --out /tmp/dump >/dev/null 2>&1 \
  && ok "mongodump (built from source) in the debug image works" || bad "mongodump"

echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
