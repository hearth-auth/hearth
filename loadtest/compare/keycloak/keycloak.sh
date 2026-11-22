#!/usr/bin/env bash
# Keycloak for the same-hardware comparison (#913): one server with Keycloak
# and its PostgreSQL (compose.yaml), the `stress` realm, and the seed.
#
# Usage: keycloak.sh <command>
#   up            make the bundle (first time), start PostgreSQL and Keycloak,
#                 wait until Keycloak is ready, create the realm (first time)
#   seed <from> <to>
#                 import password-less users bulk<from> .. bulk<to - 1> through
#                 partialImport (k6/prepare.js, PRODUCT=keycloak); prints the
#                 seed time (duration_s) from <bundle>/out/seed-<from>-<to>.json
#   restart       restart Keycloak (the data stays)
#   down          remove the containers and the database volume (the images stay)
#
# Environment:
#   BUNDLE              the bundle directory (default ../.build/keycloak): CA, TLS
#                       leaf, server.env, generator.env; mode 0700
#   SERVER_IP           the address the generator dials (default 127.0.0.1)
#   KC_BIND             the address Keycloak listens on (default 127.0.0.1)
#   LOGIN_USERS         users with a password (default 1000, as in #647)
#   IMPORT_BATCH, IMPORT_VUS   seed batch size and concurrency (prepare.js)
#   KEYCLOAK_MEM_LIMIT  Keycloak's container memory limit (default 2g)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
compare=$(cd "$here/.." && pwd)
export BUNDLE=${BUNDLE:-$compare/.build/keycloak}
export KC_HOST=keycloak.stress.test
set -a
# shellcheck disable=SC1091
. "$compare/images.env"
set +a

log() { printf 'keycloak: %s\n' "$*" >&2; }
die() {
  log "FAILED: $*"
  exit 2
}
compose() { docker compose -f "$here/compose.yaml" --env-file "$BUNDLE/server.env" "$@"; }
password() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

make_bundle() {
  [ ! -e "$BUNDLE" ] || return 0
  log "making the bundle in $BUNDLE"
  mkdir -p "$BUNDLE"
  chmod 0700 "$BUNDLE"
  bash "$compare/tls.sh" "$BUNDLE" "$KC_HOST"
  # Keycloak runs as uid 1000 in its image and must read the leaf; the bundle
  # directory (0700) keeps other users of this host out.
  chmod 0755 "$BUNDLE/tls"
  chmod 0644 "$BUNDLE/tls/https.key" "$BUNDLE/tls/https.crt"
  (
    umask 077
    # Compose variables (compose.yaml hands each container its own keys).
    printf 'DB_PASSWORD=%s\nKC_BOOTSTRAP_ADMIN_USERNAME=bootstrap\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' \
      "$(password)" "$(password)" > "$BUNDLE/server.env"
    cat > "$BUNDLE/generator.env" << EOF
PRODUCT=keycloak
STRESS_BASE=https://$KC_HOST:8443
STRESS_HOST=$KC_HOST
STRESS_SERVER_IP=${SERVER_IP:-127.0.0.1}
STRESS_REDIRECT_URI=https://app.stress.test/callback
STRESS_LOGIN_USERS=${LOGIN_USERS:-1000}
STRESS_USER_PASSWORD=$(password)
STRESS_ADMIN_EMAIL=admin@$KC_HOST
STRESS_ADMIN_PASSWORD=$(password)
STRESS_REALM=stress
STRESS_APP_CLIENT_ID=app
STRESS_API_CLIENT_ID=api
STRESS_API_SECRET=$(password)
EOF
  )
}

ready() {
  curl -fsS -o /dev/null --max-time 4 --cacert "$BUNDLE/ca.crt" \
    --resolve "$KC_HOST:9000:${SERVER_IP:-127.0.0.1}" "https://$KC_HOST:9000/health/ready" 2> /dev/null
}

wait_ready() {
  local i
  for i in $(seq 1 300); do
    if ready; then
      log "Keycloak is ready after ${i} s"
      return 0
    fi
    sleep 1
  done
  compose logs --tail 40 keycloak >&2
  die "Keycloak is not ready after 300 s"
}

cmd_up() {
  make_bundle
  compose up -d
  wait_ready
  if [ ! -e "$BUNDLE/realm.done" ]; then
    log "creating the realm and its login users"
    python3 -I "$here/realm.py" "$BUNDLE"
    touch "$BUNDLE/realm.done"
  fi
}

cmd_seed() {
  local from=${1:?usage: keycloak.sh seed <from> <to>} to=${2:?usage: keycloak.sh seed <from> <to>}
  local out=seed-$from-$to.json
  log "seeding users $from .. $((to - 1))"
  bash "$compare/k6.sh" "$BUNDLE" prepare.js IMPORT_FROM="$from" IMPORT_TO="$to" \
    IMPORT_BATCH="${IMPORT_BATCH:-1000}" IMPORT_VUS="${IMPORT_VUS:-4}" PREPARE_OUT="/out/$out" > /dev/null
  python3 -I - "$BUNDLE/out/$out" << 'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"seed: {r['users_imported']} imported, {r['users_import_failed']} failed, "
      f"{r['import_batches_failed']} batches failed, {r['duration_s']:.1f} s")
PY
}

cmd_restart() {
  compose restart keycloak
  wait_ready
}

cmd_down() {
  compose down --volumes --remove-orphans
}

case ${1:-} in
  up) cmd_up ;;
  seed) shift && cmd_seed "$@" ;;
  restart) cmd_restart ;;
  down) cmd_down ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2 && exit 2 ;;
esac
