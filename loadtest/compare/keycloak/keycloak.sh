#!/usr/bin/env bash
# Keycloak for the same-hardware comparison (#913): one server with Keycloak
# and its PostgreSQL (compose.yaml), the `stress` realm, and the seed.
#
# Usage: keycloak.sh <command>
#   up            make the bundle (first time), start PostgreSQL and Keycloak,
#                 wait until Keycloak is ready, create the realm (first time)
#   bundle        make the bundle (first time) and nothing else
#   seed <from> <to>
#                 import password-less users bulk<from> .. bulk<to - 1> through
#                 partialImport (k6/prepare.js, PRODUCT=keycloak); prints the
#                 seed time (duration_s) from <bundle>/out/seed-<from>-<to>.json
#   ids <n> <file>
#                 write the ids of the realm's first <n> users, one per line,
#                 to <file>, in the admin API's order (GET .../users: by
#                 username, no service account), read from PostgreSQL: the
#                 #913 cold read's working set in seconds (paging the admin
#                 API by offset through 1M users takes about 45 min on 2
#                 vCPUs); fails, and writes no <file>, when the realm has fewer
#   restart       restart Keycloak (the data stays)
#   down          remove the containers and the database volume, and with them the
#                 realm (the images and the bundle's passwords stay)
#
# Environment:
#   BUNDLE              the bundle directory (default ../.build/keycloak): CA, TLS
#                       leaf, server.env, generator.env; mode 0700
#   SERVER_IP           the address the generator dials (default 127.0.0.1)
#   KC_BIND             the address Keycloak listens on (default 127.0.0.1)
#   LOGIN_USERS         users with a password (default 1000, as in #647)
#   IMPORT_BATCH, IMPORT_VUS   seed batch size and concurrency (prepare.js)
#   KEYCLOAK_MEM_LIMIT  Keycloak's container memory limit (default 2g)
#   COMPARE_VARIANT     a labelled variant: variant-<name>.yaml over compose.yaml
#                       (durable: synchronous commits for sessions too)
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
# COMPARE_VARIANT=<name>: the labelled variant, variant-<name>.yaml over
# compose.yaml (#913; compare.sh VARIANT).
compose() {
  local files=(-f "$here/compose.yaml")
  if [ -n "${COMPARE_VARIANT:-}" ]; then
    [ -f "$here/variant-$COMPARE_VARIANT.yaml" ] || die "no variant $COMPARE_VARIANT ($here/variant-$COMPARE_VARIANT.yaml)"
    files+=(-f "$here/variant-$COMPARE_VARIANT.yaml")
  fi
  docker compose "${files[@]}" --env-file "$BUNDLE/server.env" "$@"
}
password() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

make_bundle() {
  # A whole bundle (an earlier up's, or a ramp server's copy of the seed's,
  # whose passwords the store knows) is kept; a new or an empty directory
  # (remote.sh data-new makes /data/bundle) gets one.
  [ ! -f "$BUNDLE/server.env" ] || [ ! -f "$BUNDLE/generator.env" ] || return 0
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

# The ids of the realm's first $1 users in the order of the admin API's user
# list (Keycloak's JPA user search: the realm's users without service
# accounts, by username), into the file $2 (#913: compare.sh's 1M-id listing).
cmd_ids() {
  local n=${1:?usage: keycloak.sh ids <n> <file>} file=${2:?usage: keycloak.sh ids <n> <file>} realm got
  [[ $n =~ ^[1-9][0-9]*$ ]] || die "ids: $n is not a positive number"
  realm=$(sed -n 's/^STRESS_REALM=//p' "$BUNDLE/generator.env")
  [[ $realm =~ ^[a-z0-9-]+$ ]] || die "ids: no realm name in $BUNDLE/generator.env"
  if ! compose exec -T postgres psql -U keycloak -d keycloak -v ON_ERROR_STOP=1 -Atq -c "COPY (
      SELECT u.id FROM user_entity u JOIN realm r ON r.id = u.realm_id
       WHERE r.name = '$realm' AND u.service_account_client_link IS NULL
       ORDER BY u.username LIMIT $n) TO STDOUT" > "$file.part"; then
    rm -f "$file.part"
    die "ids: the query failed"
  fi
  got=$(wc -l < "$file.part")
  [ "$got" -eq "$n" ] || { rm -f "$file.part"; die "ids: the realm has $got users, fewer than $n"; }
  mv "$file.part" "$file"
  log "ids: the first $n users' ids in $file"
}

cmd_restart() {
  compose restart keycloak
  wait_ready
}

cmd_down() {
  compose down --volumes --remove-orphans
  # The realm went with the database: the next `up` makes it again.
  rm -f "$BUNDLE/realm.done"
}

case ${1:-} in
  bundle) make_bundle ;;
  up) cmd_up ;;
  seed) shift && cmd_seed "$@" ;;
  ids) shift && cmd_ids "$@" ;;
  restart) cmd_restart ;;
  down) cmd_down ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2 && exit 2 ;;
esac
