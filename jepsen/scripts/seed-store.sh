#!/usr/bin/env bash
# Seeds one production-mode store with an operator account and mints a
# system-realm token into it (design decision 5). Every node of the cluster
# then starts from a copy of this store, so the token validates on all of them.
#
# The path is the one an operator follows; nothing in it is test-only:
#
#   1. `hearth serve` on the empty store, single-node (no `cluster:` section).
#   2. The first-boot setup form at /ui/setup, with the token from
#      <data_dir>/.setup_token (production never logs it).
#   3. The email-verification link from <data_dir>/.verification_url.
#   4. Stop the server; `hearth admin token` on the store, which holds no raft.db.
#
# The token goes to stdout and nowhere else. Progress goes to stderr.
#
# Environment:
#   HEARTH             the hearth binary
#   HEARTH_MASTER_KEY  the cluster's host key (64 hex characters)
#   SEED_CONFIG        single-node hearth.yaml; storage.data_dir is the store to seed.
#                      Its oidc.issuer must be the cluster's: the token names it.
#   SEED_DATA_DIR      that same data_dir (must not exist yet)
#   SEED_URL           HTTPS base URL of the seed server, e.g. https://localhost:28410
#   SEED_CA            CA certificate that signed the server's HTTPS leaf
#   OPERATOR_EMAIL     operator account to create
#   OPERATOR_PASSWORD  its password (12 characters or more)
#   TOKEN_TTL          token lifetime, default 1h (the CLI maximum)
#   SEED_LOG           server log file, default <data_dir>.log
set -euo pipefail

: "${HEARTH:?}" "${HEARTH_MASTER_KEY:?}" "${SEED_CONFIG:?}" "${SEED_DATA_DIR:?}"
: "${SEED_URL:?}" "${SEED_CA:?}" "${OPERATOR_EMAIL:?}" "${OPERATOR_PASSWORD:?}"
TOKEN_TTL=${TOKEN_TTL:-1h}
SEED_LOG=${SEED_LOG:-$SEED_DATA_DIR.log}

log() { printf 'seed-store: %s\n' "$*" >&2; }
die() {
  log "FAILED: $*"
  [ -f "$SEED_LOG" ] && tail -n 40 "$SEED_LOG" >&2
  exit 1
}

if [ -e "$SEED_DATA_DIR" ]; then
  die "$SEED_DATA_DIR exists; the seed store must start empty"
fi

jar=$(mktemp)
page=$(mktemp)
server_pid=
cleanup() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2> /dev/null; then
    kill "$server_pid" 2> /dev/null || true
    wait "$server_pid" 2> /dev/null || true
  fi
  rm -f "$jar" "$page"
}
trap cleanup EXIT

# No Origin header: the console compares it with the issuer's origin, and an
# absent header is same-site by design.
http() {
  curl --silent --show-error --cacert "$SEED_CA" -b "$jar" -c "$jar" "$@"
}

# The value of one hidden input in the page last fetched.
hidden() {
  sed -n "s/.*name=\"$1\" value=\"\([^\"]*\)\".*/\1/p" "$page" | head -n 1
}

log "starting the seed server ($SEED_URL)"
"$HEARTH" serve --config "$SEED_CONFIG" > "$SEED_LOG" 2>&1 &
server_pid=$!

for _ in $(seq 1 120); do
  kill -0 "$server_pid" 2> /dev/null || die "the seed server exited during start-up"
  if [ -s "$SEED_DATA_DIR/.setup_token" ] && http -f -o /dev/null "$SEED_URL/readyz" 2> /dev/null; then
    break
  fi
  sleep 0.5
done
[ -s "$SEED_DATA_DIR/.setup_token" ] || die "no setup token after 60 s"
setup_token=$(cat "$SEED_DATA_DIR/.setup_token")

log "first-boot setup for $OPERATOR_EMAIL"
http -L -o "$page" "$SEED_URL/ui/setup?token=$setup_token"
binding=$(hidden link_binding)
[ -n "$binding" ] || die "the setup page has no link_binding"
status=$(http -o "$page" -w '%{http_code}' -X POST "$SEED_URL/ui/setup" \
  --data-urlencode "link_binding=$binding" \
  --data-urlencode "admin_display_name=Jepsen Operator" \
  --data-urlencode "admin_email=$OPERATOR_EMAIL" \
  --data-urlencode "admin_password=$OPERATOR_PASSWORD")
[ "$status" = 303 ] || die "POST /ui/setup answered $status, expected 303"

log "verifying the operator's email"
[ -s "$SEED_DATA_DIR/.verification_url" ] || die "no verification URL file"
verification_url=$(cat "$SEED_DATA_DIR/.verification_url")
http -L -o "$page" "$verification_url"
binding=$(hidden link_binding)
csrf=$(hidden _csrf)
action=$(sed -n 's/.*<form method="post" action="\([^"]*\)".*/\1/p' "$page" | head -n 1)
[ -n "$binding" ] && [ -n "$action" ] || die "the verification page has no confirm form"
status=$(http -o "$page" -w '%{http_code}' -X POST "$SEED_URL$action" \
  --data-urlencode "link_binding=$binding" \
  --data-urlencode "_csrf=$csrf")
case "$status" in
  2??) ;;
  *) die "POST $action answered $status" ;;
esac

log "stopping the seed server"
kill -TERM "$server_pid"
wait "$server_pid" || true
server_pid=

[ ! -e "$SEED_DATA_DIR/raft.db" ] || die "the seed store holds raft.db"

log "minting a system-realm token (ttl $TOKEN_TTL)"
"$HEARTH" admin token --config "$SEED_CONFIG" --data-dir "$SEED_DATA_DIR" \
  --user "$OPERATOR_EMAIL" --ttl "$TOKEN_TTL"
