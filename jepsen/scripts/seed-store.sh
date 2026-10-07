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
#   4. The admin console, as the operator: sign in, enrol TOTP (the system
#      realm always requires MFA), create the realm admin with a password,
#      and grant it realm.admin. A system-realm token cannot manage another
#      realm's users, so the workloads act as this admin.
#   5. Stop the server; `hearth admin token` on the store, which holds no raft.db.
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
#   REALM              realm the workloads use, default jepsen (declared in SEED_CONFIG)
#   REALM_ADMIN_EMAIL  that realm's admin account to create
#   REALM_ADMIN_PASSWORD  its password
#   TOKEN_TTL          token lifetime, default 1h (the CLI maximum)
#   SEED_LOG           server log file, default <data_dir>.log
set -euo pipefail

: "${HEARTH:?}" "${HEARTH_MASTER_KEY:?}" "${SEED_CONFIG:?}" "${SEED_DATA_DIR:?}"
: "${SEED_URL:?}" "${SEED_CA:?}" "${OPERATOR_EMAIL:?}" "${OPERATOR_PASSWORD:?}"
: "${REALM_ADMIN_EMAIL:?}" "${REALM_ADMIN_PASSWORD:?}"
REALM=${REALM:-jepsen}
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

# totp <base32-secret>: the current RFC 6238 code (SHA-1, 30 s, 6 digits).
totp() {
  local secret=$1 pad key counter mac off bin
  pad=$(((8 - ${#secret} % 8) % 8))
  key=$(printf '%s%*s' "$secret" "$pad" '' | tr ' ' '=' | base32 -d | od -An -v -tx1 | tr -d ' \n')
  counter=$(printf '%016x' $(($(date +%s) / 30)) | sed 's/../\\x&/g')
  mac=$(printf "$counter" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -binary \
    | od -An -v -tx1 | tr -d ' \n')
  off=$((16#${mac:39:1} * 2))
  bin=$((16#${mac:off:8} & 0x7fffffff))
  printf '%06d\n' $((bin % 1000000))
}

# post <path> <expected-status> [curl --data-urlencode args...]: POSTs a form
# with the page's _csrf and sets $location to the redirect target.
post() {
  local path=$1 want=$2 got
  shift 2
  got=$(http -o "$page" -w '%{http_code} %{redirect_url}' -X POST "$SEED_URL$path" \
    --data-urlencode "_csrf=$(hidden _csrf)" "$@")
  location=${got#* }
  [ "${got%% *}" = "$want" ] || die "POST $path answered ${got%% *}, expected $want"
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

log "console sign-in as the operator, enrolling TOTP"
http -o "$page" "$SEED_URL/ui/admin/login"
post /ui/admin/login 303 \
  --data-urlencode "email=$OPERATOR_EMAIL" --data-urlencode "password=$OPERATOR_PASSWORD"
case "$location" in
  */ui/mfa-enroll-required) ;;
  *) die "the console sign-in went to '$location', not TOTP enrolment" ;;
esac
http -o "$page" "$location"
secret=$(sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p' "$page" | head -n 1)
[ -n "$secret" ] || die "the TOTP enrolment page shows no secret"
post /ui/mfa-enroll-required/activate 303 --data-urlencode "code=$(totp "$secret")"

log "creating $REALM_ADMIN_EMAIL, admin of realm $REALM"
http -o "$page" "$SEED_URL/ui/admin/realms/$REALM/users/new"
post "/ui/admin/realms/$REALM/users/new" 303 \
  --data-urlencode "email=$REALM_ADMIN_EMAIL" --data-urlencode "display_name=Jepsen realm admin" \
  --data-urlencode "first_name=" --data-urlencode "last_name=" \
  --data-urlencode "password=$REALM_ADMIN_PASSWORD"
user_id=${location##*/users/}
[[ $user_id =~ ^[0-9a-f-]{36}$ ]] || die "creating the realm admin went to '$location'"
http -o "$page" "$location"
post "/ui/admin/realms/$REALM/admins/grant" 303 --data-urlencode "user_id=$user_id"

log "stopping the seed server"
kill -TERM "$server_pid"
wait "$server_pid" || true
server_pid=

[ ! -e "$SEED_DATA_DIR/raft.db" ] || die "the seed store holds raft.db"

log "minting a system-realm token (ttl $TOKEN_TTL)"
"$HEARTH" admin token --config "$SEED_CONFIG" --data-dir "$SEED_DATA_DIR" \
  --user "$OPERATOR_EMAIL" --ttl "$TOKEN_TTL"
