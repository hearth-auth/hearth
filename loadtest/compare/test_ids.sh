#!/usr/bin/env bash
# `<product>.sh ids <n> <file>` (#913): the first <n> users' ids from the
# product's PostgreSQL, in its admin API's order, one per line, for the
# products whose admin API pages by offset (Keycloak, Zitadel, Authentik).
# With a stand-in for docker that answers psql with made-up rows (no
# container, no network), checks for each product:
#   - the query: one COPY of the ids, in the admin API's order, LIMIT <n>
#   - <n> rows: <file> has them, one per line, and nothing else is left
#   - fewer rows, or a failed query: the command fails and writes no <file>
#
# Usage: bash loadtest/compare/test_ids.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

# docker: `docker compose ... exec -T postgres psql ... -c <sql>` prints
# min(IDS_ROWS, the query's last LIMIT) ids, id-1, id-2, ..., and keeps the query
# in $tmp/sql; IDS_FAIL=1 makes psql fail.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/docker" << 'EOF'
#!/usr/bin/env bash
sql=""
while [ $# -gt 0 ]; do
  [ "$1" != -c ] || sql=$2
  shift
done
printf '%s\n' "$sql" > "$IDS_TMP/sql"
[ "${IDS_FAIL:-}" != 1 ] || { echo "psql: error: the query failed" >&2; exit 1; }
limit=$(grep -o 'LIMIT [0-9]*' <<< "$sql" | tail -n 1 | awk '{print $2}')
n=$IDS_ROWS
[ -z "$limit" ] || [ "$limit" -ge "$n" ] || n=$limit
for i in $(seq 1 "$n"); do echo "id-$i"; done
EOF
chmod +x "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH" IDS_TMP=$tmp

# The admin API's order and filter of each product, as its query must have them.
declare -A ORDER=(
  [keycloak]="ORDER BY u.username"
  [zitadel]="ORDER BY u.id"
  [authentik]="ORDER BY username"
)
declare -A FILTER=(
  [keycloak]="u.service_account_client_link IS NULL"
  [zitadel]="u.type = 1"
  [authentik]="username <> 'AnonymousUser'"
)

for p in keycloak zitadel authentik; do
  b=$tmp/bundle-$p
  mkdir -p "$b"
  printf 'PRODUCT=%s\nSTRESS_REALM=stress\nSTRESS_ORG_ID=123456789\n' "$p" > "$b/generator.env"
  : > "$b/server.env"
  ids() { env BUNDLE="$b" bash "$here/$p/$p.sh" ids "$@" > "$tmp/$p.out" 2>&1; }

  out=$tmp/$p-ids.txt
  if IDS_ROWS=5 ids 3 "$out"; then
    if [ "$(cat "$out")" = "$(printf 'id-1\nid-2\nid-3')" ] && [ ! -e "$out.part" ]; then
      pass "$p: ids 3 writes the 3 ids, one per line"
    else
      fail "$p: ids 3 wrote: $(tr '\n' ' ' < "$out")"
    fi
  else
    fail "$p: ids 3 failed: $(tail -n 2 "$tmp/$p.out" | tr '\n' ' ')"
  fi
  sql=$(tr '\n' ' ' < "$tmp/sql" 2> /dev/null)
  [[ $sql == *"COPY ("* ]] && [[ $sql == *"${ORDER[$p]} LIMIT 3) TO STDOUT"* ]] && [[ $sql == *"${FILTER[$p]}"* ]] \
    && pass "$p: the query copies the ids in the admin API's order (${ORDER[$p]}), ${FILTER[$p]}" \
    || fail "$p: query: $sql"

  rm -f "$out"
  if IDS_ROWS=2 ids 3 "$out"; then
    fail "$p: ids 3 with 2 users did not fail"
  else
    [ ! -e "$out" ] && [ ! -e "$out.part" ] && grep -q 'fewer than 3' "$tmp/$p.out" \
      && pass "$p: fewer users than asked: fails, no file" || fail "$p: fewer users: $(ls "$tmp" | tr '\n' ' ')"
  fi
  if IDS_ROWS=5 IDS_FAIL=1 ids 3 "$out"; then
    fail "$p: a failed query did not fail"
  else
    [ ! -e "$out" ] && [ ! -e "$out.part" ] && pass "$p: a failed query: fails, no file" || fail "$p: failed query left a file"
  fi
  IDS_ROWS=5 ids 0 "$out" && fail "$p: ids 0 did not fail" || pass "$p: ids 0 is refused"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
