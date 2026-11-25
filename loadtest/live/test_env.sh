#!/usr/bin/env bash
# Tests remote/env.sh and launch.sh's environment (#913): a generator reads
# generator.env as data, never as shell code. In the AWS session's attempts 4
# and 5, launch.sh's `set -a; . generator.env` (set -u) stopped at Ory's
# bulk-password hash ($argon2id$v=19$...: "argon2id: unbound variable"), and
# k6 never started.
#
#   case 1  load_env exports each value exactly as written: an Argon2id PHC
#           hash, spaces, quotes, backticks and $(...) (neither runs), an
#           unset $NAME, '=' in a value, an empty value, a last line without
#           a newline; comments and blank lines are skipped; under set -u, as
#           launch.sh runs
#   case 2  a line that is not KEY=VALUE fails the load, which names its
#           number and not its content
#   case 3  redact leaves out each line with a secret's value (a key named
#           like a password, secret, token or hash) or such a word, and keeps
#           the others
#   case 4  launch.sh starts k6 with a generator.env from the real writers
#           (ory.sh's lines, then ory/realm.py's; zitadel's, then
#           zitadel/instance.py's: update_env and unusable_hash), and k6 sees
#           every value as written
#   case 5  no script sources generator.env any more
#
# Usage: bash loadtest/live/test_env.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
compare=$(cd "$here/../compare" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

# envjson.py <file> literal: the file's KEY=VALUE lines as JSON, each value as
# written (the rule). envjson.py <file> environ: the same keys' values in this
# process's environment.
cat > "$tmp/envjson.py" << 'PY'
import json, os, sys
want = {}
for line in open(sys.argv[1]).read().split("\n"):
    if line and not line.startswith("#"):
        k, v = line.split("=", 1)
        want[k] = v
if sys.argv[2] == "environ":
    want = {k: os.environ.get(k) for k in want}
print(json.dumps(want, sort_keys=True))
PY
literal() { python3 -I "$tmp/envjson.py" "$1" literal; }
# The values of $1's keys after load_env $1 in a `bash -u`.
loaded() {
  bash -uc '. "$1" && load_env "$2" && python3 -I "$3" "$2" environ' _ \
    "$here/remote/env.sh" "$1" "$tmp/envjson.py"
}

# Case 1.
cat > "$tmp/one.env" << 'EOF'
# a comment
PRODUCT=ory

STRESS_BULK_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGk
QUOTES='single' "double" \n
BACKTICKS=`touch TMP/backtick`
SUBST=$(touch TMP/subst)
UNSET=$NOT_SET_ANYWHERE ${ALSO_NOT_SET}
EQUALS=a=b==c
EMPTY=
EOF
sed -i "s|TMP|$tmp|g" "$tmp/one.env"
printf 'SPACES= a b  c \nLAST=no newline' >> "$tmp/one.env"
got=$(loaded "$tmp/one.env" 2> "$tmp/one.err")
want=$(literal "$tmp/one.env")
if [ "$got" = "$want" ] && [ ! -e "$tmp/backtick" ] && [ ! -e "$tmp/subst" ] && [ ! -s "$tmp/one.err" ]; then
  pass "load_env exports every value exactly as written (an Argon2id hash, spaces, quotes, backticks, \$(...), '='), and runs nothing"
else
  fail "load_env: got $got; want $want; ran: $(ls "$tmp" | grep -E '^(backtick|subst)$' | tr '\n' ' '); stderr: $(head -n 3 "$tmp/one.err")"
fi

# Case 2.
printf 'PRODUCT=ory\nnot a pair\nOTHER=1\n' > "$tmp/bad.env"
printf 'PRODUCT=ory\n1KEY=x\n' > "$tmp/badkey.env"
printf 'PRODUCT=ory\nA-B=x\n' > "$tmp/badname.env"
ok=1
for f in bad badkey badname; do
  if bash -uc '. "$1" && load_env "$2"' _ "$here/remote/env.sh" "$tmp/$f.env" 2> "$tmp/$f.err"; then
    ok=0
    echo "  $f.env loaded"
  elif ! grep -q "$tmp/$f.env: line 2 is not KEY=VALUE" "$tmp/$f.err" || grep -qE 'pair|1KEY|A-B' "$tmp/$f.err"; then
    ok=0
    echo "  $f.env: $(cat "$tmp/$f.err")"
  fi
done
[ "$ok" = 1 ] && pass "a line that is not KEY=VALUE fails the load, which names its number, not its content" \
  || fail "malformed lines"

# Case 3.
cat > "$tmp/secrets.env" << 'EOF'
PRODUCT=ory
STRESS_SERVER_IP=10.0.0.9
STRESS_USER_PASSWORD=Pw0rdOne
STRESS_API_SECRET=Vq7Lm2Xk
STRESS_METRICS_TOKEN=Rb4Nc8Ws
STRESS_BULK_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGln
STRESS_CC_SECRET=
EOF
cat > "$tmp/journal.txt" << 'EOF'
Started stress-job.service.
k6: dialing 10.0.0.9 failed
login with Pw0rdOne refused
Authorization: Basic Vq7Lm2Xk
bearer Rb4Nc8Ws
got $argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGln
STRESS_ADMIN_PASSWORD is not set
the api Secret was rotated
an id token expired
stress-job.service: Main process exited, code=exited, status=1/FAILURE
EOF
got=$(bash -c '. "$1" && redact "$2"' _ "$here/remote/env.sh" "$tmp/secrets.env" < "$tmp/journal.txt")
want=$(printf '%s\n' "Started stress-job.service." "k6: dialing 10.0.0.9 failed" \
  "stress-job.service: Main process exited, code=exited, status=1/FAILURE")
[ "$got" = "$want" ] && pass "redact leaves out every line with a secret's value or word, and keeps the others" \
  || fail "redact gave: $(tr '\n' '|' <<< "$got")"
got=$(bash -c '. "$1" && redact "$2"' _ "$here/remote/env.sh" "$tmp/missing.env" < "$tmp/journal.txt")
! grep -qE 'Pw0rdOne|Vq7Lm2Xk|Rb4Nc8Ws|ZGln' <<< "$got" && [ -n "$got" ] \
  && pass "redact without its env file leaves out every line (it says so)" || fail "redact without its env file: $got"

# Case 4: launch.sh in a stand-in /opt/stress (STRESS_ROOT), with a stand-in
# k6 (STRESS_K6) that prints its environment as JSON (into k6.txt).
cat > "$tmp/k6" << 'EOF'
#!/usr/bin/env bash
exec python3 -I -c 'import json, os; print(json.dumps(dict(os.environ)))'
EOF
chmod 0755 "$tmp/k6"
for writer in ory/realm.py zitadel/instance.py; do
  product=${writer%%/*}
  root=$tmp/root-$product
  mkdir -p "$root/out/job" "$root/k6"
  cp "$here/remote/env.sh" "$root/env.sh"
  printf 'exit 0\n' > "$root/sampler.sh"
  printf 'K6_SCRIPT=stress.js\nK6_NO_CSV=1\nJOURNEY=login\n' > "$root/out/job/params.env"
  # The product script's lines (ory.sh, zitadel.sh make_bundle), then the
  # realm setup's (main's update_env).
  printf 'PRODUCT=%s\nSTRESS_BASE=https://%s.stress.test:4444\nSTRESS_SERVER_IP=10.0.0.9\nSTRESS_USER_PASSWORD=abc123\nSTRESS_REALM=stress\n' \
    "$product" "$product" > "$root/generator.env"
  python3 -I - "$compare/$writer" "$root/generator.env" << 'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("writer", sys.argv[1])
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
w.update_env(sys.argv[2], {"STRESS_APP_CLIENT_ID": "app-id", "STRESS_API_CLIENT_ID": "api-id",
                           "STRESS_API_SECRET": "api-secret", "STRESS_BULK_PASSWORD_HASH": w.unusable_hash()})
PY
  if ! grep -q '^STRESS_BULK_PASSWORD_HASH=\$argon2id\$v=19\$' "$root/generator.env"; then
    fail "$writer: no \$argon2id\$ hash in its generator.env"
    continue
  fi
  STRESS_ROOT=$root STRESS_K6=$tmp/k6 bash "$here/remote/launch.sh" job > "$tmp/launch-$product.out" 2>&1
  status=$(cat "$root/out/job/k6.exit" 2> /dev/null)
  got=$(python3 -I - "$root/generator.env" "$root/out/job/k6.txt" << 'PY' 2>&1
import json, sys
want = dict(l.split("=", 1) for l in open(sys.argv[1]).read().split("\n") if l)
env = json.load(open(sys.argv[2]))
bad = [k for k, v in want.items() if env.get(k) != v]
print("ok" if not bad and env.get("K6_SCRIPT") == "stress.js" and env.get("JOURNEY") == "login" else f"differ: {bad}")
PY
  )
  if [ "$status" = 0 ] && [ "$got" = ok ]; then
    pass "launch.sh starts k6 with $writer's generator.env, its Argon2id hash as written"
  else
    fail "launch.sh with $writer's generator.env: k6.exit '${status:-none}', $got; $(grep -v ulimit "$tmp/launch-$product.out" | head -n 3)"
  fi
done

# Case 5: every reader of generator.env for k6 goes through load_env.
sourced=$(grep -nE '(^|[;&|[:space:]])\.[[:space:]]+[^[:space:]]*generator\.env' \
  "$here/cloud.sh" "$here/steady-memory.sh" "$here/remote/launch.sh" "$compare/aws/compare.sh")
[ -z "$sourced" ] && pass "no script sources generator.env" || fail "generator.env is still sourced: $sourced"

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
