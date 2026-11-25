# Reads an env file (generator.env, a job's params.env) as data, never as
# shell code. Sourced by launch.sh, by cloud.sh's commands on a generator
# (/opt/stress/env.sh) and by steady-memory.sh; test_env.sh tests it.
#
#   load_env <file>  exports each KEY=VALUE line of <file>, the value exactly
#                    as written: `$`, quotes, backticks and spaces stay. Ory's
#                    and Zitadel's bulk-password hash is a `$argon2id$v=19$...`
#                    PHC string (#913), which `set -a; . <file>` under set -u
#                    stopped at ("argon2id: unbound variable"). Blank lines and
#                    # comments are skipped; any other line that is not
#                    KEY=VALUE fails the load, which names its number, never
#                    its content
#   redact <file>    copies stdin to stdout without each line that may hold a
#                    secret: one with the value of a <file> key whose name has
#                    PASSWORD, SECRET, TOKEN, HASH or KEY in it, or with one of
#                    the words password, secret, token or hash (any case).
#                    Without a readable <file> it leaves out every line
#
# Every writer (gen-config.sh, the product scripts, realm.py, instance.py)
# writes values unquoted, as the other readers take them literally: docker's
# --env-file (compare/k6.sh), the realm scripts' read_env and
# `sed -n 's/^KEY=//p'`. Quoting a value would break those readers.

load_env() {
  local line key n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case $line in '' | '#'*) continue ;; esac
    key=${line%%=*}
    case $line in *=*) ;; *) key= ;; esac
    case $key in
      '' | [0-9]* | *[!A-Za-z0-9_]*)
        printf 'load_env: %s: line %d is not KEY=VALUE\n' "$1" "$n" >&2
        return 1
        ;;
    esac
    export "$line" || return 1
  done < "$1"
}

redact() {
  awk -v env="$1" '
    BEGIN {
      while ((r = (getline l < env)) > 0) {
        i = index(l, "=")
        if (i > 1 && i < length(l) && toupper(substr(l, 1, i - 1)) ~ /PASSWORD|SECRET|TOKEN|HASH|KEY/)
          secret[substr(l, i + 1)] = 1
      }
      if (r < 0) {
        print "redact: cannot read " env ": every line left out"
        none = 1
      }
    }
    none || tolower($0) ~ /password|secret|token|hash/ { next }
    {
      for (s in secret) if (index($0, s)) next
      print
    }'
}
