#!/usr/bin/env bash
# scripts/check-compose-env-scope.sh — a shipped compose file must not source
# an environment file it does not define the scope of.
#
# Audit 2026-08-28 finding §4.8#17 (LOW):
#
#   deploy/docker-compose.yml carried
#
#       env_file:
#         - path: ../.env
#           required: false
#
#   `../.env` is the repository root `.env` — a gitignored, developer-local
#   file with no defined schema anywhere in this repo. Compose injects EVERY
#   key in it into the hearth container's runtime environment. Two consequences,
#   both silent:
#
#     1. Any unrelated credential a developer keeps there (a cloud key, a
#        registry token, a personal API key) is handed to the server process and
#        is readable by anyone who can run `docker inspect`.
#     2. Hearth reads `HEARTH_*` environment variables as configuration. A stray
#        key in that file silently overrides the bind-mounted hearth.yaml, so the
#        server does not run the configuration the operator is reading.
#
#   A shipped compose file must name an environment file whose scope this repo
#   defines, and that file must live beside the compose file it belongs to.
#
# Three rules, applied to every tracked compose file:
#
#   R1  No `env_file` path escapes the compose file's own directory. A `..`
#       segment reaches files this repo does not own.
#   R2  No `env_file` path has the basename `.env`. Compose already auto-loads
#       a project-root `.env` for VARIABLE SUBSTITUTION in the compose file
#       itself; naming it again under `env_file` is the different and much
#       broader act of injecting it into a container. Keeping the names distinct
#       keeps the two effects distinguishable.
#   R3  A committed `<path>.example` exists for every `env_file` path, and every
#       key it declares is one Hearth actually reads. That file IS the schema —
#       without it "scope" is only a claim.
#
# Usage:  bash scripts/check-compose-env-scope.sh
# Env:    COMPOSE_GLOB_DIR   directory to search (default: repo root)

set -uo pipefail

ROOT="${COMPOSE_GLOB_DIR:-.}"

# Keys a Hearth container legitimately reads. Anything else in a shipped
# env example is out of scope for this service and must not be there.
ALLOWED_KEY_RE='^(HEARTH_[A-Z0-9_]+|RUST_LOG|RUST_BACKTRACE|OTEL_[A-Z0-9_]+)$'

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

mapfile -t COMPOSE_FILES < <(
    find "$ROOT" \
        -path '*/node_modules' -prune -o \
        -path '*/target' -prune -o \
        -path '*/.git' -prune -o \
        -path '*/.claude' -prune -o \
        -type f \( -name 'docker-compose*.yml'  -o -name 'docker-compose*.yaml' \
                -o -name 'compose.yml'          -o -name 'compose.yaml' \) -print
)

if [[ "${#COMPOSE_FILES[@]}" -eq 0 ]]; then
    echo "FAIL: no compose file found under ${ROOT}; this guard has nothing to check."
    exit 1
fi

# extract_env_paths <compose-file> — print one env_file path per line.
# Handles both compose forms: a bare `- ./file` list item, and the long form
# `- path: ./file` with sibling keys such as `required:`.
extract_env_paths() {
    awk '
        /^[[:space:]]*env_file:[[:space:]]*$/ { in_env = 1; next }
        # A key at the same or lower indentation ends the block.
        in_env && /^[[:space:]]*[A-Za-z_][A-Za-z0-9_-]*:/ && !/^[[:space:]]*-/ &&
            !/^[[:space:]]*(path|required|format):/ { in_env = 0 }
        in_env && /^[[:space:]]*-[[:space:]]*path:[[:space:]]*/ {
            p = $0; sub(/^[[:space:]]*-[[:space:]]*path:[[:space:]]*/, "", p)
            gsub(/["'"'"']/, "", p); print p; next
        }
        in_env && /^[[:space:]]*-[[:space:]]*[^[:space:]]/ &&
            !/^[[:space:]]*-[[:space:]]*(required|format):/ {
            p = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", p)
            gsub(/["'"'"']/, "", p); print p; next
        }
        # An inline single-value form: env_file: ./file
        /^[[:space:]]*env_file:[[:space:]]*[^[:space:]]/ {
            p = $0; sub(/^[[:space:]]*env_file:[[:space:]]*/, "", p)
            gsub(/["'"'"']/, "", p); print p
        }
    ' "$1"
}

for cf in "${COMPOSE_FILES[@]}"; do
    rel="${cf#./}"
    dir="$(dirname "$cf")"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue

        # ── R1: no escape from the compose file's own directory. ─────────────
        if [[ "$p" == *".."* ]]; then
            fail "${rel}: env_file '${p}' reaches outside $(dirname "$rel")/." \
                $'\n      Compose injects every key in that file into the container. This repo' \
                $'\n      does not define the schema of a file it does not own (§4.8#17).'
            continue
        fi

        # ── R2: not the project-root catch-all. ──────────────────────────────
        if [[ "$(basename "$p")" == ".env" ]]; then
            fail "${rel}: env_file '${p}' is a bare .env." \
                $'\n      Compose already auto-loads a project .env for variable substitution.' \
                $'\n      Listing it under env_file additionally injects every key into the' \
                $'\n      container runtime — a different and much broader effect (§4.8#17).'
            continue
        fi

        # ── R3: a committed example defines the scope. ───────────────────────
        example="${dir}/${p}.example"
        if [[ ! -f "$example" ]]; then
            fail "${rel}: env_file '${p}' has no committed '${p}.example'." \
                $'\n      Without one, nothing states which keys belong in it (§4.8#17).'
            continue
        fi
        while IFS= read -r key; do
            [[ -n "$key" ]] || continue
            if [[ ! "$key" =~ $ALLOWED_KEY_RE ]]; then
                fail "${example}: declares '${key}', which Hearth does not read." \
                    $'\n      A shipped env example must stay inside this service\'s own scope.'
            fi
        done < <(grep -vE '^[[:space:]]*(#|$)' "$example" | sed 's/=.*//' | tr -d ' \t')
    done < <(extract_env_paths "$cf")
done

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} compose env-scope violation(s)."
    echo "See scripts/check-compose-env-scope.sh for the rules and the audit citation."
    exit 1
fi
echo "OK: every shipped compose file sources only an env file this repo defines."
exit 0
