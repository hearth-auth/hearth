#!/usr/bin/env bash
# scripts/heap-check-runner.sh — run a test binary under glibc's heap checking.
#
# A cargo target runner: `make heap-check` sets it as
# CARGO_TARGET_<HOST>_RUNNER, and nextest then starts every test process as
#     heap-check-runner.sh <test-binary> <args...>
#
# Why a runner, not environment variables on the `make` line: the checks must
# reach the test processes and nothing else — cargo, rustc and nextest itself
# run unchecked.
#
# glibc 2.34 moved the malloc debugging hooks into libc_malloc_debug.so. Without
# that library preloaded, MALLOC_CHECK_ is read and ignored: a heap check that
# is silently off. So the runner preloads the copy that sits beside the libc.so.6
# the binary itself links (the one built with it), and refuses to run the test
# if there is none, rather than report a pass that checked nothing.
#
#   MALLOC_CHECK_=3      abort with a diagnostic on a detected heap error
#   MALLOC_PERTURB_=165  fill freed chunks with a byte pattern, so a read after
#                        free sees garbage instead of intact stale data
#
# This is the recipe that separated arc-swap's heap corruption from EpochCell
# (https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/reports/arc-swap-use-after-free-2026-09-21.md). docs/dev/ARCHITECTURE.md §9.2 names the
# tools; unsafe-check/ covers the cell itself under Miri and AddressSanitizer.
set -euo pipefail

bin="${1:?usage: heap-check-runner.sh <test-binary> [args...]}"

# ldd runs to completion before anything parses its output. Piped straight into
# an `awk` that exits at the first match, ldd sometimes took SIGPIPE and
# returned 1, and pipefail + `set -e` ended this script with no message: 4% of
# test processes "failed" with a heap check that never started.
if ! ldd_out="$(ldd "$bin" 2>&1)"; then
    echo "heap-check-runner: \`ldd ${bin}\` failed:" >&2
    echo "$ldd_out" >&2
    exit 1
fi
libc="$(awk '$1 == "libc.so.6" { print $3; exit }' <<<"$ldd_out")"
if [[ -z "$libc" || ! -e "$libc" ]]; then
    echo "heap-check-runner: ${bin} does not link glibc's libc.so.6." >&2
    echo "heap-check-runner: glibc heap checking needs glibc (Linux)." >&2
    exit 1
fi

debug_lib="$(dirname "$libc")/libc_malloc_debug.so.0"
if [[ ! -e "$debug_lib" ]]; then
    echo "heap-check-runner: ${debug_lib} not found." >&2
    echo "heap-check-runner: glibc >= 2.34 ships it beside ${libc};" \
        "without it MALLOC_CHECK_ does nothing." >&2
    exit 1
fi

exec env \
    LD_PRELOAD="${debug_lib}${LD_PRELOAD:+:${LD_PRELOAD}}" \
    MALLOC_CHECK_=3 \
    MALLOC_PERTURB_=165 \
    "$@"
