#!/usr/bin/env bash
# Records glibc's malloc_info of the running Hearth process (through gdb, which
# stops the process for a fraction of a second), with RSS and MemAvailable.
#
# Usage: malloc-info.sh <name>   writes /opt/hearth/out/<name>.malloc_info.xml
#                                and /opt/hearth/out/<name>.malloc-state.txt
set -uo pipefail

name=${1:?usage: malloc-info.sh <name>}
out=/opt/hearth/out
pid=$(pgrep -o -x hearth) || { echo "no hearth process" > "$out/$name.malloc-state.txt"; exit 1; }
xml=/tmp/hearth-malloc-info-$name.xml
rm -f "$xml"
{
  date -u +%FT%TZ
  grep -E '^(VmRSS|RssAnon|RssFile|RssShmem)' "/proc/$pid/status"
  grep -E '^(MemAvailable|AnonPages|AnonHugePages):' /proc/meminfo
  t0=$(date +%s%N)
  timeout 60 gdb -p "$pid" -batch -nx \
    -ex 'set debuginfod enabled off' \
    -ex "set \$f = (void *) fopen(\"$xml\", \"w\")" \
    -ex 'call (int) malloc_info(0, $f)' \
    -ex 'call (int) fclose($f)' 2>&1 | grep -v -E '^\[(New|Thread)|^[0-9]+\s' | tail -n 5
  echo "gdb ms: $((($(date +%s%N) - t0) / 1000000))"
} > "$out/$name.malloc-state.txt" 2>&1
cp "$xml" "$out/$name.malloc_info.xml" 2>> "$out/$name.malloc-state.txt"
