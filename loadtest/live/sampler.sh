#!/usr/bin/env bash
# Samples the Hearth process and the machine once a second, as CSV, until
# killed. Runs on the server, next to Hearth, so it reads /proc directly.
#
# Usage: sampler.sh <out.csv> [disk-device] [process]
#   disk-device  whole-disk name in /proc/diskstats (default: the disk that
#                holds /var/lib/hearth, e.g. vda; "" for the default)
#   process      process name to follow (default: hearth; k6 on the generator)
#
# Columns:
#   ts                wall clock, seconds (fractional)
#   alive             1 while the followed process exists, else 0
#   pid               its pid ("" when none)
#   cpu_ticks         its utime + stime, in clock ticks (cumulative)
#   clk_tck           ticks per second
#   rss_kb            its VmRSS
#   threads           its thread count
#   fds               its open file descriptors
#   mem_available_kb  MemAvailable of the machine
#   disk_writes       completed writes on the disk (cumulative)
#   disk_write_sectors sectors written (cumulative)
#   load1             1-minute load average
set -euo pipefail

out=${1:?usage: sampler.sh <out.csv> [disk-device] [process]}
dev=${2:-}
proc=${3:-hearth}
if [ -z "$dev" ]; then
  src=$(findmnt -no SOURCE --target /var/lib/hearth 2> /dev/null || findmnt -no SOURCE /)
  dev=$(lsblk -no PKNAME "$src" 2> /dev/null | head -n 1)
  [ -n "$dev" ] || dev=$(basename "$src")
fi
clk=$(getconf CLK_TCK)

echo "ts,alive,pid,cpu_ticks,clk_tck,rss_kb,threads,fds,mem_available_kb,disk_writes,disk_write_sectors,load1" > "$out"
while true; do
  ts=$(date +%s.%N)
  pid=$(pgrep -o -x "$proc" || true)
  alive=0 ticks="" rss="" threads="" fds=""
  if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
    # Fields 14 and 15 of /proc/<pid>/stat, counted after the ") " that ends
    # the command name (which may contain spaces).
    stat=$(cat "/proc/$pid/stat" 2> /dev/null || true)
    if [ -n "$stat" ]; then
      alive=1
      rest=${stat##*) }
      read -r -a f <<< "$rest"
      ticks=$((f[11] + f[12]))
      rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2> /dev/null || true)
      threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status" 2> /dev/null || true)
      fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)
    fi
  fi
  mem=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  read -r writes sectors < <(awk -v d="$dev" '$3 == d {print $8, $10}' /proc/diskstats)
  load=$(cut -d' ' -f1 /proc/loadavg)
  echo "$ts,$alive,$pid,$ticks,$clk,$rss,$threads,$fds,$mem,${writes:-0},${sectors:-0},$load" >> "$out"
  sleep 1
done
