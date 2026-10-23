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
#   rss_anon_kb       its RssAnon: heap and other private memory, the part a
#                     leak grows
#   rss_file_kb       its RssFile: mapped file pages (the SST files), which the
#                     kernel drops when it needs the memory
set -euo pipefail

out=${1:?usage: sampler.sh <out.csv> [disk-device] [process]}
dev=${2:-}
proc=${3:-hearth}
if [ -z "$dev" ]; then
  src=$(findmnt -no SOURCE --target /var/lib/hearth 2> /dev/null || findmnt -no SOURCE /)
  # lsblk fails on a device it does not know, such as /dev/root on GitHub's runners.
  dev=$(lsblk -no PKNAME "$src" 2> /dev/null | head -n 1 || true)
  [ -n "$dev" ] || dev=$(basename "$src")
fi
clk=$(getconf CLK_TCK)

echo "ts,alive,pid,cpu_ticks,clk_tck,rss_kb,threads,fds,mem_available_kb,disk_writes,disk_write_sectors,load1,rss_anon_kb,rss_file_kb" > "$out"
while true; do
  ts=$(date +%s.%N)
  pid=$(pgrep -o -x "$proc" || true)
  alive=0 ticks="" rss="" threads="" fds="" anon="" file=""
  if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
    # Fields 14 and 15 of /proc/<pid>/stat, counted after the ") " that ends
    # the command name (which may contain spaces).
    stat=$(cat "/proc/$pid/stat" 2> /dev/null || true)
    if [ -n "$stat" ]; then
      alive=1
      rest=${stat##*) }
      read -r -a f <<< "$rest"
      ticks=$((f[11] + f[12]))
      read -r rss threads anon file < <(awk '/^VmRSS:/ {r = $2} /^Threads:/ {t = $2}
        /^RssAnon:/ {a = $2} /^RssFile:/ {f = $2} END {print r, t, a, f}' \
        "/proc/$pid/status" 2> /dev/null || true)
      fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)
    fi
  fi
  mem=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  # No line for a device that /proc/diskstats does not list: the columns are 0.
  read -r writes sectors < <(awk -v d="$dev" '$3 == d {print $8, $10}' /proc/diskstats) || true
  load=$(cut -d' ' -f1 /proc/loadavg)
  echo "$ts,$alive,$pid,$ticks,$clk,$rss,$threads,$fds,$mem,${writes:-0},${sectors:-0},$load,$anon,$file" >> "$out"
  sleep 1
done
