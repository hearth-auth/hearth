#!/usr/bin/env bash
# The product servers' sampler.sh (#913): samples one docker compose project
# (the product and its postgres) and the machine once a second, as CSV, until
# killed, in loadtest/live/sampler.sh's columns, so analyze.py and ramps.py
# read it unchanged. compare.sh installs it as /opt/hearth/sampler.sh on a
# product server, where remote/observe.sh starts it.
#
# Usage: compose-sampler.sh <out.csv> [disk-device] [project]
#   disk-device  whole-disk name in /proc/diskstats (default: the disk that
#                holds /var/lib/docker; "" for the default)
#   project      compose project (default: COMPOSE_PROJECT from
#                /opt/compare/product.env)
#
# The process columns add up every container of the project, from its cgroup
# (cgroup v2, docker's systemd driver):
#   alive        1 while as many containers run as at the first sample
#   pid          the number of running containers
#   cpu_ticks    cpu.stat usage_usec, in clock ticks of clk_tck
#   rss_kb       memory.stat anon + file_mapped (comparable to a process's
#                VmRSS: private memory plus mapped file pages; not the page
#                cache that memory.current also counts)
#   threads      pids.current (tasks)
#   fds          "" (not sampled)
#   rss_anon_kb, rss_file_kb  anon and file_mapped
set -euo pipefail

out=${1:?usage: compose-sampler.sh <out.csv> [disk-device] [project]}
dev=${2:-}
project=${3:-}
if [ -z "$project" ]; then
  project=$(sed -n 's/^COMPOSE_PROJECT=//p' /opt/compare/product.env 2> /dev/null || true)
fi
[ -n "$project" ] || { echo "compose-sampler: no compose project" >&2; exit 1; }
if [ -z "$dev" ]; then
  src=$(findmnt -no SOURCE --target /var/lib/docker 2> /dev/null || findmnt -no SOURCE /)
  dev=$(lsblk -no PKNAME "$src" 2> /dev/null | head -n 1 || true)
  [ -n "$dev" ] || dev=$(basename "$src")
fi
clk=$(getconf CLK_TCK)

# The cgroup directories of the project's running containers.
cgroups() {
  local id
  for id in $(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$project"); do
    for d in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
      [ -d "$d" ] && { echo "$d"; break; }
    done
  done
}

echo "ts,alive,pid,cpu_ticks,clk_tck,rss_kb,threads,fds,mem_available_kb,disk_writes,disk_write_sectors,load1,rss_anon_kb,rss_file_kb" > "$out"
want="" dirs="" n=0
while true; do
  ts=$(date +%s.%N)
  # docker ps once every 10 samples: a restart gives containers new cgroups.
  if [ $((n % 10)) = 0 ]; then dirs=$(cgroups); fi
  n=$((n + 1))
  count=0 usec=0 anon=0 mapped=0 tasks=0
  for d in $dirs; do
    [ -r "$d/cpu.stat" ] || continue
    count=$((count + 1))
    usec=$((usec + $(awk '$1 == "usage_usec" {print $2}' "$d/cpu.stat")))
    read -r a m < <(awk '$1 == "anon" {a = $2} $1 == "file_mapped" {m = $2} END {print a + 0, m + 0}' "$d/memory.stat")
    anon=$((anon + a / 1024))
    mapped=$((mapped + m / 1024))
    tasks=$((tasks + $(cat "$d/pids.current" 2> /dev/null || echo 0)))
  done
  [ -n "$want" ] || want=$count
  alive=0
  [ "$count" -gt 0 ] && [ "$count" -ge "$want" ] && alive=1
  mem=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  read -r writes sectors < <(awk -v d="$dev" '$3 == d {print $8, $10}' /proc/diskstats) || true
  load=$(cut -d' ' -f1 /proc/loadavg)
  if [ "$count" -gt 0 ]; then
    echo "$ts,$alive,$count,$((usec * clk / 1000000)),$clk,$((anon + mapped)),$tasks,,$mem,${writes:-0},${sectors:-0},$load,$anon,$mapped" >> "$out"
  else
    echo "$ts,0,,,$clk,,,,$mem,${writes:-0},${sectors:-0},$load,," >> "$out"
  fi
  sleep 1
done
