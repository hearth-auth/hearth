#!/usr/bin/env bash
# The server side of compare.sh (#913): runs on a seed or ramp server as root,
# from /opt/compare/remote.sh. Every step that touches the data volume, Docker
# or a product is here, so compare.sh sends one short command per step.
#
# Usage: remote.sh <command> [args]
#   data-new <volume id>        format the data volume (the second EBS volume,
#                               found by its serial) and mount it at /data
#   data-pristine <volume id>   mount the data volume, made from a seed's
#                               snapshot, read-only at /pristine, then read the
#                               whole device once (a volume made from a
#                               snapshot loads its blocks from S3 lazily);
#                               prints the read time
#   bind-docker-volumes         keep Docker's volumes on /data (seed servers;
#                               before Docker is installed)
#   bind-hearth                 keep Hearth's store on /data (seed servers;
#                               before cloud.sh deploy)
#   install-docker              Docker and Compose from Ubuntu 24.04's own
#                               archive (docker.io, docker-compose-v2), and
#                               sysstat (iostat) for observe.sh
#   pull <product>              pull the product's images, PostgreSQL's and
#                               k6's by digest (images.env); prints the time
#   product <product> <cmd>...  the product's own script (<product>.sh up, seed,
#                               settle, restart, down) with the server's bundle
#   restore <product>           stop the server under test, replace its store
#                               with the pristine copy, drop the page cache and
#                               start it again; prints the restore time
#   settle <dir>                wait until no file under <dir> has changed for
#                               60 s; prints the wait
#   idle <product>              the server's idle RSS: 15 s of the sampler, the
#                               last row's rss_kb
#   store-size <product>        bytes of the store on disk
#   freeze <product>            stop the product (and Docker), flush, and
#                               unmount /data, ready for a snapshot
#   scale <factor>              size 2 (#913: "Size 2 scales both by 4"): the
#                               products' container memory limits and this
#                               server's copy of postgres/postgresql.conf
#                               (shared_buffers) times <factor>
#
# Layout: /opt/compare/loadtest/{compare,live/k6} (the repo's), the bundle at
# /data/bundle (seed) or /opt/compare/bundle (ramp, copied from
# /pristine/bundle); the seeded data at /data/{volumes,hearth} and
# /pristine/{volumes,hearth}.
set -euo pipefail

top=/opt/compare
compare=$top/loadtest/compare
log() { printf 'remote: %s\n' "$*" >&2; }
die() {
  log "FAILED: $*"
  exit 1
}

bundle() {
  if mountpoint -q /data && [ -d /data/bundle ]; then echo /data/bundle; else echo "$top/bundle"; fi
}

# The device of EBS volume $1 (its NVMe serial is the id without the dash).
device_of() {
  local serial=${1//-/} name
  for _ in $(seq 1 60); do
    name=$(lsblk -dno NAME,SERIAL | awk -v s="$serial" '$2 == s {print $1}')
    [ -z "$name" ] || { echo "/dev/$name"; return 0; }
    sleep 2
  done
  die "no block device for volume $1"
}

project_of() { echo "compare-$1"; }

# The product's bind variable: its listener must answer the generators.
bind_var() {
  case $1 in
    keycloak) echo KC_BIND ;;
    zitadel) echo ZT_BIND ;;
    ory) echo ORY_BIND ;;
    authentik) echo AK_BIND ;;
    *) die "unknown product $1" ;;
  esac
}

product() {
  local p=$1
  shift
  # The size 2 memory limits (scale), if any.
  set -a
  # shellcheck disable=SC1091
  [ ! -f "$top/scale.env" ] || . "$top/scale.env"
  set +a
  env BUNDLE="$(bundle)" SERVER_IP=127.0.0.1 "$(bind_var "$p")=0.0.0.0" \
    bash "$compare/$p/$p.sh" "$@"
}

drop_caches() {
  sync
  echo 3 > /proc/sys/vm/drop_caches
}

cmd=${1:-}
shift || true
case $cmd in
  data-new)
    dev=$(device_of "${1:?volume id}")
    mkfs.ext4 -q -L data "$dev"
    mkdir -p /data
    mount -o noatime "$dev" /data
    mkdir -p /data/bundle
    chmod 0700 /data/bundle
    ;;
  data-pristine)
    dev=$(device_of "${1:?volume id}")
    t0=$(date +%s)
    dd if="$dev" of=/dev/null bs=4M status=none
    mkdir -p /pristine
    # noload: no journal replay on a read-only mount.
    mount -o ro,noload "$dev" /pristine
    echo "read $(blockdev --getsize64 "$dev") bytes in $(($(date +%s) - t0)) s"
    ;;
  bind-docker-volumes)
    mkdir -p /data/volumes /var/lib/docker/volumes
    mount --bind /data/volumes /var/lib/docker/volumes
    ;;
  bind-hearth)
    mkdir -p /data/hearth /var/lib/hearth
    mount --bind /data/hearth /var/lib/hearth
    ;;
  install-docker)
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update > /dev/null
    apt-get -qq install -y docker.io docker-compose-v2 sysstat > /dev/null
    systemctl enable --now docker > /dev/null 2>&1
    docker version --format 'docker {{.Server.Version}}'
    docker compose version
    ;;
  pull)
    p=${1:?product}
    set -a
    # shellcheck disable=SC1091
    . "$compare/images.env"
    set +a
    case $p in
      keycloak) images=("$KEYCLOAK_IMAGE") ;;
      zitadel) images=("$ZITADEL_IMAGE") ;;
      ory) images=("$HYDRA_IMAGE" "$KRATOS_IMAGE" "$UI_IMAGE") ;;
      authentik) images=("$AUTHENTIK_IMAGE") ;;
      *) die "unknown product $p" ;;
    esac
    images+=("$POSTGRES_IMAGE" "$K6_IMAGE")
    t0=$(date +%s)
    for i in "${images[@]}"; do
      [[ $i == *@sha256:* ]] || die "$i is not pinned by digest"
      docker pull -q "$i" > /dev/null
    done
    echo "pulled ${#images[@]} images in $(($(date +%s) - t0)) s"
    ;;
  product)
    p=${1:?product}
    shift
    product "$p" "$@"
    ;;
  restore)
    p=${1:?product}
    t0=$(date +%s)
    if [ "$p" = hearth ]; then
      systemctl stop hearth
      find /var/lib/hearth -mindepth 1 -delete
      cp -a /pristine/hearth/. /var/lib/hearth/
      chown -R hearth:hearth /var/lib/hearth
      drop_caches
      systemctl reset-failed hearth 2> /dev/null || true
      systemctl start hearth
    else
      docker compose -p "$(project_of "$p")" down --remove-orphans > /dev/null 2>&1 || true
      systemctl stop docker.socket docker
      rm -rf /var/lib/docker/volumes "$top/bundle"
      cp -a /pristine/volumes /var/lib/docker/volumes
      cp -a /pristine/bundle "$top/bundle"
      drop_caches
      systemctl start docker
      product "$p" up >&2
    fi
    echo "restored in $(($(date +%s) - t0)) s"
    ;;
  settle)
    dir=${1:?dir}
    t0=$(date +%s) last="" quiet=0
    while [ "$quiet" -lt 60 ]; do
      now=$(find "$dir" -type f -printf '%p %s %T@\n' 2> /dev/null | sort | md5sum)
      if [ "$now" = "$last" ]; then quiet=$((quiet + 10)); else quiet=0 last=$now; fi
      [ $(($(date +%s) - t0)) -lt "${SETTLE_MAX_S:-7200}" ] || die "$dir still changes after ${SETTLE_MAX_S:-7200} s"
      [ "$quiet" -ge 60 ] || sleep 10
    done
    echo "settled after $(($(date +%s) - t0 - 60)) s"
    ;;
  idle)
    p=${1:?product}
    f=$(mktemp)
    if [ "$p" = hearth ]; then
      timeout 15 /opt/hearth/sampler.sh "$f" || true
    else
      timeout 15 /opt/hearth/sampler.sh "$f" "" "$(project_of "$p")" || true
    fi
    tail -n 1 "$f" | cut -d, -f6
    rm -f "$f"
    ;;
  store-size)
    p=${1:?product}
    if [ "$p" = hearth ]; then du -sb /var/lib/hearth | cut -f1; else du -sb /var/lib/docker/volumes | cut -f1; fi
    ;;
  freeze)
    p=${1:?product}
    if [ "$p" = hearth ]; then
      systemctl stop hearth
      umount /var/lib/hearth
    else
      docker compose -p "$(project_of "$p")" stop > /dev/null
      systemctl stop docker.socket docker
      umount /var/lib/docker/volumes
    fi
    sync
    umount /data
    ;;
  scale)
    f=${1:?factor}
    [[ $f =~ ^[1-9]$ ]] || die "scale factor $f"
    # The size 1 values (each product's compose.yaml default) times f.
    cat > "$top/scale.env" << EOF
KEYCLOAK_MEM_LIMIT=$((2048 * f))m
ZITADEL_MEM_LIMIT=$((2048 * f))m
HYDRA_MEM_LIMIT=$((512 * f))m
KRATOS_MEM_LIMIT=$((1024 * f))m
UI_MEM_LIMIT=$((512 * f))m
SERVER_MEM_LIMIT=$((1280 * f))m
WORKER_MEM_LIMIT=$((768 * f))m
EOF
    conf=$compare/postgres/postgresql.conf
    grep -q '^shared_buffers = 512MB$' "$conf" || die "$conf: shared_buffers is not the size 1 value"
    sed -i "s/^shared_buffers = 512MB$/shared_buffers = $((512 * f))MB/" "$conf"
    cat "$top/scale.env"
    grep '^shared_buffers' "$conf"
    ;;
  *)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2
    exit 2
    ;;
esac
