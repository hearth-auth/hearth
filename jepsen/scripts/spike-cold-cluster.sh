#!/usr/bin/env bash
# Spike for task 0.2: a cold, production-mode cluster gets its first operator
# token with no `--dev`, no `dev-endpoints` and no test-only path.
#
# Starts 3 nodes on this host, seeded from one store (seed-store.sh), and
# succeeds when GET /admin/cluster/status answers 200 to the seeded
# system-realm token on every node.
#
# Usage: spike-cold-cluster.sh <hearth-binary> [work-dir]
# The binary MUST be built without the dev-endpoints feature.
set -euo pipefail

HEARTH=$(realpath "$1")
WORK=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")" && pwd)
nodes=(n1 n2 n3)
SYSTEM_REALM=00000000-0000-0000-0000-000000000000

log() { printf 'spike: %s\n' "$*" >&2; }

# 10 apart: each node also binds an HTTP->HTTPS redirect listener on its HTTPS
# port minus 1.
https_port() { echo $((28400 + 10 * ${1#n})); }
peer_port() { echo $((28600 + 10 * ${1#n})); }

mkdir -p "$WORK"
log "work directory: $WORK"
EXTRA_SAN=DNS:localhost,IP:127.0.0.1 "$here/gen-material.sh" "$WORK/material" "${nodes[@]}"
export HEARTH_MASTER_KEY
HEARTH_MASTER_KEY=$(cat "$WORK/material/master_key")
kek=$(cat "$WORK/material/kek")

# One hearth.yaml. $2 is the data directory; with $3 = cluster, it carries
# the cluster section.
write_config() {
  local node=$1 data_dir=$2 mode=${3:-}
  local file=$WORK/$node${mode:+-$mode}.yaml
  cat > "$file" << EOF
oidc:
  issuer: "https://hearth.jepsen.test"
server:
  bind_address: "127.0.0.1"
  port: $(https_port "$node")
  tls_cert_path: "$WORK/material/$node-https.crt"
  tls_key_path: "$WORK/material/$node-https.key"
security:
  key_encryption_key: "$kek"
  # Clients reach each node by its own name, not the issuer's host.
  allowed_hosts: ["hearth.jepsen.test", "localhost"]
storage:
  data_dir: "$data_dir"
email:
  transport: log
  allow_log_transport_in_production: true
onboarding:
  base_url: "https://localhost:$(https_port "$node")"
realms:
  jepsen: {}
EOF
  if [ "$mode" = cluster ]; then
    {
      echo "cluster:"
      echo "  node_id: ${node#n}"
      echo "  peer_address: \"127.0.0.1:$(peer_port "$node")\""
      echo "  peers:"
      for peer in "${nodes[@]}"; do
        [ "$peer" = "$node" ] && continue
        echo "    - id: ${peer#n}"
        echo "      address: \"localhost:$(peer_port "$peer")\""
      done
      echo "  tls_cert_path: \"$WORK/material/$node-peer.crt\""
      echo "  tls_key_path: \"$WORK/material/$node-peer.key\""
      echo "  tls_ca_cert_path: \"$WORK/material/ca.crt\""
    } >> "$file"
  fi
  echo "$file"
}

seed_config=$(write_config n1 "$WORK/seed")
for node in "${nodes[@]}"; do
  cfg=$(write_config "$node" "$WORK/$node-data" cluster)
  "$HEARTH" config validate "$cfg" > "$WORK/$node-validate.log" 2>&1 ||
    {
      cat "$WORK/$node-validate.log" >&2
      exit 1
    }
done
log "config validate: OK on ${#nodes[@]} nodes"

token=$(HEARTH=$HEARTH SEED_CONFIG=$seed_config SEED_DATA_DIR=$WORK/seed \
  SEED_URL="https://localhost:$(https_port n1)" SEED_CA=$WORK/material/ca.crt \
  OPERATOR_EMAIL=operator@jepsen.test OPERATOR_PASSWORD='jepsen-operator-pw-1' \
  "$here/seed-store.sh")
(umask 077 && printf '%s\n' "$token" > "$WORK/token")
log "seeded store holds an operator token (${#token} bytes, copy in $WORK/token)"

pids=()
stop_nodes() {
  for pid in "${pids[@]}"; do kill "$pid" 2> /dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2> /dev/null || true; done
}
trap stop_nodes EXIT

for node in "${nodes[@]}"; do
  mkdir "$WORK/$node-data"
  cp -a "$WORK/seed/." "$WORK/$node-data/"
  "$HEARTH" serve --config "$WORK/$node-cluster.yaml" > "$WORK/$node.log" 2>&1 &
  pids+=($!)
done
log "started ${#nodes[@]} cluster nodes"

ok=0
for node in "${nodes[@]}"; do
  url="https://localhost:$(https_port "$node")/admin/cluster/status"
  for _ in $(seq 1 300); do
    status=$(curl --silent --cacert "$WORK/material/ca.crt" -o "$WORK/$node-status.json" \
      -w '%{http_code}' -H "Authorization: Bearer $token" -H "X-Realm-ID: $SYSTEM_REALM" \
      "$url" || true)
    [ "$status" = 200 ] && break
    sleep 0.5
  done
  log "$node: GET /admin/cluster/status -> $status $(cat "$WORK/$node-status.json" 2> /dev/null)"
  [ "$status" = 200 ] && ok=$((ok + 1))
done

if [ "$ok" -ne "${#nodes[@]}" ]; then
  log "FAILED: $ok of ${#nodes[@]} nodes answered 200; logs in $WORK"
  exit 1
fi
log "PASS: every node answered 200 to the seeded system-realm token"
