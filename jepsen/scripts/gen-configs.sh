#!/usr/bin/env bash
# Writes one upload-ready bundle per node from the material gen-material.sh
# made (task 1.3). The Jepsen `db` setup copies <material>/nodes/<node>/ to
# $HEARTH_ROOT on that node:
#
#   hearth.yaml          production-mode cluster config for the node
#   seed.yaml            single-node config that seeds the shared store
#                        (decision 5); only in the first node's bundle
#   master_key           HEARTH_MASTER_KEY for `hearth serve` (0600)
#   tls/ca.crt           CA for peer mTLS and HTTPS
#   tls/peer.{crt,key}   peer mTLS leaf, SAN DNS:<node> (and the node's IP)
#   tls/https.{crt,key}  HTTPS leaf, SAN DNS:<node> (and the node's IP)
#
# Every node listens on the same ports: HTTPS on 8443 (the HTTP->HTTPS
# redirect on 8442) and peer gRPC on 7443. Clients reach a node by its name,
# so its name is in security.allowed_hosts. Peers reach it by its IP address,
# <prefix>.<10+id>: hearth's peer server binds cluster.peer_address, which must
# be an IP address, and gen-material.sh puts the IP in each leaf.
#
# Usage: gen-configs.sh <material-dir> <node>...
# Env:   HEARTH_ROOT     install directory on the nodes (default /opt/hearth)
#        ISSUER          oidc.issuer (default https://hearth.jepsen.test)
#        NODE_IP_PREFIX  first three octets of the node addresses (default 10.77.0)
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <material-dir> <node>..." >&2
  exit 2
fi
material=$1
shift
nodes=("$@")
root=${HEARTH_ROOT:-/opt/hearth}
issuer=${ISSUER:-https://hearth.jepsen.test}
https_port=8443
peer_port=7443
ip_prefix=${NODE_IP_PREFIX:-10.77.0}
peer_addr() { echo "$ip_prefix.$((10 + ${1#n})):$peer_port"; }

kek=$(cat "$material/kek")
issuer_host=${issuer#https://}
issuer_host=${issuer_host%%/*}
allowed_hosts="\"$issuer_host\""
for node in "${nodes[@]}"; do
  allowed_hosts+=", \"$node\""
done

# The part every config shares. $1 is the node, $2 the data directory.
common() {
  cat << EOF
oidc:
  issuer: "$issuer"
server:
  bind_address: "0.0.0.0"
  port: $https_port
  tls_cert_path: "$root/tls/https.crt"
  tls_key_path: "$root/tls/https.key"
security:
  key_encryption_key: "$kek"
  # Clients reach each node by its own name, not the issuer's host.
  allowed_hosts: [$allowed_hosts]
storage:
  data_dir: "$2"
email:
  transport: log
  allow_log_transport_in_production: true
onboarding:
  base_url: "https://$1:$https_port"
realms:
  # W4 redeems a refresh token through the password flow (design.md, Open
  # Question 3), so this realm does not require MFA.
  jepsen:
    auth:
      mfa_required: false
EOF
}

umask 077
for node in "${nodes[@]}"; do
  if ! [[ $node =~ ^n[0-9]+$ ]]; then
    echo "$0: node names must be n<id>, got '$node'" >&2
    exit 2
  fi
  bundle=$material/nodes/$node
  mkdir -p "$bundle/tls"
  cp "$material/ca.crt" "$bundle/tls/ca.crt"
  for leaf in peer https; do
    cp "$material/$node-$leaf.crt" "$bundle/tls/$leaf.crt"
    cp "$material/$node-$leaf.key" "$bundle/tls/$leaf.key"
  done
  cp "$material/master_key" "$bundle/master_key"
  chmod 0644 "$bundle"/tls/*.crt

  {
    common "$node" "$root/data"
    echo "cluster:"
    echo "  node_id: ${node#n}"
    echo "  peer_address: \"$(peer_addr "$node")\""
    echo "  peers:"
    for peer in "${nodes[@]}"; do
      [ "$peer" = "$node" ] && continue
      echo "    - id: ${peer#n}"
      echo "      address: \"$(peer_addr "$peer")\""
    done
    echo "  tls_cert_path: \"$root/tls/peer.crt\""
    echo "  tls_key_path: \"$root/tls/peer.key\""
    echo "  tls_ca_cert_path: \"$root/tls/ca.crt\""
  } > "$bundle/hearth.yaml"
done

common "${nodes[0]}" "$root/seed" > "$material/nodes/${nodes[0]}/seed.yaml"
