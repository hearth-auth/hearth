#!/usr/bin/env bash
# Generates the key material for one harness run (design decision 4):
#
#   <out>/kek            security.key_encryption_key, the same on every node
#   <out>/master_key     HEARTH_MASTER_KEY, the same on every node
#   <out>/ca.crt         CA for peer mTLS and HTTPS (ca.key stays next to it)
#   <out>/<node>-peer.{crt,key}    peer mTLS leaf
#   <out>/<node>-https.{crt,key}   HTTPS leaf
#
# Each leaf carries subjectAltName=DNS:<node>; rustls ignores the CN. Set
# EXTRA_SAN to add entries to every leaf, e.g. EXTRA_SAN=DNS:localhost,IP:127.0.0.1
# when the nodes run on one host.
#
# Usage: gen-material.sh <out-dir> <node>...
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <out-dir> <node>..." >&2
  exit 2
fi
out=$1
shift

# A fresh directory per run: material from an earlier run must never mix in.
mkdir "$out"
umask 077

openssl rand -hex 32 > "$out/kek"
openssl rand -hex 32 > "$out/master_key"

# Full X.509 extensions: strict verifiers (Python 3.13+, for one) refuse a CA
# without keyUsage and a leaf without authorityKeyIdentifier.
openssl req -new -x509 -days 30 -nodes -subj "/CN=hearth-jepsen-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -keyout "$out/ca.key" -out "$out/ca.crt" 2> /dev/null

leaf() {
  local name=$1 cn=$2 san=$3
  openssl req -new -nodes -subj "/CN=$cn" \
    -keyout "$out/$name.key" -out "$out/$name.csr" 2> /dev/null
  openssl x509 -req -days 30 \
    -extfile <(printf '%s\n' "subjectAltName=$san" "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth,clientAuth" \
      "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid") \
    -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial \
    -in "$out/$name.csr" -out "$out/$name.crt" 2> /dev/null
  rm "$out/$name.csr"
}

for node in "$@"; do
  san="DNS:$node${EXTRA_SAN:+,$EXTRA_SAN}"
  leaf "$node-peer" "hearth-peer-$node" "$san"
  leaf "$node-https" "hearth-https-$node" "$san"
done

# The certificates are public; only the keys stay 0600.
chmod 0644 "$out"/*.crt
