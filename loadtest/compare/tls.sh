#!/usr/bin/env bash
# A CA and an HTTPS leaf for one product of the comparison (#913), the same
# kind as gen-config.sh makes for Hearth (ECDSA P-256, 7 days), so every
# product pays the same TLS cost. The key usages make strict verifiers (Python
# 3.13+) accept the chain.
#
# Usage: tls.sh <dir> <host>
#   <dir>/ca.crt, <dir>/ca.key    the CA (the generator trusts ca.crt)
#   <dir>/tls/https.crt, .key     the leaf, SAN DNS:<host> and IP:127.0.0.1
set -euo pipefail

dir=${1:?usage: tls.sh <dir> <host>}
host=${2:?usage: tls.sh <dir> <host>}
[ ! -e "$dir/ca.crt" ] || {
  echo "tls: $dir/ca.crt exists; refusing to overwrite" >&2
  exit 2
}
umask 077
mkdir -p "$dir/tls"
openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -days 7 -subj "/CN=compare-ca" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$dir/ca.key" -out "$dir/ca.crt" 2> /dev/null
openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -subj "/CN=$host" \
  -keyout "$dir/tls/https.key" -out "$dir/tls/https.csr" 2> /dev/null
openssl x509 -req -days 7 -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
  -extfile <(printf 'subjectAltName=DNS:%s,IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$host") \
  -in "$dir/tls/https.csr" -out "$dir/tls/https.crt" 2> /dev/null
rm -f "$dir/tls/https.csr" "$dir/ca.srl"
