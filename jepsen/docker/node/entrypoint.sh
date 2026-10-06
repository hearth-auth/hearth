#!/usr/bin/env bash
# Trusts the control node's public key, then runs sshd in the foreground.
# The control container writes the key to the shared `keys` volume; Compose
# starts the nodes only after it is there.
set -euo pipefail

key=/keys/id_ed25519.pub
for _ in $(seq 1 60); do
  [ -s "$key" ] && break
  sleep 1
done
if [ ! -s "$key" ]; then
  echo "node-entrypoint: no control key at $key after 60 s" >&2
  exit 1
fi
install -m 0600 "$key" /root/.ssh/authorized_keys

# A fresh host key per container: none is baked into the image.
ssh-keygen -A > /dev/null
exec /usr/sbin/sshd -D -e
