#!/usr/bin/env bash
# Writes the SSH key pair the nodes trust to the shared `keys` volume, once
# per volume, then idles. Runs start with `docker compose exec control ...`.
set -euo pipefail

if [ ! -s /keys/id_ed25519 ]; then
  rm -f /keys/id_ed25519 /keys/id_ed25519.pub
  ssh-keygen -q -t ed25519 -N "" -C jepsen-control -f /keys/id_ed25519
fi
exec sleep infinity
