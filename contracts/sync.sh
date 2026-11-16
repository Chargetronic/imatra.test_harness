#!/usr/bin/env bash
# Copy the contracts of an Imatra commit or tag into contracts/.
#   contracts/sync.sh REF [REPO_URL]
# REPO_URL defaults to the Imatra repository on GitHub.
set -euo pipefail
ref=${1:?usage: contracts/sync.sh REF [REPO_URL]}
url=${2:-https://github.com/Chargetronic/imatra.iso15118_server}
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" fetch -q --depth 1 "$url" "$ref"
for f in asyncapi-device.yaml asyncapi-registry.yaml asyncapi-layer.yaml; do
  git -C "$tmp" show "FETCH_HEAD:spec/$f" > "$here/$f"
done
git -C "$tmp" rev-parse FETCH_HEAD > "$here/IMATRA_REF"
echo "contracts from $(cat "$here/IMATRA_REF")"
