#!/usr/bin/env bash
# Start an Imatra deployment (PKI_MODE=layer) and the whole harness next to it:
# test layer, test station, test EV. Nothing outside this machine is used.
#   compose/up.sh                  IMATRA_DIR: Imatra checkout (default ../imatra.iso15118_server,
#                                  cloned at contracts/IMATRA_REF if missing)
#                                  IMATRA_REF=local: use the checkout as it is (no fetch)
#                                  NO_STATION=1: layer and Imatra only (Imatra's load test)
#   compose/e2e.sh                 watch one session end to end
#   compose/down.sh [--volumes]
set -euo pipefail
cd "$(dirname "$0")/.."
H="docker compose -f compose/harness.yml"
IMATRA_DIR=${IMATRA_DIR:-$PWD/../imatra.iso15118_server}
REF=${IMATRA_REF:-$(cat contracts/IMATRA_REF)}

if [ ! -d "$IMATRA_DIR/.git" ]; then
  git clone -q https://github.com/Chargetronic/imatra.iso15118_server "$IMATRA_DIR"
fi
if [ "$REF" != local ]; then
  git -C "$IMATRA_DIR" fetch -q --depth 1 origin "$REF" && git -C "$IMATRA_DIR" checkout -q FETCH_HEAD
fi
echo "Imatra at $(git -C "$IMATRA_DIR" rev-parse --short HEAD)"

# 1. the link network (harness ↔ Imatra broker), the test layer's trust roots and broker
docker network inspect imatra-harness-link >/dev/null 2>&1 || docker network create imatra-harness-link >/dev/null
$H up -d --build layer-mqtt

# 2. the files the deployment imports from the layer
tmp=$(mktemp -d)
$H run --rm --no-deps -T layer-init sh -c 'tar -C /data/pki/deployments/test-deployment/for-imatra -cf - .' | tar -x -C "$tmp"

# 3. the Imatra deployment: local settings, fresh secrets, PKI from the test layer
I="docker compose -p imatra-harness-server -f $IMATRA_DIR/docker-compose.yml -f $PWD/compose/imatra.override.yml --project-directory $IMATRA_DIR"
if [ ! -f "$IMATRA_DIR/.env" ]; then
  r() { openssl rand -hex "$1"; }
  sed -e "s|^SITE_ADDRESS=.*|SITE_ADDRESS=localhost|" \
      -e "s|^PUBLIC_PORT=.*|PUBLIC_PORT=${PUBLIC_PORT:-18101}|" \
      -e "s|^PUBLIC_TCP_PORT=.*|PUBLIC_TCP_PORT=${PUBLIC_TCP_PORT:-18883}|" \
      -e "s|^BROKER_DNS=.*|BROKER_DNS=mqtt|" \
      -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(r 16)|" \
      -e "s|^PKI_MODE=.*|PKI_MODE=layer|" \
      -e "s|^MQTT_SERVER_PASSWORD=.*|MQTT_SERVER_PASSWORD=$(r 16)|" \
      -e "s|^OPERATOR_API_KEYS=.*|OPERATOR_API_KEYS=\"admin:$(r 24)\"|" \
      "$IMATRA_DIR/.env.example" > "$IMATRA_DIR/.env"
  echo "Imatra settings written to $IMATRA_DIR/.env"
fi
$I build -q
$I run --rm -T -v "$tmp:/in:ro" pki-init import
rm -rf "$tmp"
$I up -d

# 4. the layer service, one test station bound to the deployment
$H up -d --build layer
if [ -n "${NO_STATION:-}" ]; then
  echo "layer and Imatra running (no station)"; exit 0
fi
$H run --rm --no-deps -T layer sh -c '[ -f /boot/dev-01.json ] || layer provision dev-01 > /boot/dev-01.json'
$H run --rm --no-deps -T layer layer bind dev-01 || true
$H run --rm --no-deps -T layer layer type dev-01 station
$H run --rm --no-deps -T layer layer rules dev-01 '{"topology":"integrated"}'

# 5. station and EV
$H up -d --build station ev
echo "harness running: $H ps; logs: $H logs -f station ev"
