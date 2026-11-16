#!/usr/bin/env bash
# Watch the Imatra broker until one full charging session has gone through
# (registry, connect, plug-in, TLS session, cache pair, end) and check every
# message against the contracts. Exit 1 if not.
set -euo pipefail
cd "$(dirname "$0")/.."
IMATRA_DIR=${IMATRA_DIR:-$PWD/../imatra.iso15118_server}
MQTT_SERVER_PASSWORD=$(grep '^MQTT_SERVER_PASSWORD=' "$IMATRA_DIR/.env" | cut -d= -f2-) \
  docker compose -f compose/harness.yml --profile e2e run --rm watch
