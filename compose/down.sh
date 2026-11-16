#!/usr/bin/env bash
# Stop the harness and its Imatra deployment. --volumes also removes every
# generated trust root, key and registry entry.
set -euo pipefail
cd "$(dirname "$0")/.."
IMATRA_DIR=${IMATRA_DIR:-$PWD/../imatra.iso15118_server}
docker compose -f compose/harness.yml --profile e2e down "$@" || true
docker compose -p imatra-harness-server -f "$IMATRA_DIR/docker-compose.yml" -f "$PWD/compose/imatra.override.yml" \
  --project-directory "$IMATRA_DIR" down "$@" || true
