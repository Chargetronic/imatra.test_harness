#!/usr/bin/env bash
# Scenarios against a running harness (compose/up.sh). Each one drives Imatra
# through its operator API (/v1 through the gateway) and checks the answers;
# meanwhile the watcher checks every message on the Imatra broker against the
# contracts. Exit 1 on the first failed check or on any contract problem.
#   compose/scenarios.sh t2        operator commands during a session: current
#                                  limit, group activation, session summary
#   compose/scenarios.sh t3        the test layer stops during a session and comes
#                                  back: the session, the station's link to
#                                  Imatra, a registry change made meanwhile
# Settings: IMATRA_DIR (Imatra checkout, as for up.sh), API (default
# https://localhost/v1), DEVICE_ID (dev-01), T_WAIT (seconds per wait, 180).
set -euo pipefail
cd "$(dirname "$0")/.."
IMATRA_DIR=${IMATRA_DIR:-$PWD/../imatra.iso15118_server}
API=${API:-https://localhost/v1}
DEV=${DEVICE_ID:-dev-01}
T_WAIT=${T_WAIT:-180}
KEY=$(sed -n 's/^OPERATOR_API_KEYS="\{0,1\}admin:\([^ "]*\).*/\1/p' "$IMATRA_DIR/.env")
[ -n "$KEY" ] || { echo "no admin key in $IMATRA_DIR/.env"; exit 1; }

t0=$(date +%s)
log() { printf '%5ss  %s\n' "$(( $(date +%s) - t0 ))" "$*"; }
fail() { log "FAILED: $*"; exit 1; }
# the gateway runs with a local certificate (SITE_ADDRESS=localhost): -k
api() { curl -sS -k --fail-with-body -H "X-API-Key: $KEY" -H 'Content-Type: application/json' "$@"; }
# wait_for <what> <url> <jq filter that is true when done>
wait_for() {
  local what=$1 url=$2 filter=$3 end=$(( $(date +%s) + T_WAIT )) out
  while [ "$(date +%s)" -lt "$end" ]; do
    out=$(api "$url" 2>/dev/null || true)
    if [ -n "$out" ] && jq -e "$filter" >/dev/null 2>&1 <<<"$out"; then
      log "ok: $what"; LAST=$out; return 0
    fi
    sleep 2
  done
  echo "$out" | jq . 2>/dev/null || echo "$out"
  fail "$what (no result in ${T_WAIT}s)"
}

# The watcher runs through the whole scenario and stops when the scenario
# writes the stop file; its exit code says whether any contract was broken.
WATCH_TMP=$(mktemp -d)
start_watch() {
  MQTT_SERVER_PASSWORD=$(grep '^MQTT_SERVER_PASSWORD=' "$IMATRA_DIR/.env" | cut -d= -f2-) \
  REQUIRE_STEPS=0 WATCH_S=3600 STOP_FILE=/watch-tmp/stop WATCH_TMP=$WATCH_TMP \
    docker compose -f compose/harness.yml --profile e2e run --rm -T watch >"$WATCH_TMP/watch.log" 2>&1 &
  WATCH_PID=$!
  sleep 15   # the watcher installs its packages and subscribes
}
stop_watch() {
  touch "$WATCH_TMP/stop"
  local rc=0
  wait "$WATCH_PID" || rc=$?
  grep -E "PROBLEM|contract problem" "$WATCH_TMP/watch.log" || true
  [ "$rc" -eq 0 ] || fail "contract problems on the broker (watcher exit $rc)"
  log "ok: no contract problems on the broker"
}

t2() {
  log "T2: operator commands during a session ($DEV)"
  start_watch
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  wait_for "device online and in a session" "$API/devices/$DEV" '.online == true and .session != null'
  local max; max=$(jq -r '.station_max_a' <<<"$LAST")
  log "station limit ${max} A, session $(jq -r '.session.session_id' <<<"$LAST")"

  # 1. a direct limit: accepted, applied, confirmed by the device
  local r cid
  r=$(api -X POST "$API/devices/$DEV/limit" -d '{"limit_a": 10, "duration_s": 600}') || fail "POST limit: $r"
  cid=$(jq -r '.command_id' <<<"$r")
  log "limit 10 A sent, command $cid"
  wait_for "limit 10 A confirmed by the device" "$API/devices/$DEV" \
    ".limit.command_id == $cid and .limit.limit_a == 10 and .limit.confirmed_at != null"
  log "confirmed via $(jq -r '.limit.confirmed_via' <<<"$LAST"), reaction $(jq -r '.limit.reaction_ms' <<<"$LAST") ms"

  # 2. limits the server must refuse
  for bad in '{"limit_a": 2, "duration_s": 60}' "{\"limit_a\": $(( ${max%.*} + 1 )), \"duration_s\": 60}" \
             '{"limit_a": 10, "duration_s": 0}'; do
    code=$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST -H "X-API-Key: $KEY" \
      -H 'Content-Type: application/json' "$API/devices/$DEV/limit" -d "$bad")
    [ "$code" = 422 ] || fail "limit $bad: expected 422, got $code"
  done
  log "ok: limits below 6 A, above the station limit, without duration refused (422)"
  code=$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    "$API/devices/$DEV/limit" -d '{"limit_a": 10, "duration_s": 60}')
  [ "$code" = 401 ] || fail "limit without a key: expected 401, got $code"
  log "ok: a command without a key refused (401)"

  # 3. cancel: no limit in force
  api -X DELETE "$API/devices/$DEV/limit" >/dev/null || fail "DELETE limit"
  wait_for "limit cancelled" "$API/devices/$DEV" '.limit == null'

  # 4. a group activation over this device: dispatched and confirmed
  local aid="harness-t2-$(date +%s)"
  r=$(api -X POST "$API/activations" -d "{\"id\": \"$aid\", \"selection\": {\"devices\": [\"$DEV\"]},
       \"level\": {\"current_a\": 8}, \"stages\": [{\"count\": 1}], \"duration_s\": 300}") || fail "POST activation: $r"
  log "activation $aid created"
  wait_for "activation confirmed by the device" "$API/activations/$aid" \
    '.state == "active" and .totals.selected == 1 and .totals.confirmed == 1'
  wait_for "device under the activation's limit" "$API/devices/$DEV" \
    ".limit.activation_id == \"$aid\" and .limit.limit_a == 8"
  # the same id and body again: safe, no second activation
  api -X POST "$API/activations" -d "{\"id\": \"$aid\", \"selection\": {\"devices\": [\"$DEV\"]},
       \"level\": {\"current_a\": 8}, \"stages\": [{\"count\": 1}], \"duration_s\": 300}" >/dev/null \
    || fail "repeated POST of the same activation"
  log "ok: the repeated activation is accepted without a second one"
  api -X DELETE "$API/activations/$aid" >/dev/null || fail "DELETE activation"
  wait_for "activation ended, no limit in force" "$API/devices/$DEV" '.limit == null'

  # 5. the session ends and its summary shows the limits
  wait_for "a session summary since the start, ended, with limits applied" \
    "$API/sessions?device=$DEV&from=$since&open=false" \
    '[.sessions[] | select(.limits_applied > 0)] | length > 0'
  log "summary: $(jq -c '[.sessions[] | select(.limits_applied > 0)][0] | {mode, end_reason, energy_wh, limits_applied, duration_s}' <<<"$LAST")"

  stop_watch
  log "T2 passed"
}

H="docker compose -f compose/harness.yml"
layer_rules() { $H run --rm --no-deps -T layer layer rules "$DEV" "$1" >/dev/null; }

t3() {
  log "T3: the test layer stops during a session ($DEV)"
  start_watch
  wait_for "device online and in a session" "$API/devices/$DEV" '.online == true and .session != null'
  local started; started=$(jq -r '.session.started_at' <<<"$LAST")
  local started_q; started_q=$(jq -rn --arg v "$started" '$v|@uri')   # "+00:00" in a query
  local ver0; ver0=$(jq -r '.registry.binding_ver' <<<"$LAST")

  # 1. the layer goes away while the session runs
  $H stop layer layer-mqtt >/dev/null 2>&1
  local down; down=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  log "test layer stopped (service and broker)"

  # 2. the running session ends normally: the layer was needed for its TLS handshake only
  wait_for "the session started before the stop ended normally" "$API/sessions?device=$DEV&from=$started_q&open=false" \
    "[.sessions[] | select(.started_at <= \"$down\" and .end_reason == \"ev_unplugged\")] | length > 0"

  # 3. while the layer is away: the station stays connected to Imatra; a registry change is queued
  layer_rules '{"topology":"integrated","rated_current_a":20}'
  log "registry change queued while the layer is away: rated_current_a 20 A"
  sleep 60
  api "$API/devices/$DEV" >/tmp/t3-dev.json || fail "GET device"
  jq -e '.online == true' /tmp/t3-dev.json >/dev/null || fail "the station went offline at Imatra while the layer was away"
  jq -e '.registry.rules.rated_current_a == null' /tmp/t3-dev.json >/dev/null \
    || fail "the registry change reached Imatra although the layer was stopped"
  log "ok: after 60 s without the layer the station is online at Imatra; the change has not arrived"
  # what plug-ins did without the signer: recorded, not judged (EV enforces TLS)
  log "plug-ins without the layer: $(api "$API/sessions?device=$DEV&from=$down" | \
    jq -c "[.sessions[] | select(.started_at > \"$down\") | {mode, end_reason, v2g_sessions, duration_s}]")"

  # 4. the layer comes back: the queued change arrives, TLS sessions go on
  $H start layer-mqtt layer >/dev/null 2>&1
  local up; up=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  log "test layer started again"
  wait_for "the registry change arrived after the layer came back" "$API/devices/$DEV" \
    ".registry.rules.rated_current_a == 20 and .station_max_a == 20 and .registry.binding_ver > $ver0"
  wait_for "a TLS session after the layer came back" "$API/sessions?device=$DEV&from=$up&open=false" \
    '[.sessions[] | select(.mode == "iso15118-2" and .end_reason == "ev_unplugged" and .v2g_sessions > 0)] | length > 0'

  # 5. back to the start
  layer_rules '{"topology":"integrated"}'
  wait_for "registry restored" "$API/devices/$DEV" '.registry.rules.rated_current_a == null and .station_max_a == 32'
  stop_watch
  log "T3 passed"
}

case "${1:-}" in
  t2) t2 ;;
  t3) t3 ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
