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
#   compose/scenarios.sh t4        the registry: unbind, bind, revoke, repeats and
#                                  late messages, a digest that differs
#   compose/scenarios.sh t5        PKI_MODE=own: a new deployment without the layer,
#                                  the station on the deployment's own CA, the
#                                  registry by scripts/registry.sh (stops the rest)
#   compose/scenarios.sh t6        an EV without TLS: ISO 15118-2 over TCP through
#                                  Imatra, then the EV with TLS again
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
  # plug-in sessions start at plug-in, before the V2G session: query from a minute back
  local from_q; from_q=$(date -u -d '-60 sec' +%Y-%m-%dT%H:%M:%SZ)
  wait_for "device online and in a session" "$API/devices/$DEV" '.online == true and .session != null'
  local ver0; ver0=$(jq -r '.registry.binding_ver' <<<"$LAST")

  # 1. the layer goes away while the session runs
  $H stop layer layer-mqtt >/dev/null 2>&1
  local down; down=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  log "test layer stopped (service and broker)"

  # 2. the running session ends normally: the layer was needed for its TLS handshake only
  wait_for "the session running at the stop ended normally" "$API/sessions?device=$DEV&from=$from_q&open=false" \
    "[.sessions[] | select(.started_at < \"$down\" and .ended_at > \"$down\" and .mode == \"iso15118-2\" and .end_reason == \"ev_unplugged\")] | length > 0"

  # 3. without the layer: the station stays connected to Imatra; the EV insists on TLS, the
  #    station can only offer TCP (no signer), the EV declines, the station charges on PWM
  #    after hlc_wait_s (IEC 61851 basic charging)
  layer_rules '{"topology":"integrated","rated_current_a":20}'
  log "registry change queued while the layer is away: rated_current_a 20 A"
  wait_for "basic charging on PWM without the layer (plugged in, no V2G session, current flowing)" "$API/devices/$DEV" \
    '.online == true and .charge != null and .session == null and (.metering.i_a[0] // 0) > 0'
  $H logs --since "$down" station 2>/dev/null | grep -q "asked for TLS, offered TCP" \
    || fail "the station did not answer SDP with TCP while the signer was away"
  if $H logs --since "$down" station 2>/dev/null | grep -q "connected (TLS"; then
    fail "a TLS connection although the signer was away"
  fi
  jq -e '.registry.rules.rated_current_a == null' <<<"$LAST" >/dev/null \
    || fail "the registry change reached Imatra although the layer was stopped"
  log "ok: SDP offered TCP, the EV declined, basic charging; the registry change has not arrived"

  # 4. the layer comes back: the queued change arrives, TLS sessions go on
  $H start layer-mqtt layer >/dev/null 2>&1
  local up; up=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  log "test layer started again"
  wait_for "the registry change arrived after the layer came back" "$API/devices/$DEV" \
    ".registry.rules.rated_current_a == 20 and .station_max_a == 20 and .registry.binding_ver > $ver0"
  # the plug-in that fell back to PWM stays on PWM until the cable is pulled (IEC 61851);
  # the EV stops after the security mismatch (Josev): unplug and plug in again
  $H restart station ev >/dev/null 2>&1
  log "cable pulled and plugged in again (station and EV restarted)"
  wait_for "a TLS session ended after the layer came back" "$API/sessions?device=$DEV&from=$from_q&open=false" \
    "[.sessions[] | select(.ended_at > \"$up\" and .mode == \"iso15118-2\" and .v2g_sessions > 0)] | length > 0"
  $H logs --since "$up" station 2>/dev/null | grep -q "connected (TLSv1.2" || fail "no TLS connection after the layer came back"

  # 5. back to the start
  layer_rules '{"topology":"integrated"}'
  wait_for "registry restored" "$API/devices/$DEV" '.registry.rules.rated_current_a == null and .station_max_a == 32'
  stop_watch
  log "T3 passed"
}

I="docker compose -p imatra-harness-server -f $IMATRA_DIR/docker-compose.yml -f $PWD/compose/imatra.override.yml --project-directory $IMATRA_DIR"
# a message on the Imatra broker from the services' account (not retained: the
# layer's retained entry stays as it is)
imatra_pub() {
  local pw; pw=$(grep '^MQTT_SERVER_PASSWORD=' "$IMATRA_DIR/.env" | cut -d= -f2-)
  $I exec -T mqtt mosquitto_pub -h 127.0.0.1 -p 1883 -u server -P "$pw" -q 1 -t "$1" -m "$2"
}
layer_cmd() { $H run --rm --no-deps -T layer layer "$@" >/dev/null; }
feed_has() { # <event type> <cursor>: true when the feed has it for the device after the cursor
  api "$API/events?cursor=$2&types=$1&device=$DEV" | jq -e '.events | length > 0' >/dev/null 2>&1
}
wait_feed() {
  local end=$(( $(date +%s) + T_WAIT ))
  while [ "$(date +%s)" -lt "$end" ]; do feed_has "$1" "$2" && { log "ok: feed event $1"; return 0; }; sleep 2; done
  fail "no feed event $1"
}

t4() {
  log "T4: the registry ($DEV)"
  start_watch
  wait_for "device online and bound" "$API/devices/$DEV" '.online == true and .registry.state == "bound"'
  local ver; ver=$(jq -r '.registry.binding_ver' <<<"$LAST")
  local cur; cur=$(api "$API/events?cursor=0&limit=1000" | jq -r '.next_cursor')

  # 1. unbind: the device's limits are cancelled, it leaves the operator
  api -X POST "$API/devices/$DEV/limit" -d '{"limit_a": 12, "duration_s": 900}' >/dev/null || fail "POST limit"
  wait_for "a limit in force before unbinding" "$API/devices/$DEV" '.limit.limit_a == 12'
  layer_cmd unbind "$DEV"
  wait_for "unbound at Imatra, the limit cancelled" "$API/devices/$DEV" \
    ".registry.state == \"unbound\" and .registry.binding_ver > $ver and .limit == null"
  ver=$(jq -r '.registry.binding_ver' <<<"$LAST")
  wait_feed device.unbound "$cur"

  # 2. bound again
  layer_cmd bind "$DEV"
  wait_for "bound again" "$API/devices/$DEV" ".registry.state == \"bound\" and .registry.binding_ver > $ver"
  ver=$(jq -r '.registry.binding_ver' <<<"$LAST")
  wait_feed device.bound "$cur"

  # 3. revoked: served no more at once (blocked); bound again: served again
  layer_cmd revoke "$DEV"
  wait_for "revoked: blocked at Imatra" "$API/devices/$DEV" \
    ".registry.state == \"revoked\" and .registry.binding_ver > $ver and .blocked != null"
  ver=$(jq -r '.registry.binding_ver' <<<"$LAST")
  wait_feed device.revoked "$cur"
  layer_cmd bind "$DEV"
  wait_for "bound after the revocation: unblocked" "$API/devices/$DEV" \
    ".registry.state == \"bound\" and .registry.binding_ver > $ver and .blocked == null"
  ver=$(jq -r '.registry.binding_ver' <<<"$LAST")
  local back; back=$(date -u -d '-60 sec' +%Y-%m-%dT%H:%M:%SZ); local back_at; back_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  wait_for "a TLS session ended after the device was served again" "$API/sessions?device=$DEV&from=$back&open=false" \
    "[.sessions[] | select(.ended_at > \"$back_at\" and .mode == \"iso15118-2\" and .v2g_sessions > 0)] | length > 0"

  # 4. a late message (lower binding_ver) and a repeat (the same one) change nothing
  local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  imatra_pub "registry/dev/$DEV" "{\"v\":1,\"device_id\":\"$DEV\",\"state\":\"revoked\",\"binding_ver\":$(( ver - 1 )),\"at\":\"$now\"}"
  imatra_pub "registry/dev/$DEV" "{\"v\":1,\"device_id\":\"$DEV\",\"state\":\"unbound\",\"binding_ver\":$ver,\"at\":\"$now\"}"
  sleep 8
  api "$API/devices/$DEV" | jq -e ".registry.state == \"bound\" and .registry.binding_ver == $ver and .blocked == null" >/dev/null \
    || fail "a late or repeated registry message changed the device"
  log "ok: a late message (binding_ver $(( ver - 1 ))) and a repeat ($ver) changed nothing"

  # 5. a digest that differs: Imatra reads the registry again, writes system.registry_mismatch, keeps the state
  local cur2; cur2=$(api "$API/events?cursor=0&limit=1000" | jq -r '.next_cursor')
  imatra_pub "registry/digest" "{\"v\":1,\"bound\":99,\"max_binding_ver\":1,\"at\":\"$now\"}"
  local end=$(( $(date +%s) + 60 )) got=""
  while [ "$(date +%s)" -lt "$end" ]; do
    got=$(api "$API/events?cursor=$cur2&types=system.registry_mismatch" | jq -r '.events | length')
    [ "${got:-0}" -gt 0 ] && break; sleep 2
  done
  [ "${got:-0}" -gt 0 ] || fail "no system.registry_mismatch after a differing digest"
  sleep 5
  api "$API/devices/$DEV" | jq -e ".registry.state == \"bound\" and .registry.binding_ver == $ver" >/dev/null \
    || fail "the device changed after reading the registry again"
  log "ok: a differing digest: system.registry_mismatch, registry read again, the device unchanged"
  stop_watch
  log "T4 passed"
}

# PKI_MODE=own: stops the harness and its deployment (volumes too) and starts a
# new deployment without the layer. Runs last.
t5() {
  log "T5: PKI_MODE=own, no layer ($DEV)"
  compose/down.sh --volumes >/dev/null 2>&1
  rm -f "$IMATRA_DIR/.env"
  docker network create imatra-harness-link >/dev/null
  r() { openssl rand -hex "$1"; }
  sed -e "s|^SITE_ADDRESS=.*|SITE_ADDRESS=localhost|" \
      -e "s|^PUBLIC_TCP_PORT=.*|PUBLIC_TCP_PORT=${PUBLIC_TCP_PORT:-18883}|" \
      -e "s|^BROKER_DNS=.*|BROKER_DNS=mqtt|" \
      -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(r 16)|" \
      -e "s|^PKI_MODE=.*|PKI_MODE=own|" \
      -e "s|^MQTT_SERVER_PASSWORD=.*|MQTT_SERVER_PASSWORD=$(r 16)|" \
      -e "s|^OPERATOR_API_KEYS=.*|OPERATOR_API_KEYS=\"admin:$(r 24)\"|" \
      "$IMATRA_DIR/.env.example" > "$IMATRA_DIR/.env"
  KEY=$(sed -n 's/^OPERATOR_API_KEYS="\{0,1\}admin:\([^ "]*\).*/\1/p' "$IMATRA_DIR/.env")
  $I up -d >/dev/null 2>&1 || fail "the deployment in PKI_MODE=own did not start"
  log "deployment started in PKI_MODE=own"

  # the device's certificate from the deployment's own CA; the registry by script
  local own; own=$(mktemp -d)
  $I run --rm -T pki-init device "$DEV" > "$own/$DEV.pem" 2>/dev/null || fail "pki-init device"
  $I run --rm -T --entrypoint cat pki-init /pki/ca.crt > "$own/ca.crt" || fail "the deployment CA"
  chmod 0644 "$own"/*
  ( cd "$IMATRA_DIR" && COMPOSE_PROJECT_NAME=imatra-harness-server \
      scripts/registry.sh bound "$DEV" station "" "" "" '{"topology":"integrated"}' ) >/dev/null || fail "registry.sh bound"
  log "device certificate from the deployment CA; registry entry by scripts/registry.sh"

  start_watch
  local since; since=$(date -u -d '-60 sec' +%Y-%m-%dT%H:%M:%SZ)
  # no layer, no signer: an EV without TLS (an EV insisting on TLS would charge on PWM, see t3)
  OWN_DIR=$own EV_TLS=0 $H --profile own up -d --build --no-deps station-own ev >/dev/null 2>&1 || fail "station-own, ev"
  wait_for "the station online and bound" "$API/devices/$DEV" '.online == true and .registry.state == "bound" and .registry.type == "station"'
  wait_for "an ISO 15118-2 session ended normally" "$API/sessions?device=$DEV&from=$since&open=false" \
    '[.sessions[] | select(.mode == "iso15118-2" and .end_reason == "ev_unplugged" and .v2g_sessions > 0)] | length > 0'
  # revoked by script: blocked at once
  ( cd "$IMATRA_DIR" && COMPOSE_PROJECT_NAME=imatra-harness-server scripts/registry.sh revoked "$DEV" ) >/dev/null
  wait_for "revoked by script: blocked" "$API/devices/$DEV" '.registry.state == "revoked" and .blocked != null'
  ( cd "$IMATRA_DIR" && COMPOSE_PROJECT_NAME=imatra-harness-server scripts/registry.sh bound "$DEV" station "" "" "" '{"topology":"integrated"}' ) >/dev/null
  wait_for "bound again by script: unblocked" "$API/devices/$DEV" '.registry.state == "bound" and .blocked == null'
  stop_watch
  rm -rf "$own"
  log "T5 passed"
}

t6() {
  log "T6: an EV without TLS ($DEV)"
  start_watch
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  EV_TLS=0 $H up -d --no-deps ev >/dev/null 2>&1
  log "EV restarted without TLS"
  wait_for "an ISO 15118-2 session over TCP, ended normally" "$API/sessions?device=$DEV&from=$since&open=false" \
    '[.sessions[] | select(.mode == "iso15118-2" and .end_reason == "ev_unplugged" and .v2g_sessions > 0)] | length > 0'
  log "summary: $(jq -c '[.sessions[] | select(.mode == "iso15118-2")][0] | {mode, end_reason, energy_wh, duration_s}' <<<"$LAST")"
  $H logs --since "$since" station 2>/dev/null | grep -q "asked for TCP, offered TCP" \
    || fail "the station log shows no SDP request for TCP"
  $H logs --since "$since" station 2>/dev/null | grep -q "connected (TCP)" \
    || fail "the station log shows no V2G connection over TCP"
  if $H logs --since "$since" station 2>/dev/null | grep -q "connected (TLS"; then
    fail "a TLS connection while the EV had TLS off"
  fi
  log "ok: SDP asked for TCP, the V2G connection was plain TCP"
  local up; up=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  EV_TLS=1 $H up -d --no-deps ev >/dev/null 2>&1
  log "EV restarted with TLS"
  wait_for "a TLS session again" "$API/sessions?device=$DEV&from=$up&open=false" \
    '[.sessions[] | select(.mode == "iso15118-2" and .end_reason == "ev_unplugged" and .v2g_sessions > 0)] | length > 0'
  $H logs --since "$up" station 2>/dev/null | grep -q "connected (TLSv1.2" || fail "no TLS connection after the EV got TLS back"
  stop_watch
  log "T6 passed"
}

case "${1:-}" in
  t4) t4 ;;
  t5) t5 ;;
  t6) t6 ;;
  t2) t2 ;;
  t3) t3 ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
