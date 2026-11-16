# Compose

Starts Imatra (pinned release), the test layer, the test station and the test
EV on one internal network. Profiles: `own` (no layer) and `layer`.

Nothing here points at production systems. The test layer's broker is not
published outside the compose network.

## Scenarios

`compose/scenarios.sh <name>` runs against a harness started by `up.sh`: it
drives Imatra through its operator API (`/v1` through the gateway) and checks
the answers, while a watcher checks every message on the Imatra broker against
the contracts.

| Name | What it checks |
|---|---|
| `t2` | during a session: a current limit is applied and confirmed by the station; limits below 6 A, above the station limit, without a duration or without a key are refused; cancelling; a group activation over the station is dispatched, confirmed, idempotent by its id and ended; the session summary counts the limits |
| `t3` | the test layer (service and broker) stops during a session: the session ends normally; the station stays connected to Imatra; without the signer the station answers SDP with TCP, the EV (TLS enforced) declines and the station charges on PWM (IEC 61851); a registry change made meanwhile does not arrive; when the layer is back the change arrives (new `binding_ver`, station limit 20 A) and TLS sessions go on |
| `t6` | an EV without TLS (`EV_TLS=0`: asks for TCP, does not insist on TLS): an ISO 15118-2 session over plain TCP through Imatra, ended normally; then the EV with TLS again |
