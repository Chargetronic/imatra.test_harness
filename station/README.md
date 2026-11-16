# Test charging station

A charging station with the Chargetronic module built in: `type station`,
`topology: integrated`. It sets its own PWM and speaks ISO 15118-2 to the EV.

## Does

| Side | Messages | Notes |
|---|---|---|
| Imatra | `v2g/up`, `v2g/down`, `trace` | requests, `open` / `closed`, `sampled` |
| Imatra | `cl/push`, `ctrl` (`ttl_renew`), `cmd/ack` | Charging Loop cache handled as the open `fleetgen` generator does |
| Imatra | `config` | applies `loop_sample_s`, `ttl_s`, `heartbeat_s`, `cache_enabled`, `digital_mode`, `hlc_wait_s`, `telemetry_s` |
| Imatra | `status`, `cp`, `cp/set`, `power/set` | the station sets its own PWM |
| Imatra | `telemetry/energy` | values derived from the current limit |
| Test layer | `cred/req` → `cred/res` | certificate for the deployment |
| Test layer | `sign/req` → `sign/res` | remote signing of the TLS handshake with the EV |
| EV | SDP, V2GTP, ISO 15118-2 AC EIM, TLS 1.2 ECDHE-ECDSA | virtual link (IPv6 link-local), no SLAC |

Settings come only from the bootstrap package issued by the test layer.

## Allowed by the contract, never produced

- `battery_pct` in `status`: the station has no battery of its own, so the
  `supply` rule never opens a window.
- Final SoC read (DIN 70121): triggered only for DIN-only EVs; the test EV
  uses ISO 15118-2 AC.

## Does not

- SLAC, PLC modem driver, CP hardware, meter.
- Any production endpoint, root or credential.

## Requirements

TK-1, TK-2, TK-3, TK-4, TK-6, TK-8, TK-9, TK-11, TK-12, TK-13 — see
[`../docs/requirements.md`](../docs/requirements.md).
