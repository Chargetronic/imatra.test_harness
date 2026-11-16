# Test service layer

A minimal service layer for testing Imatra. Written from scratch against the
published contracts; it is not a cut-down copy of any production system.

## Does

| Function | Contract | Notes |
|---|---|---|
| Generate trust roots at first start | — | layer CA (device identities), test deployment root, test V2G root and SECC certificate, broker certificates; stored under `pki/`, excluded from git |
| Provision a test station | — | key, certificate marked as test, and a bootstrap package (device id, layer address and root) |
| Device certificate for the deployment | `cred/req` → `cred/res` | real certificate under the test deployment root, 7 days; `next_req` fixed; no operator change in progress, so `current` never appears |
| Registry for Imatra | `registry/dev/{id}`, `registry/digest` | bound / unbound / revoked, type, rules; fixed coordinates and time zone; bind and unbind are immediate commands |
| Handshake signing | `sign/req` → `sign/res` | real ECDSA signature with the test SECC key; real refusal codes |
| Broker for device ↔ layer | MQTT over mTLS | internal compose network only, never published |

## Does not

- Accept any certificate, key or root it did not generate itself.
- Import a SECC key.
- Expose any port outside the compose network.
- Anything without a contract with Imatra or the station: operator change
  mechanics, user portal, analytics, backups, deployment tooling.

## Requirements

TK-1, TK-2, TK-3, TK-4, TK-5, TK-7, TK-8, TK-9, TK-11, TK-12, TK-13 — see
[`../docs/requirements.md`](../docs/requirements.md).
