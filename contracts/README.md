# Contracts

Copies of the machine-readable contracts of the Imatra release this harness is
pinned to. They are the source of truth for every check in
[`../conformance/`](../conformance/); do not edit them here.

| File | Exchange |
|---|---|
| `asyncapi-device.yaml` | station ↔ Imatra |
| `asyncapi-registry.yaml` | test layer → Imatra |
| `asyncapi-layer.yaml` | station ↔ test layer (certificate, TLS signature) |

`IMATRA_REF` names the Imatra commit or tag they come from. To move to another
release: `contracts/sync.sh REF` (needs read access to the Imatra repository),
then run the conformance tests.
