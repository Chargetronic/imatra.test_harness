# Imatra Test Harness

A self-contained test environment for developing and debugging against the
[Imatra](https://github.com/Chargetronic/imatra.iso15118_server) ISO 15118 server without any
production infrastructure.

It provides the three counterparts an Imatra deployment talks to:

| Component | Directory | What it is |
|---|---|---|
| Test service layer | [`layer/`](layer/) | Issues device certificates for your Imatra deployment, publishes the device registry to it, and signs the TLS handshake of the test station. Minimal: only what Imatra and the station need. |
| Test charging station | [`station/`](station/) | A charging station with the Chargetronic module built in (`type station`, `topology: integrated`). Speaks the full Imatra device protocol on one side and ISO 15118-2 to the test EV on the other, over a virtual link. |
| Test EV | [`ev/`](ev/) | An ISO 15118-2 AC EV simulator (Josev) configured with the test V2G root. |

[`compose/`](compose/) starts the whole environment with your Imatra
deployment; [`conformance/`](conformance/) checks that every exchange follows
the Imatra contracts.

> **Status:** scaffold. Components are not implemented yet.

## Contracts

Every exchange between the elements follows the published Imatra contracts
exactly — message set, schemas, order, timing and refusal codes. Only the data
behind a contract may be simplified (for example, fixed coordinates or energy
values derived from the current limit).

| Exchange | Contract |
|---|---|
| Station ↔ Imatra | `spec/asyncapi-device.yaml` in Imatra |
| Test layer → Imatra | `spec/asyncapi-registry.yaml` in Imatra |
| Station ↔ test layer | device certificate and handshake signing (to be added to the Imatra spec) |
| Station ↔ EV | ISO 15118-2 AC, EIM, TLS 1.2 |

Each release of this harness is pinned to an Imatra release.

## Run profiles

| Profile | Imatra setting | What you get |
|---|---|---|
| `own` | `PKI_MODE=own` | Imatra, station and EV; no layer. Fastest start. |
| `layer` | `PKI_MODE=layer` | Everything above plus the test layer: certificates, registry, TLS to the EV with remote signing. |

## Security model

This harness is built so that nothing in it — as published or as modified by
anyone — gives access to production systems.

- **Every trust root is generated on your machine at first start**: the test
  layer CA, the test deployment root, the test V2G root and SECC certificate,
  the broker certificates. They live in a directory excluded from git. No two
  installations share a root or a key.
- **Test-only identities.** Certificates issued by the test layer are marked as
  test certificates and use software keys. The SECC key is a test key under a
  test V2G root; a real EV will not accept it, and there is no way to import
  another key.
- **No production endpoints, roots, fingerprints or credentials**, by default
  or in examples. A device built from this code cannot obtain a production
  identity: production devices are admitted only with identities issued by
  Chargetronic for licensed hardware.
- **Virtual link only.** The station has no SLAC, no PLC modem driver, no CP
  hardware and no meter.
- **Internal network.** The test layer's broker is reachable only inside the
  compose network.

## Not covered

- Hardware behaviour of Chargetronic devices placed between a station and the
  EV. Testing it is done with Chargetronic's support and is not published.
- Operator change between deployments. Binding and unbinding are immediate
  commands of the test layer.
- Fault injection (forced refusals, delays). Contributions welcome.

## Licence

To be decided. Use of this code will be limited to developing and testing
software that works with Imatra. See [NOTICE](NOTICE). Third-party components
(Josev, libcbv2g) keep their own licences.
