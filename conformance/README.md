# Conformance

Checks that every exchange follows the Imatra contracts of the pinned release:
message set, schemas, order, timing and refusal codes.

Planned:

- Schema validation of every message on the station ↔ Imatra, layer → Imatra
  and station ↔ layer exchanges against the Imatra specification.
- Negative end-to-end test: a station from this harness, pointed at any
  address with any material the harness can produce, is refused unless the
  identity was issued by the trust roots generated in that installation.
