# Requirements for the harness

Principle: the harness is security-neutral. Anyone may read and change all of
it; no change gives access to production systems. Production admission does
not depend on this code.

| ID | Requirement | Layer | Station | EV |
|---|---|---|---|---|
| TK-1 | Nothing from production in any form — no certificates (not even public parts), keys, fingerprints, revocation lists, ACLs, credentials or CI secrets — by default, in examples or in git history | ✓ | ✓ | ✓ |
| TK-2 | No code or description of how production identities are issued; provisioning works with the test layer only | ✓ | ✓ | — |
| TK-3 | Every trust root is generated at first start on the developer's machine and kept out of git; no root or key is shared between installations | ✓ | ✓ | ✓ |
| TK-4 | Device certificates are marked as test certificates and use software keys | ✓ | ✓ | — |
| TK-5 | The SECC key and V2G root are test-only, generated locally; no key import | ✓ | — | ✓ |
| TK-6 | The station works over a virtual link only: no SLAC, PLC modem driver, CP hardware or meter | — | ✓ | — |
| TK-7 | The test layer's broker is reachable only inside the harness network | ✓ | — | — |
| TK-8 | Exchanges between the elements follow the Imatra contracts exactly; data behind a contract may be simplified | ✓ | ✓ | ✓ |
| TK-9 | Nothing is implemented that has no contract with Imatra, the station or the EV | ✓ | ✓ | — |
| TK-10 | Licence: use limited to developing and testing with Imatra | ✓ | ✓ | ✓ |
| TK-11 | No infrastructure identifiers: domains, IP addresses, host names, deployment ids, image paths, deployment or backup scripts | ✓ | ✓ | ✓ |
| TK-12 | No real data: registries, serial numbers, bindings, locations, sessions, vehicle identifiers. EXI test data is synthetic only (recordings from real EVs carry the EVCCID, a MAC address) | ✓ | ✓ | ✓ |
| TK-13 | Written from scratch against the published contracts; no logic beyond what the contracts require; commit history does not refer to internal systems | ✓ | ✓ | — |

## Checks

1. Repository check on every push (`scripts/check-repo.sh`): private keys and
   certificates are refused; a deny-list of production strings is supplied as
   a CI secret, never stored in the repository.
2. Negative end-to-end test (`conformance/`): a station from this harness is
   refused by any broker whose roots were not generated in that installation.
