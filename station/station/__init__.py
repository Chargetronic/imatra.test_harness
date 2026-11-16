"""Test charging station of the Imatra test harness.

A charging station with the Chargetronic module built in (type station,
topology integrated): the full device protocol with Imatra
(contracts/asyncapi-device.yaml), the certificate and TLS signature exchange
with the test layer (contracts/asyncapi-layer.yaml), and ISO 15118-2 towards
the test EV over a virtual link (no SLAC, no PLC modem, no CP hardware —
TK-6). The station does not decode EXI: it tunnels it.
"""

VERSION = "0.1.0"
