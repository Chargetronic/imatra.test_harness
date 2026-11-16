"""Smoke test of a running test layer, from inside the harness network.

Acts as the station of a bootstrap package (layer provision): connects to the
layer's broker with its certificate, asks for its deployment certificate and
for one TLS signature, and checks every answer against the contracts, the
certificate against the deployment root and the signature against the SECC
certificate. Exit 1 on any problem.
"""

import base64
import hashlib
import json
import os
import ssl
import sys
import tempfile
import threading
import time

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "conformance"))
from conformance import load  # noqa: E402

boot = json.load(open(os.environ.get("BOOTSTRAP", "dev-01.json")))
dev = boot["device_id"]
host, port = boot["layer"]["address"].rsplit(":", 1)
contracts = load()
problems = []

tmp = tempfile.mkdtemp()
for name, body in (("ca.crt", boot["layer"]["ca"]), ("dev.crt", boot["cert"]), ("dev.key", boot["key"])):
    with open(os.path.join(tmp, name), "w") as f:
        f.write(body)
key = serialization.load_pem_private_key(boot["key"].encode(), None)

answers, got = {}, threading.Event()


def on_message(_c, _u, m):
    answers[m.topic] = json.loads(m.payload)
    for p in contracts.check(m.topic, m.payload):
        problems.append(str(p))
    if len(answers) == 2:
        got.set()


c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=dev)
c.tls_set(ca_certs=os.path.join(tmp, "ca.crt"), certfile=os.path.join(tmp, "dev.crt"),
          keyfile=os.path.join(tmp, "dev.key"), tls_version=ssl.PROTOCOL_TLS_CLIENT)
c.on_message = on_message
for attempt in range(30):
    try:
        c.connect(host, int(port))
        break
    except OSError:
        time.sleep(1)
c.loop_start()
c.subscribe([(f"dev/{dev}/cred/res", 1), (f"dev/{dev}/sign/res", 1)])
time.sleep(1)

csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dev)])).sign(key, hashes.SHA256())
requests = {
    f"dev/{dev}/cred/req": {"v": 1, "id": "smoke-c", "csr": csr.public_bytes(serialization.Encoding.PEM).decode(), "binding_ver": 0},
    f"dev/{dev}/sign/req": {"v": 1, "id": "smoke-s", "alg": "ecdsa-p256-sha256",
                           "digest": base64.b64encode(hashlib.sha256(b"ServerKeyExchange").digest()).decode()},
}
for topic, body in requests.items():
    problems += [str(p) for p in contracts.check(topic, body)]
    c.publish(topic, json.dumps(body), qos=1)

if not got.wait(15):
    problems.append(f"answers received: {sorted(answers)}")
c.loop_stop()

cred, sign = answers.get(f"dev/{dev}/cred/res", {}), answers.get(f"dev/{dev}/sign/res", {})
if cred.get("error"):
    problems.append(f"cred refused: {cred['error']} (bound? layer bind {dev})")
elif cred:
    cert = x509.load_pem_x509_certificate(cred["cert"].encode())
    root = x509.load_pem_x509_certificate(cred["ca"].encode())
    try:
        cert.verify_directly_issued_by(root)
    except Exception as e:  # noqa: BLE001
        problems.append(f"deployment certificate not issued by the deployment root: {e}")
    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != dev:
        problems.append("deployment certificate CN is not the device id")
if sign.get("error"):
    problems.append(f"sign refused: {sign['error']}")
elif sign:
    secc = x509.load_pem_x509_certificate(boot["secc"]["chain"].encode())
    try:
        secc.public_key().verify(base64.b64decode(sign["sig"]), b"ServerKeyExchange", ec.ECDSA(hashes.SHA256()))
    except Exception as e:  # noqa: BLE001
        problems.append(f"signature does not verify with the SECC certificate: {e}")

for p in problems:
    print("PROBLEM", p)
print("layer smoke:", "FAILED" if problems else "passed")
sys.exit(1 if problems else 0)
