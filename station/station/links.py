"""MQTT links: to the test layer (certificate, signature) and to the deployment."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import ssl
import tempfile
import threading
from typing import Callable

import paho.mqtt.client as mqtt

log = logging.getLogger("station.links")
SIGN_TIMEOUT_S = 3.0


def write_tmp(prefix: str, files: dict[str, str]) -> dict[str, str]:
    d = tempfile.mkdtemp(prefix=prefix)
    out = {}
    for name, body in files.items():
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o600)
        out[name] = p
    return out


def _tls(c: mqtt.Client, ca: str, cert: str, key: str):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(ca)
    ctx.load_cert_chain(cert, key)
    c.tls_set_context(ctx)


class LayerLink:
    """Requests to the test layer and their answers, matched by id."""

    def __init__(self, device_id: str, address: str, ca_pem: str, cert_pem: str, key_pem: str):
        self.id = device_id
        self.files = write_tmp("layer-", {"ca.crt": ca_pem, "dev.crt": cert_pem, "dev.key": key_pem})
        host, port = address.rsplit(":", 1)
        self.waiting: dict[str, tuple[threading.Event, list]] = {}
        self.lock = threading.Lock()
        self.ready = threading.Event()
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=device_id)
        _tls(c, self.files["ca.crt"], self.files["dev.crt"], self.files["dev.key"])
        c.on_connect = self._on_connect
        c.on_message = self._on_message
        c.on_disconnect = lambda *_a: self.ready.clear()
        c.reconnect_delay_set(1, 10)
        c.connect_async(host, int(port), keepalive=30)
        c.loop_start()
        self.c = c

    def _on_connect(self, c, _u, _f, rc, _p):
        if rc == 0:
            c.subscribe([(f"dev/{self.id}/cred/res", 1), (f"dev/{self.id}/sign/res", 1)])
            self.ready.set()
            log.info("layer connected")
        else:
            log.warning("layer refused the connection: %s", rc)

    def _on_message(self, _c, _u, m):
        try:
            body = json.loads(m.payload)
        except ValueError:
            return
        with self.lock:
            w = self.waiting.pop(body.get("id"), None)
        if w:
            w[1].append(body)
            w[0].set()

    def request(self, kind: str, body: dict, timeout: float) -> dict | None:
        if not self.ready.wait(timeout):
            return None
        rid = f"{kind[0]}-{secrets.token_hex(4)}"
        ev, box = threading.Event(), []
        with self.lock:
            self.waiting[rid] = (ev, box)
        self.c.publish(f"dev/{self.id}/{kind}/req", json.dumps({"v": 1, "id": rid, **body}), qos=1)
        if not ev.wait(timeout):
            with self.lock:
                self.waiting.pop(rid, None)
            return None
        return box[0]

    def cred(self, csr_pem: str, binding_ver: int) -> dict | None:
        return self.request("cred", {"csr": csr_pem, "binding_ver": binding_ver}, 15.0)

    def sign(self, digest: bytes) -> bytes:
        r = self.request("sign", {"alg": "ecdsa-p256-sha256", "digest": base64.b64encode(digest).decode()}, SIGN_TIMEOUT_S)
        if not r:
            raise TimeoutError("no answer from the layer's signer within 3 s")
        if r.get("error"):
            raise PermissionError(f"signer refused: {r['error']}")
        return base64.b64decode(r["sig"])

    def available(self) -> bool:
        return self.ready.is_set()


SUBSCRIBE = ("v2g/down", "cl/push", "ctrl", "config", "cp/set", "power/set")


class CloudLink:
    """The device listener of the deployment's broker."""

    def __init__(self, device_id: str, address: str, ca_pem: str, cert_pem: str, key_pem: str,
                 on_connected: Callable[[], None], on_message: Callable[[str, bytes], None]):
        self.id = device_id
        self.files = write_tmp("cloud-", {"ca.crt": ca_pem, "dev.crt": cert_pem, "dev.key": key_pem})
        host, port = address.rsplit(":", 1)
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=device_id)
        _tls(c, self.files["ca.crt"], self.files["dev.crt"], self.files["dev.key"])
        c.will_set(f"dev/{device_id}/status", '{"online":false}', qos=1, retain=True)
        prefix = f"dev/{device_id}/"

        def connected(cl, _u, _f, rc, _p):
            if rc != 0:
                log.warning("deployment refused the connection: %s", rc)
                return
            cl.subscribe([(prefix + s, 0 if s == "v2g/down" else 1) for s in SUBSCRIBE])
            log.info("deployment %s connected", address)
            on_connected()

        c.on_connect = connected
        c.on_message = lambda _c, _u, m: on_message(m.topic[len(prefix):], m.payload) if m.topic.startswith(prefix) else None
        c.reconnect_delay_set(1, 10)
        c.connect_async(host, int(port), keepalive=30)
        c.loop_start()
        self.c = c

    def publish(self, suffix: str, payload: dict, qos: int, retain: bool):
        self.c.publish(f"dev/{self.id}/{suffix}", json.dumps(payload, separators=(",", ":")), qos=qos, retain=retain)

    def close(self):
        self.c.disconnect()
        self.c.loop_stop()
