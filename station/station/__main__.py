"""Run the test station.

  python -m station --bootstrap dev-01.json [--iface eth0] [--port 15119]
      With the test layer (PKI_MODE=layer): certificate for the deployment
      from the layer, TLS to the EV with the layer's signature.

  python -m station --device-id dev-01 --cert c.pem --key k.pem --ca ca.pem --address mqtt:8883
      Without a layer (PKI_MODE=own): certificate from the deployment's own CA;
      plain TCP to the EV only.

Options: --plug-at-start (default on), --unplug-after-s N (after the EV
closed its last connection, default 10), --replug-s N (plug in again after N
s, 0 = never; default 0), --debug.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import threading
import time
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .core import Station
from .links import CloudLink, LayerLink
from .v2g import interface_for, serve_sdp, serve_v2g

log = logging.getLogger("station")


def csr_for(key_pem: str, device_id: str) -> str:
    key = serialization.load_pem_private_key(key_pem.encode(), None)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def get_cred(layer: LayerLink, key_pem: str, device_id: str, binding_ver: int) -> dict:
    while True:
        r = layer.cred(csr_for(key_pem, device_id), binding_ver)
        if r and not r.get("error"):
            return r
        log.warning("certificate for the deployment: %s; retrying in 10 s",
                    r.get("error") if r else "no answer from the layer")
        time.sleep(10)


async def run(a):
    loop = asyncio.get_running_loop()
    stop = threading.Event()
    if a.v2g_subnet:
        a.iface = interface_for(a.v2g_subnet)
        log.info("V2G link on %s", a.iface)
    layer = None
    if a.bootstrap:
        boot = json.load(open(a.bootstrap))
        device_id, key_pem, secc = boot["device_id"], boot["key"], boot["secc"]["chain"]
        layer = LayerLink(device_id, boot["layer"]["address"], boot["layer"]["ca"], boot["cert"], key_pem)
        cred = await loop.run_in_executor(None, get_cred, layer, key_pem, device_id, 0)
        address, ca, cert = cred["address"], cred["ca"], cred["cert"]
        log.info("certificate for deployment %s until %s", cred["cloud_id"], cred["not_after"])
    else:
        device_id, key_pem, secc = a.device_id, open(a.key).read(), None
        address, ca, cert, cred = a.address, open(a.ca).read(), open(a.cert).read(), None

    cloud: dict = {}
    st = Station(device_id, lambda s, p, q, r: cloud["link"].publish(s, p, q, r), loop=loop)

    def connect(ca_pem, cert_pem):
        cloud["link"] = CloudLink(device_id, address, ca_pem, cert_pem, key_pem,
                                  on_connected=lambda: loop.call_soon_threadsafe(st.connected),
                                  on_message=lambda s, p: loop.call_soon_threadsafe(st.on_message, s, p))

    connect(ca, cert)

    # --- EV side (threads) bridged into the loop
    def call(fn, *args):
        return asyncio.run_coroutine_threadsafe(_call(fn, *args), loop).result()

    async def _call(fn, *args):
        r = fn(*args)
        return await r if asyncio.iscoroutine(r) else r

    state = {"closed_at": None}

    def on_open(tls):
        state["closed_at"] = None
        if st.plug is None:
            call(st.plug_in)
        call(st.ev_open, tls)

    def on_closed(reason):
        call(st.ev_closed, reason)
        state["closed_at"] = time.monotonic()

    def tls():
        return (secc, layer.sign) if layer and secc else None

    threading.Thread(target=serve_v2g, args=(a.port, on_open, lambda exi, n: call(st.ev_request, exi, n),
                                              on_closed, tls if layer else None, stop), daemon=True).start()
    threading.Thread(target=serve_sdp, args=(a.iface, a.port, lambda: bool(layer and layer.available()), stop),
                     daemon=True).start()

    if a.plug_at_start:
        await asyncio.sleep(2)
        st.plug_in()
    next_hb = 0.0
    unplugged_at = None
    renew_at = _ts(cred.get("next_req")) if cred else None
    while True:
        await asyncio.sleep(1)
        now = time.monotonic()
        if now >= next_hb:
            st.heartbeat()
            next_hb = now + st.config["heartbeat_s"]
        st.telemetry()
        st.basic_if_no_hlc()
        if state["closed_at"] and st.conn is None and st.plug and now - state["closed_at"] >= a.unplug_after_s:
            st.unplug()
            state["closed_at"], unplugged_at = None, now
        if unplugged_at and a.replug_s and now - unplugged_at >= a.replug_s and st.plug is None:
            st.plug_in()
            unplugged_at = None
        if renew_at and time.time() >= renew_at:
            new = await loop.run_in_executor(None, get_cred, layer, key_pem, device_id, cred["binding_ver"])
            cloud["link"].close()
            cred, renew_at = new, _ts(new.get("next_req"))
            connect(new["ca"], new["cert"])
            log.info("certificate renewed until %s", new["not_after"])


def _ts(s: str | None) -> float | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="station")
    ap.add_argument("--bootstrap")
    ap.add_argument("--device-id")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--ca")
    ap.add_argument("--address")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--v2g-subnet", help="pick the interface holding an address in this IPv6 subnet")
    ap.add_argument("--port", type=int, default=15119)
    ap.add_argument("--plug-at-start", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--unplug-after-s", type=float, default=10)
    ap.add_argument("--replug-s", type=float, default=0)
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args(argv)
    if not a.bootstrap and not (a.device_id and a.cert and a.key and a.ca and a.address):
        ap.error("--bootstrap, or --device-id --cert --key --ca --address")
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(run(a))


if __name__ == "__main__":
    main()
