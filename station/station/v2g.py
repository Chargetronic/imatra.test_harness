"""EV side: SDP and V2GTP over TCP or TLS 1.2, on a virtual IPv6 link.

TLS ends here (the cache needs the plain text), but the SECC key does not
live here: the one signature per handshake (ServerKeyExchange, ECDHE_ECDSA,
P-256) is asked from the test layer (``sign/req``). No SLAC, no PLC modem
(TK-6): the EV reaches the station over an ordinary network interface.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import struct
import threading
from types import SimpleNamespace
from typing import Callable

log = logging.getLogger("station.v2g")

SDP_PORT = 15118
SDP_REQ, SDP_RES, PT_EXI = 0x9000, 0x9001, 0x8001
SEC_TLS, SEC_TCP, TRANSPORT_TCP = 0x00, 0x10, 0x00
TLS_DESC = "TLSv1.2 ECDHE-ECDSA-AES128-SHA256"


def v2gtp(pt: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", 0x01, 0xFE, pt, len(payload)) + payload


def read_exact(f, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = f(n - len(b))
        if not chunk:
            raise EOFError
        b += chunk
    return b


def read_frame(recv) -> tuple[int, bytes]:
    h = read_exact(recv, 8)
    ver, inv, pt, n = struct.unpack("!BBHI", h)
    if ver != 0x01 or inv != 0xFE or n > 65536:
        raise ValueError("not a V2GTP frame")
    return pt, read_exact(recv, n)


def _inet6():
    with open("/proc/net/if_inet6") as f:
        for line in f:
            hexaddr, idx, _plen, scope, _flags, name = line.split()
            yield str(ipaddress.IPv6Address(bytes.fromhex(hexaddr))), int(idx, 16), scope, name


def interface_for(subnet: str) -> str:
    """The interface holding an address in subnet (the virtual V2G link)."""
    net = ipaddress.IPv6Network(subnet)
    for addr, _idx, _scope, name in _inet6():
        if ipaddress.IPv6Address(addr) in net:
            return name
    raise RuntimeError(f"no interface with an address in {subnet}")


def interface_address(iface: str) -> tuple[str, int]:
    """The interface's link-local IPv6 address (as ISO 15118-2 asks), else any, and its index."""
    best = None
    for addr, idx, scope, name in _inet6():
        if name != iface:
            continue
        if scope == "20":  # link-local
            return addr, idx
        best = best or (addr, idx)
    if not best:
        raise RuntimeError(f"no IPv6 address on {iface}")
    return best


# ---------------------------------------------------------------- SDP

def serve_sdp(iface: str, tcp_port: int, tls_available: Callable[[], bool], stop: threading.Event):
    addr, idx = interface_address(iface)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", SDP_PORT))
    mreq = socket.inet_pton(socket.AF_INET6, "ff02::1") + struct.pack("@I", idx)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    s.settimeout(1.0)
    log.info("SDP on %s (%s), V2G on port %d", iface, addr, tcp_port)
    while not stop.is_set():
        try:
            data, peer = s.recvfrom(64)
        except socket.timeout:
            continue
        try:
            pt, body = struct.unpack("!H", data[2:4])[0], data[8:]
        except struct.error:
            continue
        if data[:2] != b"\x01\xfe" or pt != SDP_REQ or len(body) < 2:
            continue
        sec = SEC_TLS if body[0] == SEC_TLS and tls_available() else SEC_TCP
        res = socket.inet_pton(socket.AF_INET6, addr) + struct.pack("!HBB", tcp_port, sec, TRANSPORT_TCP)
        s.sendto(v2gtp(SDP_RES, res), peer)
        log.info("SDP: %s asked for %s, offered %s", peer[0], "TLS" if body[0] == SEC_TLS else "TCP",
                 "TLS" if sec == SEC_TLS else "TCP")


# ---------------------------------------------------------------- TLS with remote signing

def remote_key(secc_pem: str, sign: Callable[[bytes], bytes]):
    """A tlslite key whose only private operation is the layer's signature."""
    from tlslite.utils.python_ecdsakey import Python_ECDSAKey
    from tlslite import X509

    x = X509().parse(secc_pem)
    pub = x.publicKey

    class RemoteKey(Python_ECDSAKey):
        def __init__(self):
            self.curve_name, self.key_type = pub.curve_name, "ecdsa"
            self.public_key = pub.public_key
            # tlslite reads the curve size from the private key object
            self.private_key = SimpleNamespace(curve=pub.public_key.curve)

        def hasPrivateKey(self):
            return True

        def _sign(self, data, hAlg):
            if hAlg != "sha256" or len(data) != 32:
                raise ValueError(f"only P-256 / SHA-256 is signed remotely, got {hAlg}")
            return bytearray(sign(bytes(data)))

    return RemoteKey()


def tls_settings():
    from tlslite import HandshakeSettings

    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 3)  # TLS 1.2 (ISO 15118-2)
    s.cipherNames = ["aes128"]
    s.macNames = ["sha256"]
    s.keyExchangeNames = ["ecdhe_ecdsa"]
    s.eccCurves = ["secp256r1"]
    s.keyShares = []
    s.useEncryptThenMAC = False
    s.useExtendedMasterSecret = True
    s.requireExtendedMasterSecret = False
    s.ecdsaSigHashes = ["sha256"]
    return s


def tls_wrap(sock: socket.socket, secc_pem: str, sign: Callable[[bytes], bytes]):
    from tlslite import TLSConnection, X509CertChain

    chain = X509CertChain()
    chain.parsePemList(secc_pem)
    c = TLSConnection(sock)
    c.handshakeServer(certChain=chain, privateKey=remote_key(secc_pem, sign), settings=tls_settings())
    return c


# ---------------------------------------------------------------- V2GTP server

Handler = Callable[[bytes, int], tuple]  # (exi, wire_bytes) -> (response exi or None, close)


def serve_v2g(port: int, on_open: Callable[[str], None], on_request: Handler, on_closed: Callable[[str], None],
              tls: Callable[[], tuple] | None, stop: threading.Event):
    """Accept one EV connection at a time. ``tls()`` returns (secc_pem, sign) or None."""
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("::", port))
    srv.listen(1)
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            sock, peer = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_connection, args=(sock, peer, on_open, on_request, on_closed, tls), daemon=True).start()


def _connection(sock, peer, on_open, on_request, on_closed, tls):
    reason = "EV closed the connection"
    conn = sock
    desc = ""
    try:
        sock.settimeout(60)
        first = sock.recv(1, socket.MSG_PEEK)
        if first == b"\x16" and tls:  # TLS ClientHello
            secc, sign = tls()
            conn = tls_wrap(sock, secc, sign)
            desc = TLS_DESC
        recv = conn.read if desc else conn.recv
        send = conn.write if desc else conn.sendall
        on_open(desc)
        log.info("EV %s connected (%s)", peer[0], desc or "TCP")
        while True:
            pt, exi = read_frame(lambda n: bytes(recv(n)) if desc else recv(n))
            if pt != PT_EXI:
                continue
            res, close = on_request(exi, len(exi) + 8)
            if res is not None:
                send(v2gtp(PT_EXI, res))
            if close or res is None:
                reason = "server closed the connection" if close else "no answer from the server"
                break
    except EOFError:
        pass
    except Exception as e:  # noqa: BLE001 — any failure ends this connection only
        reason = f"connection error: {e}"
        log.warning("EV %s: %s", peer[0], reason)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        on_closed(reason)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
