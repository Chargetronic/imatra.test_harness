"""The station's side of the device protocol with Imatra.

Everything here is transport-free: messages from the deployment come in
through ``on_message``, messages to it go out through ``publish``; the EV side
calls ``ev_open``, ``ev_request``, ``ev_closed``. Values the station cannot
know without decoding EXI (the limit inside a Charging Loop answer, real
energy) are stubs derived from the limits it is given (TK-8).
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from . import VERSION

V = 1
PT_EXI = 0x8001
STATION_DUTY = 26.7  # the station's own PWM: 16 A
NOMINAL_V = 230.0
DEFAULT_A = 16.0


def now_us() -> int:
    return time.time_ns() // 1000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@dataclass
class Pair:
    ver: int
    req: bytes
    res: bytes
    term: list[bytes]
    ttl_s: int
    command_id: int
    until: float  # monotonic deadline


@dataclass
class Conn:
    id: str
    tls: str
    seq: int = 0
    pending: dict[int, asyncio.Future] = field(default_factory=dict)
    term_left: list[bytes] | None = None  # local termination running
    last_sample: float = 0.0


Publish = Callable[[str, dict, int, bool], None]  # suffix, payload, qos, retain


class Station:
    """One station; ``publish(suffix, payload, qos, retain)`` sends dev/<id>/<suffix>."""

    def __init__(self, device_id: str, publish: Publish, loop: asyncio.AbstractEventLoop | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.id = device_id
        self.publish = publish
        self.loop = loop
        self.clock = clock
        self.boot = secrets.token_hex(4)
        self.plug_n = 0
        self.plug: str | None = None
        self.plugged_at = 0.0
        self.config = {"ver": 0, "rev": 0, "loop_sample_s": 30, "ttl_s": 1200, "heartbeat_s": 60, "trace": True,
                       "cache_enabled": True, "digital_mode": True, "hlc_wait_s": 30, "telemetry_s": 60}
        self.mode = "digital"
        self.ev = "A"
        self.limit_a: float | None = None  # basic-mode limit in force
        self.power_ver = 0
        self.pair: Pair | None = None
        self.conn: Conn | None = None
        self.loop_seen = 0.0
        self.tele_seq = 0
        self.e_wh = 0.0
        self.last_tele = 0.0

    # ----- helpers

    def _send(self, suffix: str, payload: dict, qos: int = 1, retain: bool = False):
        if self.plug and suffix in ("cp", "telemetry/energy", "cmd/ack", "v2g/up") and "plug" not in payload:
            payload = {**payload, "plug": self.plug}
        self.publish(suffix, payload, qos, retain)

    def _ack(self, kind: str, ver: int, result: str, command_id: int = 0, conn: str | None = None):
        a = {"v": V, "kind": kind, "ver": ver, "result": result, "t": now_us()}
        if command_id:
            a["command_id"] = command_id
        if conn:
            a["conn"] = conn
        self._send("cmd/ack", a)

    def cp_state(self, event: str | None = None, **extra) -> dict:
        digital = self.mode == "digital"
        st = {"mode": self.mode, "out": "mask" if digital else "transit", "ev": self.ev,
              "station": {"duty": STATION_DUTY}, "t": now_us()}
        if digital:
            st["duty"] = 5
        elif self.mode == "basic" and self.limit_a:
            st["duty"], st["limit_a"] = round(self.limit_a / 0.6, 1), self.limit_a
        if event:
            st["event"] = event
        st.update(extra)
        return st

    def _cp(self, event: str | None = None, **extra):
        self._send("cp", self.cp_state(event, **extra), 1, True)

    # ----- status

    def status(self, event: str | None = None) -> dict:
        s = {"online": True, "sw": VERSION, "platform": "virtual", "ev_connected": self.ev != "A",
             "loop_active": self.clock() - self.loop_seen < self.config["heartbeat_s"],
             "config_ver": self.config["ver"], "config_rev": self.config["rev"], "t": now_us()}
        if event:
            s["event"] = event
        return s

    def connected(self):
        """The link to the deployment is up (again)."""
        self._send("status", self.status("connect"), 1, True)
        self._cp()

    def heartbeat(self):
        self._send("status", self.status(), 1, True)

    # ----- plug

    def plug_in(self):
        self.plug_n += 1
        self.plug = f"{self.boot}-{self.plug_n}"
        self.plugged_at = self.clock()
        self.ev = "B"
        self.mode = "digital" if self.config["digital_mode"] else "transit"
        self._cp("plugged")

    def unplug(self):
        if not self.plug:
            return
        ms = int((self.clock() - self.plugged_at) * 1000)
        self.ev, self.pair = "A", None
        self._cp("unplugged", plugged_ms=ms)
        self.plug = None
        self.limit_a = None

    def basic_if_no_hlc(self):
        """No V2G connection within hlc_wait_s of plug-in: basic charging on the station PWM."""
        w = self.config["hlc_wait_s"]
        if self.plug and self.conn is None and self.mode == "digital" and w and self.clock() - self.plugged_at >= w:
            self.mode, self.ev = "basic", "C"
            self._cp()

    # ----- telemetry (stub values from the limit)

    def current_a(self) -> float:
        if self.ev != "C":
            return 0.0
        return self.limit_a or DEFAULT_A

    def telemetry(self, force: bool = False):
        now = self.clock()
        i = self.current_a()
        if i <= 0:
            self.last_tele = now
            return
        dt = now - self.last_tele if self.last_tele else 0.0
        if not force and dt < self.config["telemetry_s"]:
            return
        self.e_wh += i * NOMINAL_V * dt / 3600
        self.last_tele = now
        self.tele_seq += 1
        self._send("telemetry/energy", {"seq": self.tele_seq, "boot": self.boot, "t": now_us(), "i_a": [round(i, 1)],
                                        "p_total_w": round(i * NOMINAL_V), "e_wh": round(self.e_wh, 1)})

    # ----- messages from the deployment

    def on_message(self, suffix: str, payload: bytes):
        try:
            m = json.loads(payload)
        except ValueError:
            return
        if not isinstance(m, dict):
            return
        h = {"v2g/down": self._down, "cl/push": self._push, "ctrl": self._ctrl, "config": self._config,
             "cp/set": self._cp_set, "power/set": self._power_set}.get(suffix)
        if h:
            h(m)

    def _install(self, cl: dict, conn_id: str):
        try:
            p = Pair(ver=int(cl["ver"]), req=base64.b64decode(cl["req"]), res=base64.b64decode(cl["res"]),
                     term=[base64.b64decode(x) for x in cl.get("term") or []], ttl_s=int(cl["ttl_s"]),
                     command_id=int(cl.get("command_id") or 0), until=self.clock() + int(cl["ttl_s"]))
        except (KeyError, ValueError, TypeError):
            return
        c = self.conn
        if c is None or c.id != conn_id:
            return  # a pair for another connection is dropped
        if c.term_left is not None:
            self._ack("pair", p.ver, "rejected", p.command_id, conn_id)
        elif self.pair and p.ver <= self.pair.ver:
            self._ack("pair", p.ver, "stale", p.command_id, conn_id)
        else:
            self.pair = p
            if self.ev == "B":
                self.ev = "C"  # the Charging Loop started
                self._cp()
            self._ack("pair", p.ver, "installed", p.command_id, conn_id)

    def _down(self, m: dict):
        c = self.conn
        if c is None or m.get("conn") != c.id:
            return
        if m.get("cl"):
            self._install(m["cl"], c.id)
        f = c.pending.pop(m.get("seq"), None)
        if f and not f.done():
            m["_rx"] = now_us()
            f.set_result(m)

    def _push(self, m: dict):
        if m.get("cl"):
            self._install(m["cl"], m.get("conn", ""))

    def _ctrl(self, m: dict):
        if m.get("cmd") == "ttl_renew":
            ttl = int(m.get("ttl_s") or self.config["ttl_s"])
            if self.pair:
                self.pair.until = self.clock() + ttl

    def _config(self, m: dict):
        if int(m.get("ver", 0)) <= self.config["ver"]:
            return
        self.config.update({k: v for k, v in m.items() if k in self.config or k in ("ver", "rev")})
        self.heartbeat()

    def _cp_set(self, m: dict):
        if m.get("mode") in ("digital", "transit"):
            self.mode = m["mode"]
            self._cp()
        elif m.get("cmd") == "restart" and m.get("via") in ("X1", "F"):
            # a restart pulse: shown on the CP report; the virtual EV is not affected
            self._send("cp", {**self.cp_state(), "out": m["via"]}, 1, True)
            self._cp()

    def _power_set(self, m: dict):
        try:
            ver, limit = int(m["ver"]), float(m["limit_a"])
        except (KeyError, ValueError, TypeError):
            return
        cid = int(m.get("command_id") or 0)
        if ver <= self.power_ver:
            self._ack("power", ver, "stale", cid)
            return
        self.power_ver = ver
        if limit <= 0:
            self.limit_a = None
            self._ack("power", ver, "cleared", cid)
        elif self.conn is not None and self.mode == "digital":
            self.limit_a = max(limit, 6.0)
            self._ack("power", ver, "held", cid)  # a digital session runs: the pair carries the limit
        else:
            self.limit_a = max(limit, 6.0)
            self._ack("power", ver, "applied", cid)
            if self.plug:
                self._cp()
        self.telemetry(force=True)

    # ----- EV side

    def ev_open(self, tls: str) -> Conn:
        self.conn = Conn(id=secrets.token_hex(6), tls=tls)
        self.pair = None
        t = now_us()
        self._send("v2g/up", {"v": V, "conn": self.conn.id, "event": "open", "tls": tls, "t_ev_rx": t, "t_up_tx": t}, 0)
        return self.conn

    def ev_closed(self, reason: str):
        c = self.conn
        if c is None:
            return
        t = now_us()
        self._send("v2g/up", {"v": V, "conn": c.id, "event": "closed", "reason": reason, "t_ev_rx": t, "t_up_tx": t}, 0)
        for f in c.pending.values():
            if not f.done():
                f.cancel()
        self.conn = None
        self.pair = None
        if self.ev == "C":
            self.ev = "B"
            self._cp()

    async def ev_request(self, exi: bytes, wire_bytes: int, timeout: float = 5.0) -> tuple[bytes | None, bool]:
        """One EV request; returns (response EXI or None, close the connection)."""
        c = self.conn
        if c is None:
            return None, True
        c.seq += 1
        seq, t_rx = c.seq, now_us()
        now = self.clock()
        p = self.pair
        if c.term_left is not None or (p and now > p.until and p.term):
            # the server was silent past the TTL: local termination scenario
            if c.term_left is None:
                c.term_left = list(p.term)
            if not c.term_left:
                return None, True
            res = c.term_left.pop(0)
            self._trace(c, seq, t_rx, len(exi), len(res), term=True)
            return res, False
        if p and self.config["cache_enabled"] and exi == p.req and now <= p.until:
            self.loop_seen = now
            sample = self.config["loop_sample_s"]
            if sample == 0 or now - c.last_sample >= sample:
                c.last_sample = now
                self._send("v2g/up", {"v": V, "conn": c.id, "seq": seq, "pt": PT_EXI, "exi": b64(exi),
                                      "wire_bytes": wire_bytes, "sampled": True, "t_ev_rx": t_rx, "t_up_tx": now_us()}, 0)
            self._trace(c, seq, t_rx, len(exi), len(p.res), from_cache=True)
            return p.res, False
        fut = (self.loop or asyncio.get_running_loop()).create_future()
        c.pending[seq] = fut
        self._send("v2g/up", {"v": V, "conn": c.id, "seq": seq, "pt": PT_EXI, "exi": b64(exi),
                              "wire_bytes": wire_bytes, "t_ev_rx": t_rx, "t_up_tx": now_us()}, 0)
        try:
            d = await asyncio.wait_for(fut, timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            c.pending.pop(seq, None)
            return None, True
        res = base64.b64decode(d["exi"]) if d.get("exi") else None
        if res is not None:
            self._trace(c, seq, t_rx, len(exi), len(res), t_down_rx=d["_rx"])
        return res, bool(d.get("close"))

    def _trace(self, c: Conn, seq: int, t_rx: int, req_bytes: int, res_bytes: int, t_down_rx: int | None = None,
               from_cache: bool = False, term: bool = False):
        if not self.config["trace"]:
            return
        t = now_us()
        m = {"v": V, "conn": c.id, "seq": seq, "t_ev_rx": t_rx, "t_down_rx": t_down_rx or t, "t_ev_tx": t,
             "req_bytes": req_bytes, "res_bytes": res_bytes}
        if from_cache:
            m["from_cache"] = True
        if term:
            m["term"] = True
        self.publish("trace", m, 0, False)
