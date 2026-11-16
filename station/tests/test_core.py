"""The station's protocol logic, every message checked against the contracts."""

import asyncio
import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "station"), str(ROOT / "conformance")]

from conformance import load  # noqa: E402
from station.core import Station  # noqa: E402

C = load()
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def make():
    sent = []
    clock = Clock()
    st = Station("dev-01", lambda s, p, q, r: sent.append((f"dev/dev-01/{s}", json.loads(json.dumps(p)), q, r)),
                 clock=clock)
    return st, sent, clock


def check(sent):
    problems = [str(p) for t, p, _q, _r in sent for p in C.check(t, p)]
    assert problems == [], problems


def of(sent, suffix):
    return [p for t, p, _q, _r in sent if t.endswith("/" + suffix)]


def down(st, seq, exi=b"\x80res", cl=None, close=False):
    m = {"v": 1, "conn": st.conn.id, "seq": seq, "pt": 32769, "exi": b64(exi), "t_srv_rx": 1, "t_srv_tx": 2}
    if cl:
        m["cl"] = cl
    if close:
        m["close"] = True
    st.on_message("v2g/down", json.dumps(m).encode())


def pair(ver, req=b"\x80loop", res=b"\x80loopres", ttl=1200, cid=0, term=None):
    p = {"ver": ver, "req": b64(req), "res": b64(res), "ttl_s": ttl}
    if cid:
        p["command_id"] = cid
    if term:
        p["term"] = [b64(x) for x in term]
    return p


def test_session_with_cache():
    async def go():
        st, sent, clock = make()
        st.loop = asyncio.get_running_loop()
        st.connected()
        st.plug_in()
        st.ev_open("TLSv1.2 ECDHE-ECDSA-AES128-SHA256")
        # a session-setup request goes to the server and gets its answer
        t = asyncio.create_task(st.ev_request(b"\x80setup", 20))
        await asyncio.sleep(0)
        down(st, 1, b"\x80setupres")
        assert await t == (b"\x80setupres", False)
        # the first loop request: a miss; the answer brings the pair
        t = asyncio.create_task(st.ev_request(b"\x80loop", 13))
        await asyncio.sleep(0)
        down(st, 2, b"\x80loopres", cl=pair(1, cid=7))
        assert await t == (b"\x80loopres", False)
        assert of(sent, "cmd/ack")[-1]["result"] == "installed" and of(sent, "cmd/ack")[-1]["command_id"] == 7
        assert of(sent, "cp")[-1]["ev"] == "C"
        # loop hits: answered locally; one sampled copy per loop_sample_s
        ups = len(of(sent, "v2g/up"))
        for _ in range(3):
            assert await st.ev_request(b"\x80loop", 13) == (b"\x80loopres", False)
        sampled = [u for u in of(sent, "v2g/up")[ups:] if u.get("sampled")]
        assert len(sampled) == 1
        clock.t += 31
        await st.ev_request(b"\x80loop", 13)
        assert len([u for u in of(sent, "v2g/up") if u.get("sampled")]) == 2
        # an older pair is stale, a pair for another connection is dropped
        st.on_message("cl/push", json.dumps({"v": 1, "conn": st.conn.id, "cl": pair(1)}).encode())
        assert of(sent, "cmd/ack")[-1]["result"] == "stale"
        n = len(of(sent, "cmd/ack"))
        st.on_message("cl/push", json.dumps({"v": 1, "conn": "other", "cl": pair(5)}).encode())
        assert len(of(sent, "cmd/ack")) == n
        # end of session
        t = asyncio.create_task(st.ev_request(b"\x80stop", 12))
        await asyncio.sleep(0)
        down(st, st.conn.seq, b"\x80stopres", close=True)
        assert await t == (b"\x80stopres", True)
        st.ev_closed("server closed the connection")
        st.unplug()
        assert of(sent, "cp")[-1]["event"] == "unplugged" and "plugged_ms" in of(sent, "cp")[-1]
        plugged = [c for c in of(sent, "cp") if c.get("event") == "plugged"][0]
        assert all(u["plug"] == plugged["plug"] for u in of(sent, "v2g/up"))
        check(sent)
    asyncio.run(go())


def test_ttl_expiry_runs_the_termination_scenario():
    async def go():
        st, sent, clock = make()
        st.loop = asyncio.get_running_loop()
        st.plug_in()
        st.ev_open("")
        t = asyncio.create_task(st.ev_request(b"\x80loop", 13))
        await asyncio.sleep(0)
        down(st, 1, b"\x80loopres", cl=pair(1, ttl=60, term=[b"\x80stopcs", b"\x80pd", b"\x80ss"]))
        await t
        clock.t += 30
        st.on_message("ctrl", json.dumps({"v": 1, "cmd": "ttl_renew", "ttl_s": 60, "t_srv": 1}).encode())
        clock.t += 50  # renewed: still valid
        assert await st.ev_request(b"\x80loop", 13) == (b"\x80loopres", False)
        clock.t += 61  # silent past the TTL
        out = [await st.ev_request(b"\x80loop", 13) for _ in range(4)]
        assert out == [(b"\x80stopcs", False), (b"\x80pd", False), (b"\x80ss", False), (None, True)]
        st.on_message("cl/push", json.dumps({"v": 1, "conn": st.conn.id, "cl": pair(2)}).encode())
        assert of(sent, "cmd/ack")[-1]["result"] == "rejected"
        assert any(tr.get("term") for tr in of(sent, "trace"))
        check(sent)
    asyncio.run(go())


def test_no_answer_closes():
    async def go():
        st, sent, _ = make()
        st.loop = asyncio.get_running_loop()
        st.plug_in()
        st.ev_open("")
        assert await st.ev_request(b"\x80setup", 20, timeout=0.05) == (None, True)
        check(sent)
    asyncio.run(go())


def test_config_power_cp_set_and_basic_mode():
    st, sent, clock = make()
    st.connected()
    st.on_message("config", json.dumps({"v": 1, "ver": 3, "rev": 1, "heartbeat_s": 30, "hlc_wait_s": 5,
                                        "telemetry_s": 10}).encode())
    assert of(sent, "status")[-1]["config_ver"] == 3
    st.on_message("config", json.dumps({"v": 1, "ver": 2, "rev": 0, "heartbeat_s": 99}).encode())
    assert st.config["heartbeat_s"] == 30  # older version ignored
    st.plug_in()
    clock.t += 6
    st.basic_if_no_hlc()
    assert of(sent, "cp")[-1]["mode"] == "basic" and of(sent, "cp")[-1]["ev"] == "C"
    st.on_message("power/set", json.dumps({"v": 1, "ver": 1, "command_id": 9, "limit_a": 10, "ttl_s": 600,
                                           "t_srv": 1}).encode())
    ack = of(sent, "cmd/ack")[-1]
    assert ack["result"] == "applied" and ack["command_id"] == 9 and ack["kind"] == "power"
    assert of(sent, "cp")[-1]["limit_a"] == 10
    st.on_message("power/set", json.dumps({"v": 1, "ver": 1, "limit_a": 12, "ttl_s": 600, "t_srv": 1}).encode())
    assert of(sent, "cmd/ack")[-1]["result"] == "stale"
    clock.t += 10
    st.telemetry()
    tel = of(sent, "telemetry/energy")[-1]
    assert tel["i_a"] == [10.0] and tel["p_total_w"] == 2300 and tel["e_wh"] > 0
    st.on_message("power/set", json.dumps({"v": 1, "ver": 2, "limit_a": 0, "ttl_s": 600, "t_srv": 1}).encode())
    assert of(sent, "cmd/ack")[-1]["result"] == "cleared"
    st.on_message("cp/set", json.dumps({"v": 1, "mode": "transit"}).encode())
    assert of(sent, "cp")[-1]["mode"] == "transit" and of(sent, "cp")[-1]["out"] == "transit"
    st.on_message("cp/set", json.dumps({"v": 1, "cmd": "restart", "via": "X1", "hold_s": 3}).encode())
    assert of(sent, "cp")[-2]["out"] == "X1"
    st.on_message("cp/set", b"not json")
    check(sent)
    if os.environ.get("CONTRACT_OUT"):
        with open(os.environ["CONTRACT_OUT"], "w") as f:
            for t, p, _q, _r in sent:
                f.write(json.dumps({"topic": t, "payload": p}) + "\n")


def test_retain_and_qos_follow_the_contract():
    st, sent, _ = make()
    st.connected()
    st.plug_in()
    st.heartbeat()
    for t, _p, q, r in sent:
        if t.endswith(("/status", "/cp")):
            assert q == 1 and r is True, t
