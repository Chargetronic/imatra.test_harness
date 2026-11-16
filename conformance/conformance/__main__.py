"""Command line.

  python -m conformance check TOPIC [FILE]
      Check one message (FILE or stdin). Exit 1 on any problem.

  python -m conformance sniff --host H [--port P] [--tls --cafile F --cert F --key F]
                              [--username U --password-env VAR] [--topic T ...]
                              [--seconds N]
      Subscribe (default: dev/# and registry/#), check every message, and
      check that every layer request gets an answer with the same id (a
      signature within 3 s). Prints one line per problem; at the end a
      summary. Exit 1 if there was any problem. Needs paho-mqtt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .spec import load

SIGN_TIMEOUT_S = 3.0


def cmd_check(a) -> int:
    data = open(a.file, "rb").read() if a.file else sys.stdin.buffer.read()
    problems = load().check(a.topic, data)
    for p in problems:
        print(p)
    return 1 if problems else 0


class Pairs:
    """Layer requests and their answers, matched by id."""

    def __init__(self):
        self.open: dict[tuple[str, str, str], float] = {}  # (device, kind, id) -> time

    def seen(self, topic: str, body: dict, now: float) -> list[str]:
        parts = topic.split("/")
        if len(parts) != 4 or parts[0] != "dev" or parts[2] not in ("sign", "cred"):
            return []
        dev, kind, way = parts[1], parts[2], parts[3]
        rid = body.get("id") if isinstance(body, dict) else None
        if rid is None:
            return []
        key = (dev, kind, rid)
        if way == "req":
            self.open[key] = now
            return []
        if way == "res":
            t0 = self.open.pop(key, None)
            if t0 is None:
                return [f"answer with id {rid!r} to no request seen"]
            if kind == "sign" and now - t0 > SIGN_TIMEOUT_S:
                return [f"signature answered in {now - t0:.1f} s (device waits {SIGN_TIMEOUT_S:.0f} s)"]
        return []

    def unanswered(self, now: float, grace: float = 10.0) -> list[str]:
        late = [k for k, t in self.open.items() if now - t > grace]
        return [f"dev/{d}/{k}/req id {i!r}: no answer" for d, k, i in late]


def cmd_sniff(a) -> int:
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("sniff needs paho-mqtt: pip install paho-mqtt", file=sys.stderr)
        return 2
    contracts, pairs = load(), Pairs()
    count = {"messages": 0, "problems": 0}

    def report(line: str):
        count["problems"] += 1
        print(line, flush=True)

    def on_message(_c, _u, m):
        count["messages"] += 1
        for p in contracts.check(m.topic, m.payload):
            report(str(p))
        try:
            body = json.loads(m.payload)
        except ValueError:
            return
        for p in pairs.seen(m.topic, body, time.monotonic()):
            report(f"{m.topic}: {p}")

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=a.client_id)
    if a.tls:
        c.tls_set(ca_certs=a.cafile, certfile=a.cert, keyfile=a.key)
    if a.username:
        c.username_pw_set(a.username, os.environ.get(a.password_env or "", None))
    c.on_message = on_message
    c.on_connect = lambda cl, _u, _f, rc, _p: [cl.subscribe(t, qos=1) for t in a.topic]
    c.connect(a.host, a.port)
    c.loop_start()
    end = time.monotonic() + a.seconds if a.seconds else None
    try:
        while end is None or time.monotonic() < end:
            time.sleep(1)
            for p in pairs.unanswered(time.monotonic()):
                report(p)
            pairs.open = {k: t for k, t in pairs.open.items() if time.monotonic() - t <= 10}
    except KeyboardInterrupt:
        pass
    c.loop_stop()
    print(f"{count['messages']} message(s), {count['problems']} problem(s)")
    return 1 if count["problems"] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="conformance")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ck = sub.add_parser("check")
    ck.add_argument("topic")
    ck.add_argument("file", nargs="?")
    sn = sub.add_parser("sniff")
    sn.add_argument("--host", required=True)
    sn.add_argument("--port", type=int, default=1883)
    sn.add_argument("--tls", action="store_true")
    sn.add_argument("--cafile")
    sn.add_argument("--cert")
    sn.add_argument("--key")
    sn.add_argument("--username")
    sn.add_argument("--password-env", help="name of the environment variable holding the password")
    sn.add_argument("--client-id", default="conformance")
    sn.add_argument("--topic", action="append")
    sn.add_argument("--seconds", type=float, default=0, help="stop after N seconds (0: until Ctrl-C)")
    a = ap.parse_args(argv)
    if a.cmd == "sniff" and not a.topic:
        a.topic = ["dev/#", "registry/#"]
    return {"check": cmd_check, "sniff": cmd_sniff}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
