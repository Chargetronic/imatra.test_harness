"""End-to-end watch on the Imatra broker (internal listener, account server).

Waits until one full charging session of the test station has gone through
and checks every message on dev/# and registry/# against the contracts.
Exit 0 when every step was seen and no message broke a contract.
"""

import json
import os
import sys
import threading
import time

import paho.mqtt.client as mqtt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "conformance"))
from conformance import load  # noqa: E402

DEV = os.environ.get("DEVICE_ID", "dev-01")
WATCH_S = float(os.environ.get("WATCH_S", "240"))
contracts = load()
problems: list[str] = []
counts: dict[str, int] = {}
done = threading.Event()

STEPS = {
    "registry: bound": lambda t, m: t == f"registry/dev/{DEV}" and m.get("state") == "bound",
    "status: online": lambda t, m: t == f"dev/{DEV}/status" and m.get("online") is True,
    "cp: plugged": lambda t, m: t == f"dev/{DEV}/cp" and m.get("event") == "plugged",
    "v2g: open over TLS 1.2": lambda t, m: t == f"dev/{DEV}/v2g/up" and m.get("event") == "open"
    and str(m.get("tls", "")).startswith("TLSv1.2"),
    "v2g: engine answers": lambda t, m: t == f"dev/{DEV}/v2g/down" and bool(m.get("exi")),
    "cache pair installed": lambda t, m: t == f"dev/{DEV}/cmd/ack" and m.get("kind") == "pair"
    and m.get("result") == "installed",
    "v2g: closed": lambda t, m: t == f"dev/{DEV}/v2g/up" and m.get("event") == "closed",
    "cp: unplugged": lambda t, m: t == f"dev/{DEV}/cp" and m.get("event") == "unplugged",
}
seen: dict[str, float] = {}
t0 = time.monotonic()


def on_message(_c, _u, m):
    for p in contracts.check(m.topic, m.payload):
        problems.append(str(p))
        print("PROBLEM", p, flush=True)
    try:
        body = json.loads(m.payload)
    except ValueError:
        return
    counts[m.topic] = counts.get(m.topic, 0) + 1
    for name, match in STEPS.items():
        if name not in seen and isinstance(body, dict) and match(m.topic, body):
            seen[name] = time.monotonic() - t0
            print(f"{seen[name]:6.1f} s  {name}", flush=True)
    if len(seen) == len(STEPS):
        done.set()


c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="harness-e2e-watch")
c.username_pw_set("server", os.environ["MQTT_SERVER_PASSWORD"])
c.on_message = on_message
c.on_connect = lambda cl, *_a: cl.subscribe([("dev/#", 0), ("registry/#", 1)])
for _ in range(60):
    try:
        c.connect(os.environ.get("BROKER_HOST", "mqtt"), int(os.environ.get("BROKER_PORT", "1883")))
        break
    except OSError:
        time.sleep(2)
c.loop_start()
done.wait(WATCH_S)
c.loop_stop()

missing = [s for s in STEPS if s not in seen]
print("messages per topic:", json.dumps(counts, indent=1, sort_keys=True))
for s in missing:
    print("MISSING", s)
ok = not missing and not problems
print("e2e:", "passed" if ok else "FAILED", f"({len(problems)} contract problem(s))")
sys.exit(0 if ok else 1)
