"""The checker against the contracts themselves: examples pass, broken messages fail."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance import load  # noqa: E402

C = load()
EXAMPLES = list(C.examples())


def test_every_spec_has_channels_and_examples():
    specs = {ch.spec for ch in C.channels}
    assert specs == {"device", "registry", "layer"}
    assert len(EXAMPLES) >= 15


@pytest.mark.parametrize("ch,msg,name,payload", EXAMPLES, ids=lambda x: getattr(x, "name", None) or str(x)[:20])
def test_examples_follow_the_contract(ch, msg, name, payload):
    assert C.check(C.topic(ch), payload) == []


def _required(spec, msg):
    resolver = C.registry.resolver(base_uri=f"urn:imatra:{spec}")
    schema = resolver.lookup(f"#/components/messages/{msg}/payload").contents
    while "$ref" in schema:
        schema = resolver.lookup(schema["$ref"]).contents
    return schema.get("required", [])


@pytest.mark.parametrize("ch,msg,name,payload", EXAMPLES, ids=lambda x: getattr(x, "name", None) or str(x)[:20])
def test_missing_required_field_fails(ch, msg, name, payload):
    required = [f for f in _required(ch.spec, msg) if isinstance(payload, dict) and f in payload]
    if not required:
        pytest.skip("no required field in this example")
    for f in required:
        broken = copy.deepcopy(payload)
        del broken[f]
        assert C.check(C.topic(ch), broken), f"{ch.name}: missing {f} accepted"


def test_unknown_topic():
    assert C.check("dev/dev-01/nothing", {}) != []


def test_not_json():
    assert C.check("dev/dev-01/status", b"{") != []


def test_topic_matching():
    assert C.channel("dev/dev-01/v2g/up").name == "v2gUp"
    assert C.channel("dev/dev-01/cl/push").name == "clPush"
    assert C.channel("registry/dev/dev-01").name == "registryDevice"
    assert C.channel("registry/digest").name == "registryDigest"
    assert C.channel("dev/dev-01/sign/res").spec == "layer"
    assert C.channel("dev/a/b/status") is None  # a device id has no '/'


def test_wrong_enum_fails():
    ok = {"v": 1, "device_id": "dev-01", "state": "bound", "binding_ver": 1, "at": "2026-11-16T00:00:00Z"}
    assert C.check("registry/dev/dev-01", ok) == []
    assert C.check("registry/dev/dev-01", {**ok, "state": "moved"}) != []


def test_layer_answers_carry_exactly_one_result():
    assert C.check("dev/dev-01/sign/res", {"v": 1, "id": "1", "sig": "MEUC"}) == []
    assert C.check("dev/dev-01/sign/res", {"v": 1, "id": "1", "error": "revoked"}) == []
    assert C.check("dev/dev-01/sign/res", {"v": 1, "id": "1"}) != []
    assert C.check("dev/dev-01/sign/res", {"v": 1, "id": "1", "sig": "MEUC", "error": "revoked"}) != []
    assert C.check("dev/dev-01/sign/res", {"v": 1, "id": "1", "error": "no reason"}) != []
    assert C.check("dev/dev-01/cred/res", {"v": 1, "id": "1"}) != []
    assert C.check("dev/dev-01/cred/res", {"v": 1, "id": "1", "error": "unbound"}) == []


def test_date_time_format_is_checked():
    bad = {"v": 1, "device_id": "dev-01", "state": "bound", "binding_ver": 1, "at": "yesterday"}
    assert C.check("registry/dev/dev-01", bad) != []


def test_pairs():
    from conformance.__main__ import Pairs

    p = Pairs()
    assert p.seen("dev/d/sign/req", {"id": "1"}, 0.0) == []
    assert p.seen("dev/d/sign/res", {"id": "1"}, 1.0) == []
    assert p.seen("dev/d/sign/req", {"id": "2"}, 0.0) == []
    assert p.seen("dev/d/sign/res", {"id": "2"}, 4.0) != []  # later than the device waits
    assert p.seen("dev/d/cred/res", {"id": "x"}, 0.0) != []  # no request
    p.seen("dev/d/cred/req", {"id": "3"}, 0.0)
    assert p.unanswered(20.0) == ["dev/d/cred/req id '3': no answer"]


def test_cli_check(tmp_path, capsys):
    from conformance.__main__ import main

    f = tmp_path / "m.json"
    f.write_text('{"v":1,"bound":1,"max_binding_ver":1,"at":"2026-11-16T00:00:00Z"}')
    assert main(["check", "registry/digest", str(f)]) == 0
    f.write_text('{"v":1}')
    assert main(["check", "registry/digest", str(f)]) == 1


def test_cli_batch(tmp_path):
    from conformance.__main__ import main
    from conformance.spec import CONTRACTS_DIR

    f = tmp_path / "m.jsonl"
    f.write_text('{"topic":"dev/d/sign/res","payload":{"v":1,"id":"1","sig":"MEUC"}}\n'
                 '{"topic":"dev/d/cred/res","payload":{"v":1,"id":"2","error":"unbound"}}\n')
    assert main(["--contracts", str(CONTRACTS_DIR), "batch", str(f)]) == 0
    f.write_text('{"topic":"dev/d/sign/res","payload":{"v":1,"id":"1"}}\n')
    assert main(["batch", str(f)]) == 1
    f.write_text("")
    assert main(["batch", str(f)]) == 1  # nothing checked is a failure
