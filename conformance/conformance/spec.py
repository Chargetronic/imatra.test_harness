"""Loading the contracts and checking one message against them."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

import yaml
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

CONTRACTS_DIR = Path(__file__).resolve().parents[2] / "contracts"
SPECS = ("device", "registry", "layer")


@dataclass(frozen=True)
class Problem:
    topic: str
    message: str

    def __str__(self) -> str:
        return f"{self.topic}: {self.message}"


@dataclass(frozen=True)
class Channel:
    spec: str
    name: str
    address: str
    pattern: re.Pattern
    messages: tuple[str, ...]  # component message names


# Rules the schemas only describe in words. Keyed by (spec, channel).
def _one_of(*fields: str):
    def rule(payload: dict) -> list[str]:
        present = [f for f in fields if f in payload]
        if len(present) != 1:
            return [f"exactly one of {', '.join(fields)} expected, got {present or 'none'}"]
        return []
    return rule


# RFC 3339 date-time, without depending on an optional package of jsonschema.
FORMATS = FormatChecker(formats=())


@FORMATS.checks("date-time", raises=ValueError)
def _date_time(value) -> bool:
    if not isinstance(value, str):
        return True
    if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$", value):
        raise ValueError(f"{value!r} is not an RFC 3339 date-time")
    datetime.fromisoformat(value.replace("z", "Z"))
    return True


RULES = {
    ("layer", "signRes"): [_one_of("sig", "error")],
    ("layer", "credRes"): [_one_of("cert", "error")],
}


def _address_pattern(address: str) -> re.Pattern:
    out, pos = [], 0
    for m in re.finditer(r"\{(\w+)\}", address):
        out.append(re.escape(address[pos:m.start()]))
        out.append(f"(?P<{m.group(1)}>[^/]+)")
        pos = m.end()
    out.append(re.escape(address[pos:]))
    return re.compile("^" + "".join(out) + "$")


class Contracts:
    """The three contracts, ready to check messages."""

    def __init__(self, directory: Path = CONTRACTS_DIR):
        self.docs: dict[str, dict] = {}
        registry = Registry()
        for spec in SPECS:
            doc = yaml.safe_load((directory / f"asyncapi-{spec}.yaml").read_text(encoding="utf-8"))
            self.docs[spec] = doc
            registry = registry.with_resource(f"urn:imatra:{spec}", Resource(contents=doc, specification=DRAFT7))
        self.registry = registry
        self.channels: list[Channel] = []
        for spec, doc in self.docs.items():
            for name, ch in doc.get("channels", {}).items():
                msgs = tuple(_ref_name(m["$ref"]) for m in ch.get("messages", {}).values())
                self.channels.append(Channel(spec, name, ch["address"], _address_pattern(ch["address"]), msgs))
        self._validators: dict[tuple[str, str], Draft7Validator] = {}

    def channel(self, topic: str) -> Channel | None:
        for ch in self.channels:
            if ch.pattern.match(topic):
                return ch
        return None

    def validator(self, spec: str, message: str) -> Draft7Validator:
        key = (spec, message)
        if key not in self._validators:
            schema = {"$ref": f"urn:imatra:{spec}#/components/messages/{message}/payload"}
            self._validators[key] = Draft7Validator(schema, registry=self.registry, format_checker=FORMATS)
        return self._validators[key]

    def check(self, topic: str, payload: bytes | str | dict) -> list[Problem]:
        """Problems of one message; an empty list means it follows the contract."""
        ch = self.channel(topic)
        if ch is None:
            return [Problem(topic, "no channel of the contracts has this topic")]
        if isinstance(payload, dict):
            body = payload
        else:
            try:
                body = json.loads(payload)
            except (ValueError, UnicodeDecodeError) as e:
                return [Problem(topic, f"not JSON: {e}")]
        problems: list[str] = []
        # a channel with several messages: the message must match one of them
        per_message = []
        for msg in ch.messages:
            errs = sorted(self.validator(ch.spec, msg).iter_errors(body), key=lambda e: list(e.absolute_path))
            per_message.append([f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in errs])
        if per_message and all(per_message):
            problems.extend(min(per_message, key=len))
        if isinstance(body, dict):
            for rule in RULES.get((ch.spec, ch.name), []):
                problems.extend(rule(body))
        return [Problem(topic, p) for p in problems]

    def examples(self) -> Iterator[tuple[Channel, str, str, object]]:
        """Every example of every message: (channel, message, example name, payload)."""
        for ch in self.channels:
            msgs = self.docs[ch.spec]["components"]["messages"]
            for m in ch.messages:
                for ex in msgs[m].get("examples", []):
                    yield ch, m, ex.get("name", "?"), ex["payload"]

    def topic(self, ch: Channel, device_id: str = "dev-01") -> str:
        return ch.address.replace("{deviceId}", device_id)


def _ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def load(directory: Path = CONTRACTS_DIR) -> Contracts:
    return Contracts(directory)
