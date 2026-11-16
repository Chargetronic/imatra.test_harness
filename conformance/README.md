# Conformance

Checks that every exchange follows the Imatra contracts of the pinned release
([`../contracts/`](../contracts/)): each message is matched to its channel by
topic and validated against the message schema, plus the rules the schemas
state only in words (a layer answer carries exactly one of a result and an
error).

```sh
pip install -r conformance/requirements.txt
cd conformance

# one message
python -m conformance check dev/dev-01/status message.json

# everything on a broker: every message checked, every layer request
# answered with the same id (a signature within 3 s)
python -m conformance sniff --host localhost --port 1883 \
  --username server --password-env MQTT_SERVER_PASSWORD --seconds 600

python -m pytest tests   # the checker against the contracts themselves
```

The same checks apply to any implementation of the contracts — the test
layer and station here, Imatra, and the production service layer.

Planned: negative end-to-end test — a station from this harness, pointed at
any address with any material the harness can produce, is refused unless the
identity was issued by the trust roots generated in that installation.
