"""The server deployment loader: provisioning, refusals, and secret hygiene.

Every test drives the real operators' path: a ``server.json`` on disk is
loaded, the store is provisioned through it, and the constructed objects are
asserted on concretely — a bound port, resolvable credentials, a registered
and bound device key, funded floats. The refusal tests pin the fail-closed
behaviour the network contract promises: a server that cannot sign receipts
never serves. Every failure path is also checked for secret leakage: the token
present in the config must not appear in any raised text. The node and consumer
loaders are covered in the ``ai-potluck`` repository's own ``test_deploy.py``.
"""

from __future__ import annotations

import base64
import datetime as dt
import inspect
import json
import textwrap
from pathlib import Path
from typing import Any, cast

import pytest
from aipotluck.errors import ConflictError, PotluckError
from aipotluck.identity import generate_key_pair

from aipotluck_server import deploy
from aipotluck_server.deploy import load_server
from aipotluck_server.gateway_service import DEFAULT_MAX_QUEUE_DEPTH
from aipotluck_server.persistence import Credential

CONSUMER_TOKEN = "consumer-token-deploy-secret"
NODE_TOKEN = "node-token-deploy-secret"
API_KEY = "sk-upstream-key-deploy-secret"
NOW = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.UTC)


def _write_json(path: Path, document: dict[str, Any]) -> Path:
    """Write a strict-JSON configuration file."""
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


#: The docstring line the documented ``server.json`` example follows.
_EXAMPLE_MARKER = "``server.json`` — one server process::"


def _documented_example() -> dict[str, Any]:
    """Return the ``server.json`` example parsed out of `deploy`'s docstring.

    Read from the docstring rather than retyped in a test, so the example an
    operator copies is the example that is checked.
    """
    text = inspect.getdoc(deploy) or ""
    lines = text[text.index(_EXAMPLE_MARKER) :].splitlines()
    start = next(n for n, line in enumerate(lines) if line.strip() == "{")
    end = next(n for n, line in enumerate(lines) if n > start and line.strip() == "}")
    block = textwrap.dedent("\n".join(lines[start : end + 1]))
    return cast("dict[str, Any]", json.loads(block))


def _server_document(tmp_path: Path, *, database_name: str = "server.db") -> dict[str, Any]:
    """Build a valid server.json body; key material is generated per call."""
    _settlement_public, settlement_private = generate_key_pair()
    device_public, _device_private = generate_key_pair()
    return {
        "host": "127.0.0.1",
        "port": 0,
        "database_path": str(tmp_path / database_name),
        "platform_id": "platform-1",
        "settlement_key_id": "settlement-key-1",
        "settlement_private_key_b64": settlement_private,
        "certfile": None,
        "keyfile": None,
        "credentials": [
            {
                "token": CONSUMER_TOKEN,
                "tenant_id": "tenant-a",
                "subject_id": "consumer-X",
                "role": "consumer",
            },
            {
                "token": NODE_TOKEN,
                "tenant_id": "tenant-a",
                "subject_id": "node-A",
                "role": "node",
            },
        ],
        "providers": [
            {
                "device_id": "device-1",
                "device_key_id": "device-key-1",
                "provider_id": "provider-1",
                "public_key_b64": device_public,
                "demo_float_milli_credits": 5_000,
            }
        ],
        "consumer_floats": [{"account_id": "consumer-X", "amount": 100_000}],
    }


def test_load_server_provisions_and_starts(tmp_path: Path) -> None:
    """A started server binds a port, resolves credentials, and funded floats."""
    path = _write_json(tmp_path / "server.json", _server_document(tmp_path))
    deployment = load_server(path, start=True)
    try:
        assert deployment.config.host == "127.0.0.1"
        url = deployment.server.url
        assert url.startswith("http://127.0.0.1:")
        assert int(url.rsplit(":", 1)[1]) != 0, "port 0 must bind a real port"
        assert deployment.provider_ids == ("provider-1",)

        credential = deployment.store.resolve_credential(CONSUMER_TOKEN, NOW)
        assert credential == Credential(
            tenant_id="tenant-a", subject_id="consumer-X", role="consumer"
        )
        node_credential = deployment.store.resolve_credential(NODE_TOKEN, NOW)
        assert node_credential is not None and node_credential.role == "node"

        registry = deployment.service._registry
        device_key = registry.get_key("device-key-1")
        assert device_key.purpose == "provider_device"
        assert device_key.owner_id == "device-1"
        registry.check_device_binding("device-1", "provider-1")
        settlement_key = registry.get_key("settlement-key-1")
        assert settlement_key.purpose == "platform_settlement"
        assert settlement_key.owner_id == "platform-1"

        assert deployment.service.balance("provider-1") == 5_000
        assert deployment.service.balance("consumer-X") == 100_000
    finally:
        deployment.server.stop()
        deployment.store.close()

    # The default repr must not carry the settlement private key or tokens.
    text = repr(deployment)
    assert "settlement_private_key_b64" not in text
    assert CONSUMER_TOKEN not in text


def test_the_documented_server_json_example_boots(tmp_path: Path) -> None:
    """The example in `deploy`'s own docstring loads and starts, as written.

    Only what cannot be committed is substituted: real key material for the two
    placeholders, a database path inside this test's own directory, and a port
    that needs no privilege. A field the loader comes to require without a
    matching edit to the documented example is the drift an operator meets when
    they copy the example and it refuses to start, and this test fails first.
    """
    document = _documented_example()
    _settlement_public, settlement_private = generate_key_pair()
    device_public, _device_private = generate_key_pair()
    document["settlement_private_key_b64"] = settlement_private
    document["providers"][0]["public_key_b64"] = device_public
    document["database_path"] = str(tmp_path / "server.db")
    document["port"] = 0

    deployment = load_server(_write_json(tmp_path / "server.json", document), start=True)
    try:
        assert deployment.server.url.startswith("http://127.0.0.1:")
        assert deployment.provider_ids == ("provider-1",)
        assert deployment.service.balance("consumer-X") == 100_000
        assert deployment.service.balance("provider-1") == 5_000
        registry = deployment.service._registry
        registry.check_device_binding("device-1", "provider-1")
        assert registry.get_key("settlement-key-1").owner_id == document["platform_id"]
    finally:
        deployment.server.stop()
        deployment.store.close()


def test_load_server_restart_reprovisions_without_double_funding(tmp_path: Path) -> None:
    """Re-loading the same config re-registers bindings and mints nothing new."""
    path = _write_json(tmp_path / "server.json", _server_document(tmp_path))
    first = load_server(path, start=False)
    first.store.close()

    second = load_server(path, start=True)
    try:
        assert second.provider_ids == ("provider-1",)
        assert second.store.resolve_credential(CONSUMER_TOKEN, NOW) is not None
        assert second.service.balance("provider-1") == 5_000
        assert second.service.balance("consumer-X") == 100_000
        registry = second.service._registry
        registry.check_device_binding("device-1", "provider-1")
    finally:
        second.server.stop()
        second.store.close()


def test_load_server_refuses_unprovisionable_settlement_key(
    tmp_path: Path,
) -> None:
    """A settlement key that cannot be provisioned refuses the whole startup."""
    document = _server_document(tmp_path)
    # 31 bytes: valid base64, but not an Ed25519 private key.
    document["settlement_private_key_b64"] = base64.b64encode(b"x" * 31).decode("ascii")
    path = _write_json(tmp_path / "server.json", document)

    with pytest.raises(PotluckError) as excinfo:
        load_server(path, start=True)
    message = str(excinfo.value)
    assert "settlement-key-1" in message
    assert "settlement_private_key_b64" in message
    assert CONSUMER_TOKEN not in message and NODE_TOKEN not in message
    # Nothing was left bound: the database file was the only artifact.


def test_load_server_refuses_reprovision_of_a_different_credential_binding(
    tmp_path: Path,
) -> None:
    """A known token re-provisioned with a different binding is a conflict."""
    document = _server_document(tmp_path)
    path = _write_json(tmp_path / "server.json", document)
    first = load_server(path, start=False)
    first.store.close()

    document["credentials"][0]["tenant_id"] = "tenant-b"
    path = _write_json(tmp_path / "server-moved.json", document)
    with pytest.raises(ConflictError) as excinfo:
        load_server(path, start=False)
    # The store's conflict message names bindings, never the raw token.
    message = str(excinfo.value)
    assert "tenant-b" in message
    assert CONSUMER_TOKEN not in message and NODE_TOKEN not in message


def test_load_server_refuses_float_and_duplicate_key_json(tmp_path: Path) -> None:
    """A float or a repeated key anywhere in the file refuses the config."""
    document = _server_document(tmp_path)
    good = json.dumps(document)
    with_float = good.replace('"port": 0', '"port": 0.5')
    assert with_float != good
    (tmp_path / "float.json").write_text(with_float, encoding="utf-8")
    with pytest.raises(PotluckError) as float_exc:
        load_server(tmp_path / "float.json", start=False)
    assert "fractional" in str(float_exc.value)

    duplicated = good.replace(
        '"platform_id": "platform-1"',
        '"platform_id": "platform-1", "platform_id": "platform-2"',
    )
    assert duplicated != good
    (tmp_path / "duplicate.json").write_text(duplicated, encoding="utf-8")
    with pytest.raises(PotluckError) as duplicate_exc:
        load_server(tmp_path / "duplicate.json", start=False)
    assert "duplicate JSON key" in str(duplicate_exc.value)


def test_an_unknown_server_field_is_refused_with_the_accepted_set_named(
    tmp_path: Path,
) -> None:
    """A misspelled top-level key refuses the server instead of defaulting.

    The dangerous shape is a TLS pair spelled two different wrong ways at once
    (``cert_file``/``key_file``): the half-pair check would pass, both fields
    would read as absent, and the server would serve cleartext on whatever
    ``host`` names while believing it is configured for TLS. Naming the
    unknown fields and the accepted set is what makes that typo visible.
    """
    document = _server_document(tmp_path)
    document["max_queue_dept"] = 100
    path = _write_json(tmp_path / "server.json", document)
    with pytest.raises(PotluckError) as excinfo:
        load_server(path, start=False)
    message = str(excinfo.value)
    assert "max_queue_dept" in message
    assert "max_queue_depth" in message, "the accepted set is named"

    tls_typo = _server_document(tmp_path)
    tls_typo["cert_file"] = "server.crt"
    tls_typo["key_file"] = "server.key"
    path = _write_json(tmp_path / "tls-typo.json", tls_typo)
    with pytest.raises(PotluckError) as tls_exc:
        load_server(path, start=False)
    message = str(tls_exc.value)
    assert "cert_file" in message and "key_file" in message
    assert "cleartext" not in message




def test_a_server_that_names_no_queue_field_gets_the_documented_default(
    tmp_path: Path,
) -> None:
    """Queueing is on by default, and the default is the one the docs name.

    Asserted against the loader rather than against the dataclass, because the
    claim an operator relies on is about the file they did *not* write: a server
    upgraded in place, with a ``server.json`` that predates the field, has to come
    up holding work rather than shedding it.
    """
    document = _server_document(tmp_path)
    assert "queue_enabled" not in document and "max_queue_depth" not in document
    deployment = load_server(_write_json(tmp_path / "server.json", document))
    try:
        assert deployment.config.queue_enabled is True
        assert deployment.config.max_queue_depth == DEFAULT_MAX_QUEUE_DEPTH
    finally:
        deployment.store.close()


def test_a_server_may_turn_the_queue_off_and_bound_it(tmp_path: Path) -> None:
    """Both fields reach the running service's configuration."""
    document = _server_document(tmp_path) | {
        "queue_enabled": False,
        "max_queue_depth": 7,
    }

    deployment = load_server(_write_json(tmp_path / "server.json", document))
    try:
        assert deployment.config.queue_enabled is False
        assert deployment.config.max_queue_depth == 7
    finally:
        deployment.store.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("queue_enabled", "on"),
        ("queue_enabled", 1),
        ("queue_enabled", None),
        ("max_queue_depth", "100"),
        ("max_queue_depth", True),
        ("max_queue_depth", -1),
    ],
)
def test_a_queue_field_written_wrong_refuses_the_server_at_load(
    tmp_path: Path, field: str, value: Any
) -> None:
    """A wrong queue setting fails at startup rather than misbehaving at runtime.

    This is the fail-loud rule the rest of the loader already follows. The tempting
    alternative — reading ``queue_enabled`` with a default when it is not a boolean
    — would turn ``"on"`` into ``False``, so an operator who meant to hold work
    would run a server that sheds it and would learn so only from their users.
    ``null`` is refused for the same reason: an absent field is a documented
    default, while a field somebody wrote as null is a mistake worth reporting.
    """
    document = _server_document(tmp_path) | {field: value}

    with pytest.raises(PotluckError) as refused:
        load_server(_write_json(tmp_path / "server.json", document))

    assert field in str(refused.value)


def test_a_fractional_queue_depth_is_refused_by_the_strict_parser_first(
    tmp_path: Path,
) -> None:
    """A float never reaches the field check, because the file is not strict JSON.

    Refused even earlier than a wrong type, and for the reason the whole config
    boundary gives: an amount that can be encoded two ways is not an amount.
    """
    document = _server_document(tmp_path) | {"max_queue_depth": 1.5}

    with pytest.raises(PotluckError) as refused:
        load_server(_write_json(tmp_path / "server.json", document))

    assert "fractional number" in str(refused.value)
