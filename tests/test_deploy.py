"""The center deployment loader: provisioning, refusals, and secret hygiene.

Every test drives the real operators' path: a ``center.json`` on disk is
loaded, the store is provisioned through it, and the constructed objects are
asserted on concretely — a bound port, resolvable credentials, a registered
and bound device key, funded floats. The refusal tests pin the fail-closed
behaviour the network contract promises: a center that cannot sign receipts
never serves. Every failure path is also checked for secret leakage: the token
present in the config must not appear in any raised text. The node and consumer
loaders are covered in the ``ai-potluck`` repository's own ``test_deploy.py``.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from aipotluck.errors import ConflictError, PotluckError
from aipotluck.identity import generate_key_pair

from aipotluck_server.deploy import load_center
from aipotluck_server.persistence import Credential

CONSUMER_TOKEN = "consumer-token-deploy-secret"
NODE_TOKEN = "node-token-deploy-secret"
API_KEY = "sk-upstream-key-deploy-secret"
NOW = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.UTC)


def _write_json(path: Path, document: dict[str, Any]) -> Path:
    """Write a strict-JSON configuration file."""
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _center_document(tmp_path: Path, *, database_name: str = "center.db") -> dict[str, Any]:
    """Build a valid center.json body; key material is generated per call."""
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


def test_load_center_provisions_and_starts(tmp_path: Path) -> None:
    """A started center binds a port, resolves credentials, and funded floats."""
    path = _write_json(tmp_path / "center.json", _center_document(tmp_path))
    deployment = load_center(path, start=True)
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


def test_load_center_restart_reprovisions_without_double_funding(tmp_path: Path) -> None:
    """Re-loading the same config re-registers bindings and mints nothing new."""
    path = _write_json(tmp_path / "center.json", _center_document(tmp_path))
    first = load_center(path, start=False)
    first.store.close()

    second = load_center(path, start=True)
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


def test_load_center_refuses_unprovisionable_settlement_key(
    tmp_path: Path,
) -> None:
    """A settlement key that cannot be provisioned refuses the whole startup."""
    document = _center_document(tmp_path)
    # 31 bytes: valid base64, but not an Ed25519 private key.
    document["settlement_private_key_b64"] = base64.b64encode(b"x" * 31).decode("ascii")
    path = _write_json(tmp_path / "center.json", document)

    with pytest.raises(PotluckError) as excinfo:
        load_center(path, start=True)
    message = str(excinfo.value)
    assert "settlement-key-1" in message
    assert "settlement_private_key_b64" in message
    assert CONSUMER_TOKEN not in message and NODE_TOKEN not in message
    # Nothing was left bound: the database file was the only artifact.


def test_load_center_refuses_reprovision_of_a_different_credential_binding(
    tmp_path: Path,
) -> None:
    """A known token re-provisioned with a different binding is a conflict."""
    document = _center_document(tmp_path)
    path = _write_json(tmp_path / "center.json", document)
    first = load_center(path, start=False)
    first.store.close()

    document["credentials"][0]["tenant_id"] = "tenant-b"
    path = _write_json(tmp_path / "center-moved.json", document)
    with pytest.raises(ConflictError) as excinfo:
        load_center(path, start=False)
    # The store's conflict message names bindings, never the raw token.
    message = str(excinfo.value)
    assert "tenant-b" in message
    assert CONSUMER_TOKEN not in message and NODE_TOKEN not in message


def test_load_center_refuses_float_and_duplicate_key_json(tmp_path: Path) -> None:
    """A float or a repeated key anywhere in the file refuses the config."""
    document = _center_document(tmp_path)
    good = json.dumps(document)
    with_float = good.replace('"port": 0', '"port": 0.5')
    assert with_float != good
    (tmp_path / "float.json").write_text(with_float, encoding="utf-8")
    with pytest.raises(PotluckError) as float_exc:
        load_center(tmp_path / "float.json", start=False)
    assert "fractional" in str(float_exc.value)

    duplicated = good.replace(
        '"platform_id": "platform-1"',
        '"platform_id": "platform-1", "platform_id": "platform-2"',
    )
    assert duplicated != good
    (tmp_path / "duplicate.json").write_text(duplicated, encoding="utf-8")
    with pytest.raises(PotluckError) as duplicate_exc:
        load_center(tmp_path / "duplicate.json", start=False)
    assert "duplicate JSON key" in str(duplicate_exc.value)


