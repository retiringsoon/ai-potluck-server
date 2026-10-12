"""Admission closure, tenant scope, and the one-command consumer path.

Two ideas are pinned here.

*Admission is a closed check.* A valid signature is permission to speak, not
permission to spend: the four caps an authorization carries — the exact work it
was signed for, the attempt budget, the model allowlist, and the charge ceiling
— are each re-derived or re-checked against the submitted request, and each has
a test that it refuses a request that exceeds it.

*Scope is the tenant.* Reads, cancellations and receipts are tenant-scoped: any
credential of a tenant may see and cancel that tenant's requests, and no
credential may reach another tenant's. Because ``tenant_scope=auto`` gives every
joiner a tenant named after it, the practical default is that one person cannot
see another's work at all.

The last test drives the whole consumer path — ``join`` then ``ask`` — against a
real ``GatewayServer`` and a real ``Connector`` over loopback TCP.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.cli import main
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.errors import IdentityBindingError, ProtocolError, StateTransitionError
from aipotluck.identity import generate_key_pair, load_private_key
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.records import SpendAuthorization, new_nonce
from aipotluck.wire import compute_request_digest, user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore, Credential

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"

CONSUMER = Credential(tenant_id="tenant-a", subject_id="consumer-X", role="consumer")
SIBLING = Credential(tenant_id="tenant-a", subject_id="consumer-Y", role="consumer")
FOREIGN = Credential(tenant_id="tenant-b", subject_id="consumer-Z", role="consumer")


def _wait_until(condition: Any, *, timeout: float = 10.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


class _Center:
    """A real service and store, with a funded consumer and a settled keyring."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.keyring = Keyring()
        self.store = CenterStore.open(tmp_path / "center.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "center.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=self.keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=self.keyring.registry, now=BASE
        )
        self.service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def admit(self, authorization: Any, *, credential: Credential = CONSUMER,
              messages: tuple[Any, ...] = (user_message("write a haiku about ledgers"),),
              idempotency_key: str = "idem-1", **overrides: Any) -> Any:
        """Admit one request with test-friendly defaults."""
        arguments: dict[str, Any] = {"model": MODEL, "max_charge_milli_credits": 20_000}
        arguments.update(overrides)
        return self.service.admit_request(
            credential=credential,
            idempotency_key=idempotency_key,
            messages=messages,
            authorization=authorization,
            now=BASE,
            **arguments,
        )


@pytest.fixture
def center(tmp_path: Path) -> _Center:
    """Return a center over a fresh store, closed at the end of the test."""
    built = _Center(tmp_path)
    yield built
    built.close()


def _authorize(keyring: Keyring, **overrides: Any) -> Any:
    """Sign a consumer authorization with the shared fixtures' defaults."""
    return signed_authorization(keyring, **overrides)


# --------------------------------------------------------------------------
# The four admission checks
# --------------------------------------------------------------------------


def test_admission_accepts_a_request_matching_its_authorization(center: _Center) -> None:
    """The positive path: everything the authorization signed is submitted."""
    result = center.admit(_authorize(center.keyring, request_id="R-1"))

    assert result.created is True
    assert result.request_id == "R-1"
    assert result.delivery_mode == DELIVERY


def test_admission_refuses_work_the_authorization_did_not_sign(center: _Center) -> None:
    """A valid signature for one conversation cannot be re-pointed at another."""
    authorization = _authorize(
        center.keyring, request_id="R-1", messages=(user_message("signed prompt"),)
    )

    with pytest.raises(ProtocolError, match="request_digest"):
        center.admit(authorization, messages=(user_message("a different prompt"),))


def test_admission_refuses_a_model_outside_the_signed_allowlist(center: _Center) -> None:
    """The model must be one the authorization allowed, not merely digest-matched."""
    authorization = _authorize(
        center.keyring, request_id="R-1", model=MODEL,
        allowed_models=frozenset({"some-other-model"}),
    )

    with pytest.raises(ProtocolError, match="allowlist"):
        center.admit(authorization, model=MODEL)


def test_admission_refuses_a_delivery_mode_the_authorization_did_not_sign(
    center: _Center,
) -> None:
    """The delivery mode is part of the signed work, so it cannot be swapped."""
    authorization = _authorize(center.keyring, request_id="R-1",
                               delivery_mode="buffered_complete")

    with pytest.raises(ProtocolError, match="request_digest"):
        center.admit(authorization, delivery_mode="stream_strict")


def test_admission_refuses_more_attempts_than_authorized(center: _Center) -> None:
    """The attempt budget may not exceed what the consumer signed."""
    authorization = _authorize(center.keyring, request_id="R-1", max_attempts=1)

    with pytest.raises(ProtocolError, match="max_attempts"):
        center.admit(authorization, max_attempts=3)


def test_admission_refuses_a_ceiling_above_the_signed_cap(center: _Center) -> None:
    """The exposed charge ceiling may not exceed the signed cap."""
    authorization = _authorize(center.keyring, request_id="R-1",
                               max_charge_milli_credits=1_000)

    with pytest.raises(ProtocolError, match="ceiling"):
        center.admit(authorization, max_charge_milli_credits=5_000)


# --------------------------------------------------------------------------
# Tenant scope: state, events, and cancellation
# --------------------------------------------------------------------------


def test_a_tenant_may_read_and_cancel_its_own_siblings_request(center: _Center) -> None:
    """Requests are visible within a tenant, not only to their own subject."""
    center.admit(_authorize(center.keyring, request_id="R-1"))

    document = center.service.request_status(credential=SIBLING, request_id="R-1")
    assert document["tenant_id"] == "tenant-a"
    assert document["status"] == "ROUTING"

    cancelled = center.service.cancel_request(
        credential=SIBLING, request_id="R-1", origin="consumer_cancel", now=BASE
    )
    assert cancelled["status"] == "CANCELLED"
    events = center.service.request_events(credential=SIBLING, request_id="R-1", cursor=0)
    assert isinstance(events, list)


def test_another_tenant_cannot_read_a_request(center: _Center) -> None:
    """A credential of one tenant cannot see another tenant's request."""
    center.admit(_authorize(center.keyring, request_id="R-1"))

    with pytest.raises(IdentityBindingError):
        center.service.request_status(credential=FOREIGN, request_id="R-1")
    with pytest.raises(IdentityBindingError):
        center.service.request_events(credential=FOREIGN, request_id="R-1", cursor=0)


def test_another_tenant_cannot_cancel_a_request(center: _Center) -> None:
    """Cancellation is refused across tenants, and the request survives."""
    center.admit(_authorize(center.keyring, request_id="R-1"))

    with pytest.raises(IdentityBindingError):
        center.service.cancel_request(
            credential=FOREIGN, request_id="R-1", origin="consumer_cancel", now=BASE
        )
    assert center.service.request_status(credential=CONSUMER, request_id="R-1")["status"] != (
        "CANCELLED"
    )


def test_an_unknown_request_is_not_readable(center: _Center) -> None:
    """A request nobody admitted is a state error, not an empty document."""
    with pytest.raises(StateTransitionError):
        center.service.request_status(credential=CONSUMER, request_id="R-missing")


def test_auto_invites_are_mutually_invisible_even_with_the_same_claimed_name(
    center: _Center,
) -> None:
    """Two auto joins that both claim ``alice`` must still be fully separated.

    This is the impersonation regression: ``tenant_scope=auto`` used to name the
    tenant after the client-supplied ``subject_id``, so setting it to an existing
    funded account name let a joiner land in that account's tenant. The identity
    is now derived by the server, so the claimed name has no effect.
    """
    first_public, first_private = generate_key_pair()
    second_public, _second_private = generate_key_pair()
    center.store.add_invite("code-a", "consumer", "auto", max_uses=1, created_at=BASE)
    center.store.add_invite("code-b", "consumer", "auto", max_uses=1, created_at=BASE)
    first = center.service.join(
        invite_code="code-a",
        identity={"subject_id": "alice", "key_id": "alice-key", "public_key_b64": first_public},
        device=None, center_url="http://center.test", now=BASE,
    )
    second = center.service.join(
        invite_code="code-b",
        identity={"subject_id": "alice", "key_id": "alice-key", "public_key_b64": second_public},
        device=None, center_url="http://center.test", now=BASE,
    )

    # Neither joiner became "alice", and their tenants and accounts differ.
    assert first.subject_id != "alice"
    assert second.subject_id != "alice"
    assert first.tenant_id != second.tenant_id
    assert first.key_id != "alice-key"

    record = SpendAuthorization(
        authorization_id="auth-R-a",
        payer_account_id=first.subject_id,
        consumer_id=first.subject_id,
        request_id="R-a",
        request_digest=compute_request_digest(
            messages=(user_message("hi"),), model=MODEL, delivery_mode=DELIVERY
        ),
        max_charge_milli_credits=20_000,
        pricing_version="flat-v1",
        billing_basis="reported_native_usage",
        minimum_evidence_level="node_reported",
        allowed_models=frozenset({MODEL}),
        allowed_trust_pools=frozenset({"trusted-beta"}),
        max_attempts=2,
        duplicate_execution_policy="bounded_model_only",
        max_provider_fanout=2,
        nonce=new_nonce(),
        issued_at=BASE - dt.timedelta(minutes=1),
        expires_at=BASE + dt.timedelta(minutes=5),
        key_id=first.key_id,
    ).sign(load_private_key(first_private), first.key_id)
    credential_a = Credential(
        tenant_id=first.tenant_id, subject_id=first.subject_id, role="consumer",
        account_id=first.subject_id,
    )
    center.service.admit_request(
        credential=credential_a, idempotency_key="idem-a",
        messages=(user_message("hi"),),
        authorization=record, model=MODEL, max_charge_milli_credits=20_000,
        delivery_mode=DELIVERY, max_attempts=2, now=BASE,
    )

    credential_b = Credential(
        tenant_id=second.tenant_id, subject_id=second.subject_id, role="consumer",
        account_id=second.subject_id,
    )
    assert center.service.request_status(credential=credential_a, request_id="R-a")["status"]
    with pytest.raises(IdentityBindingError):
        center.service.request_status(credential=credential_b, request_id="R-a")


# --------------------------------------------------------------------------
# One end-to-end `ask`: join then ask against a real center and a real node
# --------------------------------------------------------------------------


class _Node:
    """A real connector dialing the center over loopback TCP."""

    def __init__(self, tmp_path: Path, keyring: Keyring, center_port: int,
                 *, token: str) -> None:
        self.upstream = FakeUpstream()
        self.upstream.queue(
            FakeResponse(
                text_chunks=("Hello ", "from the scripted node"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        self.upstream.queue(
            FakeResponse(
                text_chunks=("Second ", "answer"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        self.adapter = FakeUpstreamAdapter(upstream=self.upstream, model=MODEL)
        self.store = NodeStore.open(tmp_path / "node.db")
        self.config = ConnectorConfig(
            center_url=f"ws://127.0.0.1:{center_port}/v1/node-link",
            node_id="node-A",
            device_id="device-A",
            device_key_id="device-key-A",
            provider_id="provider-A",
            database_path=str(tmp_path / "node.db"),
            token=token,
            adapter_name="fake-adapter",
            model=MODEL,
            device_private_key_b64=keyring.private_b64["device-key-A"],
            heartbeat_interval_s=3600,
        )
        self.connector = Connector(self.config, adapter=self.adapter, store=self.store)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self.connector.run_forever,
            kwargs={"stop_event": self.stop_event},
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        """Stop the connector and join its session thread."""
        self.connector.stop()
        self.thread.join(timeout=5)
        self.store.close()


def test_ask_joins_and_prints_the_answer_and_a_cost_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole consumer path: `join`, `ask`, buffered answer plus a cost line."""
    keyring = Keyring()
    store = CenterStore.open(tmp_path / "center.db")
    config = GatewayConfig(
        host="127.0.0.1",
        port=0,
        database_path=str(tmp_path / "center.db"),
        platform_id="platform-1",
        settlement_key_id="settlement-key-1",
        settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
    )
    service = GatewayService(config=config, store=store, registry=keyring.registry)
    server = GatewayServer(service, config=config)
    server.start()
    node: _Node | None = None
    try:
        store.add_credential("node-token-ask", "tenant-a", "node-A", "node", REGISTERED_AT)
        service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )
        now = dt.datetime.now(dt.UTC)
        store.add_invite("code-ask", "consumer", "auto", max_uses=1, created_at=now)
        node = _Node(tmp_path, keyring, int(server.url.rsplit(":", 1)[1]), token="node-token-ask")
        _wait_until(lambda: server.connected_node_count == 1, what="the node link")

        identity_dir = tmp_path / "identity"
        assert main([
            "join", "--center", server.url, "--invite", "code-ask",
            "--config-dir", str(identity_dir), "--subject-id", "consumer-X",
        ]) == 0
        capsys.readouterr()

        code = main([
            "ask", "say hello", "--config-dir", str(identity_dir), "--timeout", "30",
        ])
        captured = capsys.readouterr()
    finally:
        if node is not None:
            node.stop()
        server.stop()
        store.close()

    assert code == 0, captured.err
    assert "Hello " in captured.out
    assert "cost" in captured.out
    assert captured.out.count("\n") >= 1


def test_ask_json_reports_a_machine_readable_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ask --json` prints one canonical document a program can consume."""
    keyring = Keyring()
    store = CenterStore.open(tmp_path / "center.db")
    config = GatewayConfig(
        host="127.0.0.1",
        port=0,
        database_path=str(tmp_path / "center.db"),
        platform_id="platform-1",
        settlement_key_id="settlement-key-1",
        settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
    )
    service = GatewayService(config=config, store=store, registry=keyring.registry)
    server = GatewayServer(service, config=config)
    server.start()
    node: _Node | None = None
    try:
        store.add_credential("node-token-json", "tenant-a", "node-A", "node", REGISTERED_AT)
        service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )
        now = dt.datetime.now(dt.UTC)
        store.add_invite("code-json", "consumer", "auto", max_uses=1, created_at=now)
        node = _Node(tmp_path, keyring, int(server.url.rsplit(":", 1)[1]), token="node-token-json")
        _wait_until(lambda: server.connected_node_count == 1, what="the node link")

        identity_dir = tmp_path / "identity"
        assert main([
            "join", "--center", server.url, "--invite", "code-json",
            "--config-dir", str(identity_dir), "--subject-id", "consumer-X",
        ]) == 0
        capsys.readouterr()

        code = main([
            "ask", "say hello", "--config-dir", str(identity_dir), "--timeout", "30", "--json",
        ])
        captured = capsys.readouterr()
    finally:
        if node is not None:
            node.stop()
        server.stop()
        store.close()

    assert code == 0, captured.err
    document = json.loads(captured.out)
    assert document["status"] == "SUCCEEDED"
    assert document["request_id"]
    assert document["answer"]


def test_ask_without_an_identity_fails_with_an_actionable_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ask` before `join` explains what to run, without a traceback."""
    empty_dir = tmp_path / "no-identity"
    code = main(["ask", "hello", "--config-dir", str(empty_dir)])

    assert code == 1
    err = capsys.readouterr().err
    assert "join" in err
    assert "Traceback" not in err


def test_join_over_http_is_unauthenticated_but_scoped(tmp_path: Path) -> None:
    """A sanity check that the join endpoint needs no bearer token at all."""
    keyring = Keyring()
    store = CenterStore.open(tmp_path / "center.db")
    config = GatewayConfig(
        host="127.0.0.1", port=0, database_path=str(tmp_path / "center.db"),
        platform_id="platform-1", settlement_key_id="settlement-key-1",
        settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
    )
    service = GatewayService(config=config, store=store, registry=keyring.registry)
    server = GatewayServer(service, config=config)
    server.start()
    try:
        store.add_invite("code-open", "consumer", "auto", max_uses=1, created_at=BASE)
        public_b64, _private = generate_key_pair()
        body = json.dumps({
            "invite_code": "code-open",
            "identity": {"public_key_b64": public_b64},
            "device": None,
        }).encode()
        host, _, port = server.url.split("://", 1)[1].partition(":")
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            connection.request(
                "POST", "/v1/join", body=body,
                headers={"content-type": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read()
        finally:
            connection.close()
        assert response.status == 200
        document = json.loads(raw)
        # The identity is derived, not taken from the (absent) body claim.
        assert document["subject_id"].startswith("consumer-")
        assert document["tenant_id"].startswith("t-")
    finally:
        server.stop()
        store.close()
