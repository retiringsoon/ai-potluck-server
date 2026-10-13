"""F01 · a node link is bound to the credential that authenticated it.

The transport authenticates a *credential*; every id in `node.hello` is a claim
the peer typed. Before this suite's subject was fixed, `register_node` trusted
those claims: a contributor holding one valid node token could dial with another
node's device id, device key id, provider id *and* node id, and be answered with
a `hello.ack` — displacing the victim's node record and its live connection,
since node ids key both routing and the connection table.

Each test here pins one half of the acceptance in
``docs/release-fix-plan.zh-CN.md`` §2:

* a token cannot claim another node's device, another node's node id, or a
  device the server bound to a different credential — within one tenant or
  across tenants;
* a refused hello changes nothing: not the claimed node's record, not its
  connection, not an uninvolved third node's;
* the legitimate paths still work end to end — an invited node connecting,
  reconnecting and receiving work, and an operator-provisioned credential
  dialing as its own subject;
* the refusal also holds over a real loopback WebSocket handshake, so it is not
  an artefact of calling the service function directly.

Everything drives a real `GatewayService` over a real `ServerStore`; the socket
tests additionally run a real `GatewayServer`. Time comes from the wall clock,
as it does in ``test_end_to_end_network.py``, because the transport resolves a
bearer token at the instant a link opens.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from aipotluck.errors import IdentityBindingError
from aipotluck.identity import generate_key_pair
from aipotluck.websocket import ClientConnection, WebSocketClosed
from aipotluck.wire import AttemptOffer, Envelope, NodeHello, NodePolicy, user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import Credential, NodeRecord, ServerStore

MODEL = "coding-pool"
TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
#: Keys are registered in the past, so a hello is never refused for key age by a
#: clock that happens to sit before a fixed test timestamp.
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
#: The subject an operator's hand-written ``credentials[]`` entry names, and the
#: node id the documented ``node.json`` sample for that route dials with. Its
#: device is the one `conftest.Keyring` registers and binds to a provider, which
#: is what an operator's ``providers[]`` entry does at startup.
LEGACY_SUBJECT = "node-A"
LEGACY_TOKEN = "node-token-provisioned-by-hand"
LEGACY_DEVICE = ("device-A", "device-key-A", "provider-A")


def _hello(
    *,
    node_id: str,
    device_id: str,
    device_key_id: str,
    provider_id: str,
    share_enabled: bool = True,
) -> NodeHello:
    """Build a well-formed hello out of the four identity claims it carries."""
    return NodeHello(
        node_id=node_id,
        device_id=device_id,
        device_key_id=device_key_id,
        provider_id=provider_id,
        adapter_name="mock-adapter",
        model=MODEL,
        policy=NodePolicy(
            share_enabled=share_enabled,
            max_concurrency=2,
            max_local_reserved_milli_credits=0,
        ),
    )


def _legacy_hello(**claims: str) -> NodeHello:
    """Build the hello the operator-provisioned route's ``node.json`` documents.

    A claim passed here replaces one field of that document, which is how a test
    states "this credential lied about exactly this id".
    """
    device_id, device_key_id, provider_id = LEGACY_DEVICE
    fields = {
        "node_id": LEGACY_SUBJECT,
        "device_id": device_id,
        "device_key_id": device_key_id,
        "provider_id": provider_id,
    }
    fields.update(claims)
    return _hello(**fields)


@dataclass(frozen=True)
class JoinedNode:
    """One node an invite minted: its credential and the ids the server derived.

    `node_id` is the device id on purpose — that is what the contributor wizard
    writes into ``node.json``, and it is the only node id `register_node` accepts
    from a join-minted credential.
    """

    token: str
    credential: Credential
    node_id: str
    device_id: str
    device_key_id: str
    provider_id: str

    def hello(self, *, share_enabled: bool = True, **claims: str) -> NodeHello:
        """Build this node's own hello, with any single claim replaced."""
        fields = {
            "node_id": self.node_id,
            "device_id": self.device_id,
            "device_key_id": self.device_key_id,
            "provider_id": self.provider_id,
        }
        fields.update(claims)
        return _hello(share_enabled=share_enabled, **fields)


class Server:
    """A real service over a real store, with invites minted on demand."""

    def __init__(self, tmp_path: Path) -> None:
        self.keyring = Keyring()
        self.store = ServerStore.open(tmp_path / "server.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "server.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=self.keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=self.keyring.registry
        )
        self.outbox: dict[str, list[Envelope]] = {}
        #: Counts the invites minted, so every code is single-use and unique.
        self._invites = 0
        self.service.fund_account(
            account_id="consumer-X",
            kind="consumer_available",
            amount=100_000,
            now=self.moment(),
        )

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    @staticmethod
    def moment() -> dt.datetime:
        """Return the instant an operation should be stamped with."""
        return dt.datetime.now(dt.UTC)

    def join_node(self, *, tenant: str = "friends") -> JoinedNode:
        """Invite one node into `tenant`, redeem it, and return what it holds.

        The invite is minted here, single-use and with a fresh code every call,
        because a code spent by one join cannot be spent by the next node.
        """
        self._invites += 1
        code = f"code-node-{self._invites}"
        self.store.add_invite(
            code,
            "node",
            tenant,
            max_uses=1,
            created_at=REGISTERED_AT,
            quota_milli_credits=0,
        )
        node_public, _node_private = generate_key_pair()
        device_public, _device_private = generate_key_pair()
        result = self.service.join(
            invite_code=code,
            identity={"public_key_b64": node_public},
            device={"public_key_b64": device_public},
            server_url="http://server.test",
            now=self.moment(),
        )
        token = result.node_token
        device_id = result.device_id
        device_key_id = result.device_key_id
        provider_id = result.provider_id
        assert token is not None and device_id is not None
        assert device_key_id is not None and provider_id is not None
        credential = self.store.resolve_credential(token, self.moment())
        assert credential is not None and credential.device_id == device_id
        return JoinedNode(
            token=token,
            credential=credential,
            node_id=device_id,
            device_id=device_id,
            device_key_id=device_key_id,
            provider_id=provider_id,
        )

    def provision_node(self, subject_id: str, token: str) -> Credential:
        """Register a credential the way an operator's ``server.json`` does.

        This is the pre-registration route: the entry names no device, so the
        credential carries no device binding and its subject is the node id it
        may dial as.
        """
        self.store.add_credential(token, TENANT, subject_id, "node", REGISTERED_AT)
        credential = self.store.resolve_credential(token, self.moment())
        assert credential is not None and credential.device_id is None
        return credential

    def sink(self, node_id: str) -> Callable[[Envelope], None]:
        """Return an `enqueue` that appends to one node's outbox."""
        return lambda envelope: self.outbox.setdefault(node_id, []).append(envelope)

    def take(self, node_id: str) -> list[Envelope]:
        """Return and clear the envelopes waiting for one node."""
        drained, self.outbox[node_id] = self.outbox.get(node_id, []), []
        return drained

    def register(self, credential: Credential, hello: NodeHello) -> None:
        """Open a node link, buffering what the server sends into an outbox."""
        self.outbox[hello.node_id] = []
        self.service.register_node(
            credential=credential,
            hello=hello,
            enqueue=self.sink(hello.node_id),
            now=self.moment(),
        )

    def admit(self, request_id: str, idempotency_key: str) -> None:
        """Admit one signed consumer request, which offers it to a live node."""
        moment = self.moment()
        messages = (user_message("write a haiku about bindings"),)
        self.service.admit_request(
            credential=Credential(
                tenant_id=TENANT,
                subject_id="consumer-X",
                role="consumer",
                account_id="consumer-X",
            ),
            idempotency_key=idempotency_key,
            messages=messages,
            authorization=signed_authorization(
                self.keyring,
                request_id=request_id,
                messages=messages,
                model=MODEL,
                issued_at=moment - dt.timedelta(minutes=1),
                expires_at=moment + dt.timedelta(minutes=10),
            ),
            model=MODEL,
            max_charge_milli_credits=20_000,
            delivery_mode="buffered_complete",
            max_attempts=2,
            now=moment,
        )

    def offers(self, node_id: str) -> list[AttemptOffer]:
        """Return the offers waiting in one node's outbox."""
        return [
            AttemptOffer.from_payload(envelope.payload)
            for envelope in self.outbox.get(node_id, [])
            if envelope.type == "attempt.offer"
        ]


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    """Return a server over a fresh store, closed at the end of the test."""
    built = Server(tmp_path)
    yield built
    built.close()


def _two_joined_nodes(
    server: Server, *, tenants: tuple[str, str]
) -> tuple[JoinedNode, JoinedNode]:
    """Join two nodes, one invite each, into the tenants named."""
    first, second = tenants
    return server.join_node(tenant=first), server.join_node(tenant=second)


def _types(outbox: list[Envelope]) -> list[str]:
    """Return the envelope types an outbox holds, for a readable assertion."""
    return [envelope.type for envelope in outbox]


def _impersonate(server: Server, attacker: JoinedNode, victim: JoinedNode) -> None:
    """Dial in as `attacker` claiming every id of `victim`, into a fresh outbox.

    This is the reproduced attack: a real credential the server minted, a hello
    naming somebody else, and none of the victim's key material. The outbox is
    opened first so a caller can assert afterwards that nothing was ever sent
    into it.
    """
    server.outbox["attacker"] = []
    server.service.register_node(
        credential=attacker.credential,
        hello=attacker.hello(
            node_id=victim.node_id,
            device_id=victim.device_id,
            device_key_id=victim.device_key_id,
            provider_id=victim.provider_id,
        ),
        enqueue=server.sink("attacker"),
        now=server.moment(),
    )


# --------------------------------------------------------------------------- #
# A token speaks for one node: the impersonation the review reproduced
# --------------------------------------------------------------------------- #


def test_a_node_token_cannot_claim_another_nodes_device_identity(
    server: Server,
) -> None:
    """A's real token plus B's device, device key and provider is refused.

    Both nodes share one tenant, the shape an operator mints for a friends
    community, so nothing but the credential's own binding separates them. The
    first refusal keeps A's node id and claims only B's device half; the second
    is the attack exactly as reproduced, claiming B's node id as well.
    """
    alice, bob = _two_joined_nodes(server, tenants=("friends", "friends"))
    assert alice.credential.tenant_id == bob.credential.tenant_id
    server.outbox["attacker"] = []
    enqueue = server.sink("attacker")

    # Claiming B's device while still naming A's own node id...
    with pytest.raises(IdentityBindingError, match="is bound to device"):
        server.service.register_node(
            credential=alice.credential,
            hello=alice.hello(
                device_id=bob.device_id,
                device_key_id=bob.device_key_id,
                provider_id=bob.provider_id,
            ),
            enqueue=enqueue,
            now=server.moment(),
        )
    assert server.outbox["attacker"] == [], "a refused hello is answered with nothing"

    # ...and the attack exactly as reproduced, claiming B's node id as well.
    with pytest.raises(IdentityBindingError):
        _impersonate(server, alice, bob)
    assert server.outbox["attacker"] == []
    assert server.store.get_node(bob.node_id) is None


def test_a_node_token_cannot_claim_another_nodes_node_id(server: Server) -> None:
    """A's token with A's own device but B's node id is refused too.

    The node id is not a free label: it keys the live-connection table and every
    dispatch, so claiming B's is how a trusted hello becomes a hijacked link and
    a stolen task feed.
    """
    alice, bob = _two_joined_nodes(server, tenants=("friends", "friends"))

    attacker: list[Envelope] = []
    with pytest.raises(IdentityBindingError, match="speaks for node"):
        server.service.register_node(
            credential=alice.credential,
            hello=alice.hello(node_id=bob.node_id),
            enqueue=attacker.append,
            now=server.moment(),
        )
    assert attacker == []


def test_impersonation_is_refused_across_tenants_as_well_as_within_one(
    server: Server,
) -> None:
    """A tenant boundary is not what stops this, so neither may be the fix.

    One tenant is the community shape the runbook mints; two tenants is what an
    operator who separates communities gets. The binding is read from the
    credential, never from the tenant, so the answer must be the same both ways.
    """
    for tenants in (("friends", "friends"), (TENANT, OTHER_TENANT)):
        alice, bob = _two_joined_nodes(server, tenants=tenants)
        assert (alice.credential.tenant_id == bob.credential.tenant_id) == (
            tenants[0] == tenants[1]
        )
        with pytest.raises(IdentityBindingError):
            _impersonate(server, alice, bob)


def test_a_refused_hello_leaves_every_other_node_exactly_as_it_was(
    server: Server,
) -> None:
    """The victim's record, its link and an uninvolved third node all survive.

    Asserted against a snapshot taken before the refusal, and then asserted
    again the way the victim would notice it: work admitted afterwards still
    reaches the victim's own sink, which is precisely what a displaced enqueue
    would have stolen.
    """
    alice, bob = _two_joined_nodes(server, tenants=("friends", "friends"))
    carol = server.join_node()
    server.register(bob.credential, bob.hello())
    # Carol is connected but not sharing, so the dispatch below has exactly one
    # candidate and "the offer still reaches the victim" cannot be decided by
    # which of two random node ids sorts first.
    server.register(carol.credential, carol.hello(share_enabled=False))
    bob_before: NodeRecord | None = server.store.get_node(bob.node_id)
    carol_before: NodeRecord | None = server.store.get_node(carol.node_id)
    assert bob_before is not None and bob_before.connected
    server.take(bob.node_id)

    with pytest.raises(IdentityBindingError):
        _impersonate(server, alice, bob)

    assert server.store.get_node(bob.node_id) == bob_before
    assert server.store.get_node(carol.node_id) == carol_before
    assert server.outbox["attacker"] == []
    assert server.outbox[bob.node_id] == [], "the victim was told nothing new"

    server.admit("R-still-bobs", "idem-still-bobs")
    assert [offer.resource_id for offer in server.offers(bob.node_id)] == [bob.node_id]
    assert server.outbox["attacker"] == []


# --------------------------------------------------------------------------- #
# The legitimate invited path: connect, reconnect, receive work
# --------------------------------------------------------------------------- #


def test_an_invited_node_connects_reconnects_and_receives_work(
    server: Server,
) -> None:
    """A token plus its own identity is accepted, again and again.

    The second registration is a reconnect: a fresh sink replaces the old one,
    so work admitted afterwards must arrive on the *new* link. Binding a hello to
    its credential has to make impersonation impossible without making a node's
    own re-handshake suspicious.
    """
    alice = server.join_node()

    server.register(alice.credential, alice.hello())
    assert _types(server.take(alice.node_id)) == ["hello.ack"]

    server.register(alice.credential, alice.hello())
    assert _types(server.take(alice.node_id)) == ["hello.ack"]
    record = server.store.get_node(alice.node_id)
    assert record is not None and record.connected and record.share_enabled

    server.admit("R-alice", "idem-alice")
    assert [offer.resource_id for offer in server.offers(alice.node_id)] == [
        alice.node_id
    ]


# --------------------------------------------------------------------------- #
# The operator-provisioned path: one subject, one node id, no free claims
# --------------------------------------------------------------------------- #


def test_a_pre_registered_node_dials_as_its_own_subject(server: Server) -> None:
    """The hand-written ``credentials[]`` route still works, and still gets work.

    An operator-provisioned credential names no device, so the constraint that
    replaces the device binding is its subject: the documented ``node.json``
    sample dials with the credential's own subject as its ``node_id`` and with a
    device the operator registered in ``providers[]``.
    """
    credential = server.provision_node(LEGACY_SUBJECT, LEGACY_TOKEN)
    hello = _legacy_hello()
    assert (hello.node_id, hello.device_id, hello.provider_id) == (
        LEGACY_SUBJECT,
        LEGACY_DEVICE[0],
        LEGACY_DEVICE[2],
    )

    server.register(credential, hello)
    assert _types(server.take(LEGACY_SUBJECT)) == ["hello.ack"]
    assert server.store.get_node(LEGACY_SUBJECT) is not None

    server.admit("R-legacy", "idem-legacy")
    assert [offer.resource_id for offer in server.offers(LEGACY_SUBJECT)] == [
        LEGACY_SUBJECT
    ]


def test_a_pre_registered_credential_cannot_take_another_node_id(
    server: Server,
) -> None:
    """Two provisioned credentials are two nodes, not one node and a spare token.

    The missing device column is not a licence: whatever else a hello claims,
    its ``node_id`` has to be the subject the operator bound that token to.
    """
    first = server.provision_node(LEGACY_SUBJECT, LEGACY_TOKEN)
    second = server.provision_node("node-B", "node-token-second")
    server.register(first, _legacy_hello())
    before = server.store.get_node(LEGACY_SUBJECT)
    server.take(LEGACY_SUBJECT)

    attacker: list[Envelope] = []
    with pytest.raises(IdentityBindingError, match="speaks for node"):
        server.service.register_node(
            credential=second,
            hello=_legacy_hello(node_id=LEGACY_SUBJECT),
            enqueue=attacker.append,
            now=server.moment(),
        )

    assert attacker == []
    assert server.store.get_node(LEGACY_SUBJECT) == before
    assert server.outbox[LEGACY_SUBJECT] == []


def test_a_pre_registered_credential_cannot_claim_a_joined_nodes_device(
    server: Server,
) -> None:
    """A device the server bound to a credential belongs to that credential.

    The provisioned path has no device column to compare against, so without
    this rule a hand-written token could still dial as an invited node's device
    and provider — the same impersonation, entered through the other door. The
    check reads the binding the join wrote, and it leaves a device no credential
    owns (the operator's own ``providers[]`` entry) free for its node to claim.
    """
    alice = server.join_node()
    legacy = server.provision_node(LEGACY_SUBJECT, LEGACY_TOKEN)

    attacker: list[Envelope] = []
    with pytest.raises(IdentityBindingError, match="may not dial as it"):
        server.service.register_node(
            credential=legacy,
            hello=_legacy_hello(
                device_id=alice.device_id,
                device_key_id=alice.device_key_id,
                provider_id=alice.provider_id,
            ),
            enqueue=attacker.append,
            now=server.moment(),
        )

    assert attacker == []
    assert server.store.get_node(LEGACY_SUBJECT) is None


# --------------------------------------------------------------------------- #
# The same rules over a real loopback WebSocket handshake
# --------------------------------------------------------------------------- #


def _hello_envelope(hello: NodeHello) -> Envelope:
    """Wrap a hello the way a connector puts it on the wire."""
    return Envelope(type="node.hello", payload=hello.to_payload())


def _open_link(transport: GatewayServer, token: str) -> ClientConnection:
    """Dial the node link with a bearer token and complete the handshake."""
    return ClientConnection.connect(
        transport.node_url, headers={"Authorization": f"Bearer {token}"}
    )


def test_a_real_node_link_refuses_an_impersonating_hello(tmp_path: Path) -> None:
    """Over real sockets the victim stays up and the attacker is told and closed.

    A real `GatewayServer` on loopback, two nodes joined through the real invite
    flow, and B's link open with a real handshake before A dials in claiming
    B's identity. What has to happen is what the service-level tests cannot show
    on their own: the transport refuses the link *before* binding it, so the
    victim's connection is never replaced and never closed, and the attacker
    receives a `protocol.error` and a policy-violation close instead of a
    `hello.ack`. B then reconnects on its own token, the legitimate path the
    refusal must not have broken.
    """
    server = Server(tmp_path)
    transport = GatewayServer(server.service, config=server.config)
    transport.start()
    try:
        alice, bob = _two_joined_nodes(server, tenants=("friends", "friends"))
        victim = _open_link(transport, bob.token)
        try:
            victim.send_text(_hello_envelope(bob.hello()).encode())
            ack = Envelope.decode(victim.recv_text(timeout=10.0))
            assert ack.type == "hello.ack"
            assert ack.payload["node_id"] == bob.node_id
            assert transport.connected_node_count == 1
            bob_before = server.store.get_node(bob.node_id)

            attacker = _open_link(transport, alice.token)
            try:
                attacker.send_text(
                    _hello_envelope(
                        alice.hello(
                            node_id=bob.node_id,
                            device_id=bob.device_id,
                            device_key_id=bob.device_key_id,
                            provider_id=bob.provider_id,
                        )
                    ).encode()
                )
                refusal = Envelope.decode(attacker.recv_text(timeout=10.0))
                assert refusal.type == "protocol.error"
                assert refusal.payload["code"] == "hello_refused"
                with pytest.raises(WebSocketClosed) as closed:
                    attacker.recv_text(timeout=10.0)
                assert closed.value.code == 1008
            finally:
                attacker.close()

            # The refused hello bound nothing, displaced nothing, closed nothing.
            assert transport.connected_node_count == 1
            assert server.store.get_node(bob.node_id) == bob_before

            # Work still reaches the victim over its own socket.
            server.admit("R-real-socket", "idem-real-socket")
            offer = Envelope.decode(victim.recv_text(timeout=10.0))
            assert offer.type == "attempt.offer"
            assert AttemptOffer.from_payload(offer.payload).resource_id == bob.node_id

            # And the victim can still reconnect as itself, on the same link
            # object a connector would reopen with.
            reopened = _open_link(transport, bob.token)
            try:
                reopened.send_text(_hello_envelope(bob.hello()).encode())
                reconnect = Envelope.decode(reopened.recv_text(timeout=10.0))
                assert reconnect.type == "hello.ack", reconnect.payload
            finally:
                reopened.close()
        finally:
            victim.close()
    finally:
        transport.stop()
        server.close()


def test_a_real_node_link_accepts_the_identity_its_token_carries(
    tmp_path: Path,
) -> None:
    """Positive control: a matching hello is accepted over the real handshake.

    A refusal that closed every link would satisfy the negative test above, so
    both legitimate routes are asserted to complete a real handshake — an invited
    node dialing as its device, and an operator-provisioned node dialing as its
    subject with a device from ``providers[]``.
    """
    server = Server(tmp_path)
    transport = GatewayServer(server.service, config=server.config)
    transport.start()
    try:
        alice = server.join_node()
        server.provision_node(LEGACY_SUBJECT, LEGACY_TOKEN)
        links = ((alice.token, alice.hello()), (LEGACY_TOKEN, _legacy_hello()))
        for token, hello in links:
            link = _open_link(transport, token)
            try:
                link.send_text(_hello_envelope(hello).encode())
                ack = Envelope.decode(link.recv_text(timeout=10.0))
                assert ack.type == "hello.ack", ack.payload
                assert ack.payload["node_id"] == hello.node_id
            finally:
                link.close()
        assert server.store.get_node(alice.node_id) is not None
        assert server.store.get_node(LEGACY_SUBJECT) is not None
    finally:
        transport.stop()
        server.close()
