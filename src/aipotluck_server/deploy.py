"""Server deployment: the ``server.json`` schema, provisioning, and inspection.

One JSON schema drives the server operator's role. Every file is parsed with
:func:`aipotluck.canonical.loads_strict`, so a float, a repeated key, or a
``NaN`` literal is refused at the boundary — the same rules the wire applies,
because a config that only mostly parses is a config an operator cannot audit.

``server.json`` — one server process::

    {
      "host": "127.0.0.1", "port": 443,
      "database_path": "server.db",
      "platform_id": "platform-1",
      "settlement_key_id": "settlement-key-1",
      "settlement_private_key_b64": "<base64 Ed25519 private key>",
      "certfile": null, "keyfile": null,
      "queue_enabled": true, "max_queue_depth": 100,
      "credentials": [
        {"token": "...", "tenant_id": "tenant-a", "subject_id": "consumer-X",
         "role": "consumer"}
      ],
      "providers": [
        {"device_id": "device-1", "device_key_id": "device-key-1",
         "provider_id": "provider-1", "public_key_b64": "<base64 public key>",
         "demo_float_milli_credits": 5000}
      ],
      "consumer_floats": [{"account_id": "consumer-X", "amount": 100000}]
    }

``queue_enabled`` and ``max_queue_depth`` are optional and govern the dispatch
queue: whether a request nothing can dispatch this instant waits for a node
instead of being refused, and how many such requests the server holds at once.
See `GatewayService`'s configuration for why the default is on. A request that
waits still carries its own deadline, and the sweep that ends an overdue request
is the same one that always ran, so a queued request nothing ever took still ends
``EXPIRED`` with the server's own reason recorded — waiting changes when a
request is answered, never whether it is billed honestly.

An unknown top-level field is refused rather than ignored: a misspelled
``certfile``/``keyfile`` pair would otherwise read as "no TLS configured" and
start a cleartext listener on whatever ``host`` names, and a misspelled
``max_queue_depth`` would silently take the default. The refusal names the
unknown fields and the accepted set.

The node and consumer loaders, the consumer HTTP client, and the shared
config-parsing helpers live in :mod:`aipotluck.deploy` (the client package
this one depends on); ``PROVISIONED_AT`` and `DeploymentError` come from there
too, so both sides date and refuse things the same way.

Secrecy rules
-------------
* A config file's tokens are only ever written into the credential store (as
  digests). No loader logs, and no error message raised here quotes a token
  value: validation messages name fields, not values.
  `ServerDeployment.__repr__` is overridden for the same reason — the default
  dataclass repr would embed ``config``, which carries the settlement private
  key.
* Provisioning is idempotent by design: re-loading an unchanged server config
  re-registers the same bindings (a no-op) and re-funds no float, so a restart
  never double-mints. A *changed* binding for an already-known token or device
  key is refused rather than silently applied.

Known limits (network contract v0.1 §9): ``consumer_floats`` and provider demo
floats mint demo credit; nothing here is a payments integration.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from aipotluck.canonical import base64_encode
from aipotluck.deploy import (
    PROVISIONED_AT,
    DeploymentError,
    load_document,
    optional_bool,
    optional_int,
    reject_unknown_keys,
    require_int,
    require_object_list,
    require_str,
    str_or_none,
)
from aipotluck.errors import PotluckError, UnknownKeyError
from aipotluck.identity import IdentityRegistry, KeyPurpose, load_private_key

from .gateway_server import GatewayServer
from .gateway_service import DEFAULT_MAX_QUEUE_DEPTH, GatewayConfig, GatewayService
from .persistence import ServerStore

if TYPE_CHECKING:
    from .gateway_server import GatewayConfig as _ServerGatewayConfig
    from .gateway_server import GatewayServiceProtocol as _ServerServiceProtocol

_ROLES = frozenset({"consumer", "node"})

#: Top-level keys a ``server.json`` document may carry. The three provisioned
#: lists keep their own entry schemas; this set governs the document itself,
#: where a misspelled key would otherwise read as an absent one.
SERVER_CONFIG_KEYS: Final = frozenset(
    {
        "host",
        "port",
        "database_path",
        "platform_id",
        "settlement_key_id",
        "settlement_private_key_b64",
        "certfile",
        "keyfile",
        "queue_enabled",
        "max_queue_depth",
        "credentials",
        "providers",
        "consumer_floats",
    }
)

@dataclass(frozen=True)
class ServerDeployment:
    """Everything a running server is made of, as one operator handle.

    ``provider_ids`` repeats the provider accounts the config provisioned, so
    ``potluck-server serve`` can report them without re-reading the file or exposing
    the raw document (whose credentials list holds tokens).
    """

    config: GatewayConfig
    service: GatewayService
    server: GatewayServer
    store: ServerStore
    provider_ids: tuple[str, ...] = ()

    def __repr__(self) -> str:
        # Deliberately not the dataclass repr: `config` carries the settlement
        # private key, so rendering it would put a secret into every log line.
        return (
            f"ServerDeployment(platform_id={self.config.platform_id!r}, "
            f"provider_ids={self.provider_ids!r})"
        )


@dataclass(frozen=True)
class ServerInspection:
    """A server's durable state opened for reading, with nothing written.

    Deliberately not a `ServerDeployment`: there is no service and no server,
    because an audit reads durable rows rather than the in-memory books a running
    server keeps. Building a service would replay the ledger and the log first,
    and that replay refuses a non-contiguous log — so the one defect an auditor
    most needs reported would stop the audit instead of appearing in it.
    """

    config: GatewayConfig
    store: ServerStore
    registry: IdentityRegistry

    def close(self) -> None:
        """Release the store's connection."""
        self.store.close()

    def __repr__(self) -> str:
        # Deliberately not the dataclass repr: `config` carries the settlement
        # private key, so rendering it would put a secret into every log line.
        return f"ServerInspection(platform_id={self.config.platform_id!r})"


@dataclass(frozen=True)
class _ProviderPlan:
    """One parsed ``providers`` entry, plus the float it asks for."""

    provider_id: str
    demo_float_milli_credits: int



# --------------------------------------------------------------------------
# Server provisioning
# --------------------------------------------------------------------------


def provision_settlement_key(
    registry: IdentityRegistry,
    *,
    key_id: str,
    platform_id: str,
    private_key_b64: str,
) -> None:
    """Register the platform settlement key, failing closed on bad material.

    The registry holds public keys only, so the public half is derived from the
    configured private half: one source of truth, and a private key that does
    not parse can never reach a service that would only discover the problem
    at the first receipt.

    Raises:
        DeploymentError: If the private key material is not a valid Ed25519
            key, or the key afterwards fails to resolve as an active
            ``platform_settlement`` key. Nothing is started in that case.
    """
    try:
        private_key = load_private_key(private_key_b64)
    except PotluckError as exc:
        raise DeploymentError(
            f"settlement key {key_id!r} could not be provisioned: "
            "settlement_private_key_b64 is not a valid Ed25519 private key; "
            "generate one with `potluck keygen` and restart"
        ) from exc
    public_key_b64 = base64_encode(private_key.public_key().public_bytes_raw())
    registry.register_key(
        key_id, platform_id, "platform_settlement", public_key_b64, PROVISIONED_AT
    )
    # Fail closed: refuse to start unless the settlement key is registered,
    # active, and bound to the platform settlement purpose. The gateway signs
    # every receipt with it; serving without it would mint unverifiable books.
    try:
        registered = registry.get_key(key_id)
    except UnknownKeyError as exc:
        raise DeploymentError(
            f"settlement key {key_id!r} is not registered in the identity registry "
            "at startup; refusing to serve a server that cannot sign receipts"
        ) from exc
    if registered.purpose != "platform_settlement" or registered.owner_id != platform_id:
        raise DeploymentError(
            f"settlement key {key_id!r} is registered as "
            f"{registered.purpose!r} for {registered.owner_id!r}, not as the "
            f"platform settlement key of {platform_id!r}"
        )
    if not registered.is_valid_at(dt.datetime.now(dt.UTC)):
        raise DeploymentError(
            f"settlement key {key_id!r} is registered but not valid now; refusing to start"
        )


def provision_providers(
    registry: IdentityRegistry, entries: list[dict[str, Any]], context: str
) -> list[_ProviderPlan]:
    """Register every provider's device key and bind device to provider.

    This is the production path through
    `IdentityRegistry.register_device_key`: registering the key and binding the
    provider are one operation, so a key can never exist unbound and claim
    another provider's revenue.

    Re-provisioning the identical binding is a no-op. A *changed* binding for a
    known device key — a different owner, purpose, or public key — is refused
    rather than silently applied, because `register_key` alone would keep the
    old public key and an operator rotating a device key would never learn that
    the server still verifies against the previous one.

    Raises:
        DeploymentError: If an entry is malformed, or a known key is being
            re-provisioned with different material.
    """
    plans: list[_ProviderPlan] = []
    for index, entry in enumerate(entries):
        entry_context = f"{context}: providers[{index}]"
        device_id = require_str(entry, "device_id", entry_context)
        device_key_id = require_str(entry, "device_key_id", entry_context)
        provider_id = require_str(entry, "provider_id", entry_context)
        public_key_b64 = require_str(entry, "public_key_b64", entry_context)
        demo_float = require_int(entry, "demo_float_milli_credits", entry_context)
        if demo_float < 0:
            raise DeploymentError(
                f"{entry_context}: field 'demo_float_milli_credits' must be non-negative"
            )
        try:
            existing = registry.get_key(device_key_id)
        except UnknownKeyError:
            existing = None
        if existing is not None and (
            existing.owner_id != device_id
            or existing.purpose != "provider_device"
            or existing.public_key_b64 != public_key_b64
        ):
            raise DeploymentError(
                f"{entry_context}: device key {device_key_id!r} is already provisioned "
                f"as {existing.purpose!r} for {existing.owner_id!r} with different "
                "public key material; rotating a device key is a deliberate, audited "
                "operation, not a config edit"
            )
        registry.register_device_key(
            key_id=device_key_id,
            device_id=device_id,
            provider_id=provider_id,
            public_key_b64=public_key_b64,
            registered_at=PROVISIONED_AT,
        )
        plans.append(
            _ProviderPlan(
                provider_id=provider_id, demo_float_milli_credits=demo_float
            )
        )
    return plans


def _provision_credentials(store: ServerStore, entries: list[dict[str, Any]], context: str) -> None:
    """Register every credential through `ServerStore.add_credential`.

    Re-adding an identical binding is a no-op; a different binding for a known
    token digest raises the store's `ConflictError`, which is surfaced as-is —
    a token must never silently acquire a second identity.

    Raises:
        DeploymentError: If an entry is malformed or names an unknown role.
        ConflictError: If a known token is re-provisioned with a different
            tenant, subject, or role.
    """
    for index, entry in enumerate(entries):
        entry_context = f"{context}: credentials[{index}]"
        token = require_str(entry, "token", entry_context)
        tenant_id = require_str(entry, "tenant_id", entry_context)
        subject_id = require_str(entry, "subject_id", entry_context)
        role = require_str(entry, "role", entry_context)
        if role not in _ROLES:
            raise DeploymentError(
                f"{entry_context}: field 'role' must be one of {sorted(_ROLES)}, "
                f"not {role!r}"
            )
        store.add_credential(token, tenant_id, subject_id, role, PROVISIONED_AT)


def replay_dynamic_identities(registry: IdentityRegistry, store: ServerStore) -> None:
    """Rebuild the registry's dynamic identities from the store's rows.

    `server.json` carries only the provisioned credentials and provider device
    keys. An invited identity lives solely in the ``identities`` table, so this
    replay is what carries it across a restart. A revoked row is registered and
    then revoked, so its history survives exactly as a provisioned key's does.

    Args:
        registry: The registry to populate. Keys provisioned from the config are
            already present; an identical binding here is a no-op.
        store: The server store holding the persisted identities.

    Raises:
        IdentityBindingError: If a stored identity disagrees with a key already
            in the registry (a config and a join naming the same key id
            differently); refusing rather than picking a winner is deliberate.
    """
    for record in store.identities():
        # A ``provider_device`` row *with* a provider is a contribution device
        # and must carry its binding, or it could never settle. A
        # ``provider_device`` row *without* one is a node's own identity key —
        # minted by a node invite, never used to sign usage — so it is restored
        # as a plain trusted key rather than refused, which is what lets a
        # joined node survive a restart.
        if record.purpose == "provider_device" and record.provider_id is not None:
            registry.register_device_key(
                key_id=record.key_id,
                device_id=record.owner_id,
                provider_id=record.provider_id,
                public_key_b64=record.public_key_b64,
                registered_at=record.registered_at,
            )
        else:
            registry.register_key(
                record.key_id,
                record.owner_id,
                cast("KeyPurpose", record.purpose),
                record.public_key_b64,
                record.registered_at,
            )
        if record.revoked_at is not None:
            registry.revoke_key(record.key_id, record.revoked_at)


def _already_issued(store: ServerStore, account_id: str) -> bool:
    """Whether the replay log already records an issuance into `account_id`.

    Funding is idempotent across restarts because it consults the same ordered
    log the rebuilt ledger replays: an account funded once is never funded
    again, so restarting a server cannot double-mint its demo floats.
    """
    return any(
        kind == "issue" and payload.get("account_id") == account_id
        for _seq, kind, payload in store.ledger_events()
    )


def _fund_floats(
    service: GatewayService,
    store: ServerStore,
    providers: list[_ProviderPlan],
    consumer_floats: list[dict[str, Any]],
    context: str,
) -> None:
    """Mint the configured demo floats through `GatewayService.fund_account`.

    Provider demo floats land in the provider's own account as
    ``provider_available`` credit; consumer floats land in the named account as
    ``consumer_available`` credit. Both are recorded as explicit ledger events,
    so a rebuilt service replays the same books. An already-issued account is
    skipped, which is what makes a restart a no-op rather than a double mint.

    Raises:
        DeploymentError: If a consumer float entry is malformed.
    """
    for plan in providers:
        if plan.demo_float_milli_credits > 0 and not _already_issued(store, plan.provider_id):
            service.fund_account(
                account_id=plan.provider_id,
                kind="provider_available",
                amount=plan.demo_float_milli_credits,
                now=PROVISIONED_AT,
            )
    for index, entry in enumerate(consumer_floats):
        entry_context = f"{context}: consumer_floats[{index}]"
        account_id = require_str(entry, "account_id", entry_context)
        amount = require_int(entry, "amount", entry_context)
        if amount <= 0:
            raise DeploymentError(
                f"{entry_context}: field 'amount' must be a positive integer"
            )
        if not _already_issued(store, account_id):
            service.fund_account(
                account_id=account_id, kind="consumer_available", amount=amount, now=PROVISIONED_AT
            )


def load_server(path: str | Path, *, start: bool = False) -> ServerDeployment:
    """Load, provision, and optionally start a server from its JSON file.

    The store is opened, every credential and provider device key in the config
    is provisioned idempotently, **every dynamically joined identity in the
    store is replayed into the registry**, the settlement key is verified
    fail-closed, the service is built over the rebuilt ledger, the configured
    floats are funded exactly once, and the server is constructed (and bound when
    ``start=True``). On any failure the partially built store is closed before
    the error propagates; nothing is left half-provisioned on the socket side.

    Why the identity replay matters: an invited consumer exists only in the
    ``identities`` table, never in ``server.json``. Rebuilding the registry from
    the store is what makes that consumer keep authenticating after a restart
    without any config edit — the property the invite flow exists to provide.

    Args:
        path: The ``server.json`` file.
        start: Whether to bind the listener. ``port: 0`` asks the OS for an
            ephemeral port, which is what makes tests and smoke runs cheap.

    Returns:
        The deployment handle: config, service, server, store, and the ids of
        the providers the config provisioned.

    Raises:
        DeploymentError: On any malformed configuration, bad settlement key
            material, or a refused URL pair.
        ConflictError: If a token is re-provisioned with a different binding.
    """
    config_path = Path(path)
    context = f"server configuration {config_path}"
    config, credentials, provider_entries, consumer_floats = _server_parts(
        load_document(config_path), context
    )
    store = ServerStore.open(config.database_path)
    try:
        registry = IdentityRegistry()
        provision_settlement_key(
            registry,
            key_id=config.settlement_key_id,
            platform_id=config.platform_id,
            private_key_b64=config.settlement_private_key_b64,
        )
        plans = provision_providers(registry, provider_entries, context)
        _provision_credentials(store, credentials, context)
        replay_dynamic_identities(registry, store)
        service = GatewayService(config=config, store=store, registry=registry)
        _fund_floats(service, store, plans, consumer_floats, context)
        # `GatewayService` satisfies the server's structural protocol at
        # runtime — the server calls `admit_request` only with the record form
        # the domain method accepts — and the domain `GatewayConfig` carries
        # every attribute the server reads. The casts exist because the
        # protocol's nominal annotations are narrower than the domain
        # signatures; they hold for exactly the call pattern used here.
        server = GatewayServer(
            cast("_ServerServiceProtocol", service),
            config=cast("_ServerGatewayConfig", config),
        )
        if start:
            server.start()
    except BaseException:
        store.close()
        raise
    return ServerDeployment(
        config=config,
        service=service,
        server=server,
        store=store,
        provider_ids=tuple(plan.provider_id for plan in plans),
    )


def _server_parts(
    document: dict[str, Any], context: str
) -> tuple[GatewayConfig, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse ``server.json`` into its gateway config and three provisioned lists.

    Shared by `load_server` and `load_server_for_inspection` so a field is read
    and validated in exactly one place: an audit command that parsed the same
    file slightly differently would be auditing a server the operator does not
    run.

    Returns:
        ``(config, credentials, provider_entries, consumer_floats)``.

    Raises:
        DeploymentError: On any missing or malformed field, a key outside
            ``SERVER_CONFIG_KEYS``, or a half-configured TLS pair.
    """
    reject_unknown_keys(document, SERVER_CONFIG_KEYS, context)
    host = require_str(document, "host", context)
    port = require_int(document, "port", context)
    database_path = require_str(document, "database_path", context)
    platform_id = require_str(document, "platform_id", context)
    settlement_key_id = require_str(document, "settlement_key_id", context)
    settlement_private_key_b64 = require_str(
        document, "settlement_private_key_b64", context
    )
    certfile = str_or_none(document, "certfile", context)
    keyfile = str_or_none(document, "keyfile", context)
    if (certfile is None) != (keyfile is None):
        raise DeploymentError(
            f"{context}: certfile and keyfile must be configured together, "
            "or both null for cleartext HTTP"
        )
    queue_enabled = optional_bool(document, "queue_enabled", context, True)
    max_queue_depth = optional_int(
        document, "max_queue_depth", context, DEFAULT_MAX_QUEUE_DEPTH
    )
    if max_queue_depth < 0:
        raise DeploymentError(
            f"{context}: field 'max_queue_depth' must be >= 0, got {max_queue_depth}"
        )
    config = GatewayConfig(
        host=host,
        port=port,
        database_path=database_path,
        platform_id=platform_id,
        settlement_key_id=settlement_key_id,
        settlement_private_key_b64=settlement_private_key_b64,
        certfile=certfile,
        keyfile=keyfile,
        queue_enabled=queue_enabled,
        max_queue_depth=max_queue_depth,
    )
    return (
        config,
        require_object_list(document, "credentials", context),
        require_object_list(document, "providers", context),
        require_object_list(document, "consumer_floats", context),
    )


def load_server_for_inspection(path: str | Path) -> ServerInspection:
    """Open a server for reading: its durable store and its trusted-key registry.

    This is `load_server` minus every step that writes and every step that
    serves. No credential is provisioned, no float is funded, no listener is
    constructed and no in-memory book is rebuilt, so an operator's audit command
    can be pointed at a live server's database without changing the books it is
    auditing — and without a defect in those books stopping the audit before it
    reports anything.

    The registry is built the same way `load_server` builds it, because a
    verifier that trusted a different set of keys would be verifying a different
    platform: the settlement key's public half is derived from the configured
    private half, the provider device keys come from the configuration, and every
    dynamically joined identity is replayed from the store.

    The settlement private key is read only to derive its public half; the
    returned handle renders neither, and nothing here prints either.

    The database has to exist already, and nothing here creates it. An audit
    pointed at a ``database_path`` that names nothing must report that, because
    the empty database it would otherwise open has no records and therefore no
    discrepancies either: "the server's books are consistent" and "there are no
    books" would print the same verdict.

    Args:
        path: The ``server.json`` file.

    Returns:
        The inspection handle. Its `store` must be closed by the caller.

    Raises:
        DeploymentError: On malformed configuration or bad settlement key
            material.
        PotluckError: If the configured ``database_path`` names no database.
    """
    config_path = Path(path)
    context = f"server configuration {config_path}"
    config, _credentials, provider_entries, _floats = _server_parts(
        load_document(config_path), context
    )
    store = ServerStore.open_existing(config.database_path)
    try:
        registry = IdentityRegistry()
        provision_settlement_key(
            registry,
            key_id=config.settlement_key_id,
            platform_id=config.platform_id,
            private_key_b64=config.settlement_private_key_b64,
        )
        provision_providers(registry, provider_entries, context)
        replay_dynamic_identities(registry, store)
    except BaseException:
        store.close()
        raise
    return ServerInspection(config=config, store=store, registry=registry)


