"""Shared fixtures for the test suite."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from aipotluck.allocation import AllocationContract
from aipotluck.canonical import canonical_digest
from aipotluck.identity import IdentityRegistry, generate_key_pair, load_private_key
from aipotluck.ledger import Ledger
from aipotluck.metering import Measurement, NormalizedUsage

CONSUMER_KEY = ("consumer-key-1", "consumer-X", "consumer")
CONSUMER_KEY_Y = ("consumer-key-2", "consumer-Y", "consumer")
DEVICE_KEY_A = ("device-key-A", "device-A", "provider_device")
DEVICE_KEY_B = ("device-key-B", "device-B", "provider_device")
PLATFORM_KEY = ("settlement-key-1", "platform-1", "platform_settlement")

#: Keys are registered at a fixed past instant rather than at wall-clock now.
#: `is_valid_at` refuses a record dated before its key was registered, so
#: registering at `now()` made the suite pass only while the wall clock happened
#: to sit after every fixed test timestamp — it went red two days after it was
#: written. Pinning registration time makes the tests hermetic.
KEY_REGISTRATION_TIME = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


class Keyring:
    """Holds generated keys and their registry bindings for a test."""

    def __init__(self, registered_at: dt.datetime | None = None) -> None:
        self.registry = IdentityRegistry()
        self.private: dict[str, Any] = {}
        self.private_b64: dict[str, str] = {}
        self.public: dict[str, str] = {}
        registration = registered_at or KEY_REGISTRATION_TIME
        for key_id, owner, purpose in (
            CONSUMER_KEY, CONSUMER_KEY_Y, DEVICE_KEY_A, DEVICE_KEY_B, PLATFORM_KEY
        ):
            public_b64, private_b64 = generate_key_pair()
            self.registry.register_key(key_id, owner, purpose, public_b64, registration)
            self.private[key_id] = load_private_key(private_b64)
            self.private_b64[key_id] = private_b64
            self.public[key_id] = public_b64
        # Each contribution device is bound to the provider account it may
        # report usage for, mirroring the registration flow.
        self.registry.bind_device("device-A", "provider-A")
        self.registry.bind_device("device-B", "provider-B")

    def sign(self, key_id: str, domain: str, payload: dict[str, Any]) -> str:
        """Sign a payload with one of the registered keys."""
        from aipotluck.canonical import sign_payload

        return sign_payload(domain, payload, self.private[key_id])


@pytest.fixture
def keyring() -> Keyring:
    """Return a keyring with consumer, two device, and platform keys."""
    return Keyring()


@pytest.fixture
def ledger() -> Ledger:
    """Return a ledger with funded consumer, providers, and platform reserve."""
    book = Ledger()
    book.issue("consumer-X", "consumer_available", 100_000)
    book.issue("consumer-Y", "consumer_available", 100_000)
    for account in ("provider-A", "provider-B", "provider-C", "provider-B1", "provider-B2"):
        book.account(f"{account}/pending", "provider_pending")
    book.fund_reserve(50_000)
    return book


@pytest.fixture
def now() -> dt.datetime:
    """Return a fixed timezone-aware timestamp."""
    return dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)


def solo_contract(provider_id: str = "provider-B") -> AllocationContract:
    """Return a contract giving one provider 100% and the platform nothing."""
    return AllocationContract(
        contract_id=f"contract-{provider_id}",
        version=1,
        weights={provider_id: 100},
        platform_fee_weight=0,
    )


def shared_contract() -> AllocationContract:
    """Return a 70/30 contract between two co-owners."""
    return AllocationContract(
        contract_id="contract-shared",
        version=1,
        weights={"provider-B1": 70, "provider-B2": 30},
    )


def make_measurement(
    measurement_id: str = "m-A2-U1",
    attempt_id: str = "A2",
    input_total: int = 8000,
    output_total: int = 700,
    revision: int = 3,
    semantics: str = "terminal_total",
    covered: frozenset[str] = frozenset(),
    verification_level: str = "node_reported",
    completeness: str = "complete",
) -> Measurement:
    """Build a measurement with sensible defaults for tests."""
    return Measurement(
        measurement_id=measurement_id,
        scope="upstream_call",
        semantics=semantics,  # type: ignore[arg-type]
        counter_epoch="epoch_1",
        revision=revision,
        usage=NormalizedUsage(
            input_total=input_total,
            output_total=output_total,
            completeness=completeness,  # type: ignore[arg-type]
            verification_level=verification_level,  # type: ignore[arg-type]
        ),
        attempt_id=attempt_id,
        covered_measurements=covered,
    )


def contract_hash(contract: AllocationContract) -> str:
    """Return the canonical digest of a contract."""
    return canonical_digest(contract.digest_payload())


#: The instant settlement is modelled at. Tests pass this as `settled_at` and
#: build authorization windows around it, so nothing depends on the wall clock.
SETTLEMENT_AT = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)


def signed_authorization(
    keyring: Keyring,
    *,
    request_id: str = "R-1001",
    payer_account_id: str = "consumer-X",
    consumer_id: str = "consumer-X",
    max_charge_milli_credits: int = 20_000,
    minimum_evidence_level: str = "node_reported",
    billing_basis: str = "reported_native_usage",
    pricing_version: str = "flat-v1",
    auth_method: str = "consumer_signed",
    key_id: str = "consumer-key-1",
    issued_at: dt.datetime | None = None,
    expires_at: dt.datetime | None = None,
    prompt: str = "write a haiku about ledgers",
    model: str = "coding-pool",
    delivery_mode: str = "buffered_complete",
    max_attempts: int = 2,
    allowed_models: frozenset[str] | None = None,
) -> Any:
    """Build and sign a consumer authorization for settlement tests.

    The authorization's ``request_digest`` is computed from the exact
    ``prompt``/``model``/``delivery_mode`` named here, because `admit_request`
    now re-derives that digest from the submitted work and refuses a mismatch.
    A caller that admits a different prompt must build the authorization with
    that same prompt (or accept the refusal it is testing).

    Args:
        keyring: Provides the registry and the signing key.
        request_id: The request the authorization covers.
        payer_account_id: The account that will be charged.
        consumer_id: The consumer identity.
        max_charge_milli_credits: Budget cap.
        minimum_evidence_level: Evidence policy the report must satisfy.
        billing_basis: Pricing basis the consumer agreed to.
        pricing_version: Rate card version.
        auth_method: `consumer_signed` or `gateway_authenticated`.
        key_id: Which registered key signs.
        issued_at: Window start; defaults to one minute before `SETTLEMENT_AT`.
        expires_at: Window end; defaults to five minutes after `SETTLEMENT_AT`.
        prompt: The work the authorization is signed for; its digest is bound.
        model: The model the authorization is signed for.
        delivery_mode: The delivery mode the authorization is signed for.
        max_attempts: The attempt cap the authorization permits.
        allowed_models: Model allowlist; defaults to ``{model}``.

    Returns:
        The signed authorization record.
    """
    from aipotluck.records import SpendAuthorization, new_nonce

    start = issued_at or SETTLEMENT_AT - dt.timedelta(minutes=1)
    end = expires_at or SETTLEMENT_AT + dt.timedelta(minutes=5)
    request_digest = canonical_digest(
        {"prompt": prompt, "model": model, "delivery_mode": delivery_mode}
    )
    authorization = SpendAuthorization(
        authorization_id=f"auth-{request_id}",
        payer_account_id=payer_account_id,
        consumer_id=consumer_id,
        request_id=request_id,
        request_digest=request_digest,
        max_charge_milli_credits=max_charge_milli_credits,
        pricing_version=pricing_version,
        billing_basis=billing_basis,  # type: ignore[arg-type]
        minimum_evidence_level=minimum_evidence_level,  # type: ignore[arg-type]
        allowed_models=allowed_models if allowed_models is not None else frozenset({model}),
        allowed_trust_pools=frozenset({"trusted-beta"}),
        max_attempts=max_attempts,
        duplicate_execution_policy="bounded_model_only",
        max_provider_fanout=2,
        nonce=new_nonce(),
        issued_at=start,
        expires_at=end,
        auth_method=auth_method,  # type: ignore[arg-type]
        key_id=key_id,
    )
    return authorization.sign(keyring.private[key_id], key_id)