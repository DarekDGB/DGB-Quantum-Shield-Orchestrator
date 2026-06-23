from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.key_registry import KeyRegistryEntry
from shield_orchestrator.v4.real_crypto_backend import (
    REAL_CRYPTO_SIGNATURE_INPUT_PREFIX,
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoBackendUnavailable,
    ShieldV4RealCryptoMaterialError,
    build_real_crypto_signature_input,
    build_signature_entry_with_real_backend,
    make_real_crypto_signature_verifier,
    reject_test_only_private_key_reference,
    verify_signature_entry_with_real_backend,
)

PAYLOAD_HASH = "a" * 64


@dataclass(frozen=True)
class FakeRealBackend:
    backend_name: str = "fake-real-backend"
    backend_version: str = "test-vector-only"
    supported_algorithms: tuple[str, ...] = ("classical-ed25519", "ml-dsa", "fn-dsa")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        return hashlib.sha256(
            f"sign|{algorithm}|{private_key_reference}|".encode("utf-8") + message
        ).hexdigest()

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        expected = hashlib.sha256(
            f"verify|{algorithm}|{public_key}|".encode("utf-8") + message
        ).hexdigest()
        return signature == expected


def real_key(*, algorithm: str = "ml-dsa") -> KeyRegistryEntry:
    return KeyRegistryEntry(
        role="shield_orchestrator",
        key_id=f"shield_orchestrator-{algorithm}-v1",
        key_version=1,
        algorithm=algorithm,
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        status="active",
        public_key=f"REAL-PUBLIC-shield_orchestrator-{algorithm}-v1",
    )


def signature_for_key(key: KeyRegistryEntry, *, domain_tag: str = ORCHESTRATOR_RECEIPT_DOMAIN) -> dict[str, object]:
    message = build_real_crypto_signature_input(
        algorithm=key.algorithm,
        domain_tag=domain_tag,
        signed_payload_hash=PAYLOAD_HASH,
        key_id=key.key_id,
        key_version=key.key_version,
    )
    signature = hashlib.sha256(
        f"verify|{key.algorithm}|{key.public_key}|".encode("utf-8") + message
    ).hexdigest()
    return {
        "algorithm": key.algorithm,
        "key_id": key.key_id,
        "key_version": key.key_version,
        "signed_payload_hash": PAYLOAD_HASH,
        "domain_tag": domain_tag,
        "signature": signature,
    }


def test_v48c_real_crypto_signature_input_is_frozen_and_domain_separated() -> None:
    encoded = build_real_crypto_signature_input(
        algorithm="ml-dsa",
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
    )

    assert encoded == (
        f"{REAL_CRYPTO_SIGNATURE_INPUT_PREFIX}\n"
        f"{ORCHESTRATOR_RECEIPT_DOMAIN}\n"
        f"{PAYLOAD_HASH}\n"
        "ml-dsa\n"
        "shield_orchestrator-ml-dsa-v1\n"
        "1"
    ).encode("utf-8")
    assert COMPONENT_VERDICT_DOMAIN.encode("utf-8") != encoded.splitlines()[1]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"algorithm": "unknown"}, "unsupported"),
        ({"domain_tag": "DGB-SHIELD-V4-WRONG"}, "domain_tag"),
        ({"signed_payload_hash": "A" * 64}, "lowercase"),
        ({"signed_payload_hash": "a" * 63}, "64-character"),
        ({"signed_payload_hash": "z" * 64}, "sha256"),
        ({"key_id": ""}, "key_id"),
        ({"key_version": 0}, "key_version"),
        ({"key_version": True}, "key_version"),
    ],
)
def test_v48c_real_crypto_signature_input_rejects_ambiguous_values(kwargs: dict[str, object], match: str) -> None:
    base: dict[str, object] = {
        "algorithm": "ml-dsa",
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signed_payload_hash": PAYLOAD_HASH,
        "key_id": "shield_orchestrator-ml-dsa-v1",
        "key_version": 1,
    }
    base.update(kwargs)
    with pytest.raises(ShieldV4RealCryptoBackendError, match=match):
        build_real_crypto_signature_input(**base)  # type: ignore[arg-type]


def test_v48c_real_crypto_signer_builds_entry_without_test_fallback() -> None:
    entry = build_signature_entry_with_real_backend(
        algorithm="ml-dsa",
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
        private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
        backend=FakeRealBackend(),
    )

    assert entry["algorithm"] == "ml-dsa"
    assert entry["key_id"] == "shield_orchestrator-ml-dsa-v1"
    assert len(str(entry["signature"])) == 64


@pytest.mark.parametrize("private_ref", ["", "test-only-private", "test-fixture-key"])
def test_v48c_real_crypto_signer_rejects_missing_or_test_private_material(private_ref: str) -> None:
    expected_error = ShieldV4RealCryptoBackendError if not private_ref else ShieldV4RealCryptoMaterialError
    with pytest.raises(expected_error):
        reject_test_only_private_key_reference(private_ref)


def test_v48c_real_crypto_verifier_accepts_real_backend_and_rejects_tamper() -> None:
    key = real_key()
    entry = signature_for_key(key)
    backend = FakeRealBackend()

    assert verify_signature_entry_with_real_backend(entry, key, backend=backend) is True

    tampered = dict(entry)
    tampered["signature"] = "0" * 64
    assert verify_signature_entry_with_real_backend(tampered, key, backend=backend) is False


def test_v48c_real_crypto_verifier_adapter_matches_signature_bundle_callback_shape() -> None:
    key = real_key(algorithm="classical-ed25519")
    verifier = make_real_crypto_signature_verifier(FakeRealBackend())

    assert verifier(signature_for_key(key), key) is True


def test_v48c_real_crypto_verifier_fails_closed_on_test_key_material_and_backend_gap() -> None:
    test_key = KeyRegistryEntry(
        role="shield_orchestrator",
        key_id="test-shield_orchestrator-ml-dsa-v1",
        key_version=1,
        algorithm="ml-dsa",
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        status="active",
        public_key="TEST-ONLY-PUBLIC-shield_orchestrator-ml-dsa-v1",
    )
    with pytest.raises(ShieldV4RealCryptoMaterialError, match="test-only"):
        verify_signature_entry_with_real_backend(signature_for_key(real_key()), test_key, backend=FakeRealBackend())

    unsupported_backend = FakeRealBackend(supported_algorithms=("classical-ed25519",))
    with pytest.raises(ShieldV4RealCryptoBackendUnavailable, match="support"):
        verify_signature_entry_with_real_backend(signature_for_key(real_key()), real_key(), backend=unsupported_backend)


def test_v48c_real_crypto_verifier_rejects_entry_key_mismatch_and_empty_signature() -> None:
    key = real_key()
    wrong_key = real_key(algorithm="fn-dsa")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="registry key"):
        verify_signature_entry_with_real_backend(signature_for_key(key), wrong_key, backend=FakeRealBackend())

    entry = signature_for_key(key)
    entry["signature"] = ""
    with pytest.raises(ShieldV4RealCryptoBackendError, match="signature"):
        verify_signature_entry_with_real_backend(entry, key, backend=FakeRealBackend())
