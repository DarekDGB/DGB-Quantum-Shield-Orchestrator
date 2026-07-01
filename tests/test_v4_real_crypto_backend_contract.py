from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import KeyRegistryEntry
from shield_orchestrator.v4.real_crypto_backend import (
    REAL_CRYPTO_SIGNATURE_INPUT_PREFIX,
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoBackendUnavailable,
    ShieldV4RealCryptoMaterialError,
    build_real_crypto_signature_input,
    build_signature_entry_with_real_backend,
    decode_binary_signature_material,
    encode_binary_signature_material,
    make_real_crypto_signature_verifier,
    reject_test_only_private_key_reference,
    verify_signature_entry_with_real_backend,
)

PAYLOAD_HASH = "a" * 64


class NativeBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class FakeRealBackend:
    backend_name: str = "fake-real-backend"
    backend_version: str = "contract-test-vector-only"
    supported_algorithms: tuple[str, ...] = ("classical-ed25519", "ml-dsa", "fn-dsa")
    verify_result: Any | None = None

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        raw = hashlib.sha256(f"sign|{algorithm}|{private_key_reference}|".encode("utf-8") + message).digest()
        return encode_binary_signature_material(raw, field="signature")

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        if self.verify_result is not None:
            return self.verify_result  # type: ignore[return-value]
        expected = _signature_for_public_key(algorithm=algorithm, public_key=public_key, message=message)
        return signature == expected


class AlgorithmDiscoveryFailureBackend:
    backend_name = "algorithm-discovery-failure-backend"
    backend_version = "contract-test-vector-only"

    @property
    def supported_algorithms(self) -> tuple[str, ...]:
        raise NativeBackendError("backend algorithm discovery exploded")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        return encode_binary_signature_material(b"unreachable", field="signature")

    def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> bool:
        return False


class SignFailureBackend(FakeRealBackend):
    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        raise NativeBackendError("native sign failure")


class VerifyFailureBackend(FakeRealBackend):
    def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> bool:
        raise NativeBackendError("native verify failure")


class WrappedErrorBackend(FakeRealBackend):
    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        raise ShieldV4RealCryptoBackendError("backend already failed closed")


def _real_public_key_bytes(*, algorithm: str = "ml-dsa") -> bytes:
    return f"shield-orchestrator-real-public-{algorithm}".encode("utf-8")


def _real_public_key(*, algorithm: str = "ml-dsa") -> str:
    return encode_binary_signature_material(_real_public_key_bytes(algorithm=algorithm), field="public_key")


def real_key(*, algorithm: str = "ml-dsa", key_id: str | None = None) -> KeyRegistryEntry:
    return KeyRegistryEntry(
        role="shield_orchestrator",
        key_id=key_id or f"shield_orchestrator-{algorithm}-v1",
        key_version=1,
        algorithm=algorithm,
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        status="active",
        public_key=_real_public_key(algorithm=algorithm),
    )


def _signature_message(key: KeyRegistryEntry, *, domain_tag: str = ORCHESTRATOR_RECEIPT_DOMAIN) -> bytes:
    return build_real_crypto_signature_input(
        algorithm=key.algorithm,
        standard_profile=default_standard_profile_for_algorithm(key.algorithm),
        domain_tag=domain_tag,
        signed_payload_hash=PAYLOAD_HASH,
        key_id=key.key_id,
        key_version=key.key_version,
    )


def _signature_for_public_key(*, algorithm: str, public_key: str, message: bytes) -> str:
    raw = hashlib.sha256(f"verify|{algorithm}|{public_key}|".encode("utf-8") + message).digest()
    return encode_binary_signature_material(raw, field="signature")


def signature_for_key(key: KeyRegistryEntry, *, domain_tag: str = ORCHESTRATOR_RECEIPT_DOMAIN) -> dict[str, object]:
    message = _signature_message(key, domain_tag=domain_tag)
    return {
        "algorithm": key.algorithm,
        "standard_profile": default_standard_profile_for_algorithm(key.algorithm),
        "key_id": key.key_id,
        "key_version": key.key_version,
        "signed_payload_hash": PAYLOAD_HASH,
        "domain_tag": domain_tag,
        "signature": _signature_for_public_key(algorithm=key.algorithm, public_key=key.public_key, message=message),
    }


def test_v48c_real_crypto_signature_input_is_frozen_and_domain_separated() -> None:
    encoded = build_real_crypto_signature_input(
        algorithm="ml-dsa",
        standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
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
        "fips204-ml-dsa-65-v1\n"
        "shield_orchestrator-ml-dsa-v1\n"
        "1"
    ).encode("utf-8")
    assert COMPONENT_VERDICT_DOMAIN.encode("utf-8") != encoded.splitlines()[1]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"algorithm": "unknown"}, "unsupported"),
        ({"algorithm": " ml-dsa"}, "surrounding whitespace"),
        ({"standard_profile": "fips206-draft-falcon1024-v1"}, "standard_profile"),
        ({"standard_profile": " ml-dsa-profile"}, "surrounding whitespace"),
        ({"domain_tag": "DGB-SHIELD-V4-WRONG"}, "domain_tag"),
        ({"signed_payload_hash": "A" * 64}, "lowercase"),
        ({"signed_payload_hash": "a" * 63}, "64-character"),
        ({"signed_payload_hash": "z" * 64}, "sha256"),
        ({"key_id": ""}, "key_id"),
        ({"key_id": " shield_orchestrator-ml-dsa-v1"}, "surrounding whitespace"),
        ({"key_version": 0}, "key_version"),
        ({"key_version": True}, "key_version"),
    ],
)
def test_v48c_real_crypto_signature_input_rejects_ambiguous_values(kwargs: dict[str, object], match: str) -> None:
    base: dict[str, object] = {
        "algorithm": "ml-dsa",
        "standard_profile": default_standard_profile_for_algorithm("ml-dsa"),
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signed_payload_hash": PAYLOAD_HASH,
        "key_id": "shield_orchestrator-ml-dsa-v1",
        "key_version": 1,
    }
    base.update(kwargs)
    with pytest.raises(ShieldV4RealCryptoBackendError, match=match):
        build_real_crypto_signature_input(**base)  # type: ignore[arg-type]


def test_v48c_real_crypto_signer_builds_b64u_entry_without_test_fallback() -> None:
    entry = build_signature_entry_with_real_backend(
        algorithm="ml-dsa",
        standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
        private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
        backend=FakeRealBackend(),
    )

    assert entry["algorithm"] == "ml-dsa"
    assert entry["key_id"] == "shield_orchestrator-ml-dsa-v1"
    assert str(entry["signature"]).startswith("b64u:")
    assert decode_binary_signature_material(entry["signature"], field="signature")


@pytest.mark.parametrize("private_ref", ["", " test-ref", "test-only-private", "test-fixture-key"])
def test_v48c_real_crypto_signer_rejects_missing_whitespace_or_test_private_material(private_ref: str) -> None:
    expected_error = ShieldV4RealCryptoBackendError if not private_ref or private_ref != private_ref.strip() else ShieldV4RealCryptoMaterialError
    with pytest.raises(expected_error):
        reject_test_only_private_key_reference(private_ref)


def test_v48c_real_crypto_verifier_accepts_real_backend_and_rejects_tamper() -> None:
    key = real_key()
    entry = signature_for_key(key)
    backend = FakeRealBackend()

    assert verify_signature_entry_with_real_backend(entry, key, backend=backend) is True

    tampered = dict(entry)
    tampered["signature"] = encode_binary_signature_material(b"wrong-signature", field="signature")
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


def test_v48c_real_crypto_verifier_rejects_entry_key_and_schema_mismatch_and_empty_signature() -> None:
    key = real_key()
    wrong_key = real_key(algorithm="fn-dsa")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="registry key"):
        verify_signature_entry_with_real_backend(signature_for_key(key), wrong_key, backend=FakeRealBackend())

    with pytest.raises(ShieldV4RealCryptoBackendError, match="signature entry must be dict"):
        verify_signature_entry_with_real_backend(["not-dict"], key, backend=FakeRealBackend())  # type: ignore[arg-type]

    entry = signature_for_key(key)
    entry["extra"] = "forbidden"
    with pytest.raises(ShieldV4RealCryptoBackendError, match="fields"):
        verify_signature_entry_with_real_backend(entry, key, backend=FakeRealBackend())

    entry = signature_for_key(key)
    entry["signature"] = ""
    with pytest.raises(ShieldV4RealCryptoBackendError, match="signature"):
        verify_signature_entry_with_real_backend(entry, key, backend=FakeRealBackend())


def test_v48g_real_crypto_backend_wrapper_catches_native_exceptions_and_preserves_cause() -> None:
    with pytest.raises(ShieldV4RealCryptoBackendError, match="algorithm discovery failed closed") as algorithm_error:
        build_signature_entry_with_real_backend(
            algorithm="ml-dsa",
            standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
            domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            signed_payload_hash=PAYLOAD_HASH,
            key_id="shield_orchestrator-ml-dsa-v1",
            key_version=1,
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            backend=AlgorithmDiscoveryFailureBackend(),
        )
    assert isinstance(algorithm_error.value.__cause__, NativeBackendError)

    with pytest.raises(ShieldV4RealCryptoBackendError, match="sign failed closed") as sign_error:
        build_signature_entry_with_real_backend(
            algorithm="ml-dsa",
            standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
            domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            signed_payload_hash=PAYLOAD_HASH,
            key_id="shield_orchestrator-ml-dsa-v1",
            key_version=1,
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            backend=SignFailureBackend(),
        )
    assert isinstance(sign_error.value.__cause__, NativeBackendError)

    with pytest.raises(ShieldV4RealCryptoBackendError, match="verify failed closed") as verify_error:
        verify_signature_entry_with_real_backend(signature_for_key(real_key()), real_key(), backend=VerifyFailureBackend())
    assert isinstance(verify_error.value.__cause__, NativeBackendError)

    with pytest.raises(ShieldV4RealCryptoBackendError, match="backend already failed closed") as wrapped_error:
        build_signature_entry_with_real_backend(
            algorithm="ml-dsa",
            standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
            domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            signed_payload_hash=PAYLOAD_HASH,
            key_id="shield_orchestrator-ml-dsa-v1",
            key_version=1,
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            backend=WrappedErrorBackend(),
        )
    assert wrapped_error.value.__cause__ is None


def test_v48g_real_crypto_backend_rejects_truthy_non_bool_verify_result() -> None:
    with pytest.raises(ShieldV4RealCryptoBackendError, match="verify must return bool"):
        verify_signature_entry_with_real_backend(
            signature_for_key(real_key()),
            real_key(),
            backend=FakeRealBackend(verify_result=1),
        )


def test_v48d_real_binary_encoding_helpers_are_strict() -> None:
    encoded = encode_binary_signature_material(b"abc", field="signature")
    assert encoded == "b64u:YWJj"
    assert decode_binary_signature_material(encoded, field="signature") == b"abc"

    with pytest.raises(ShieldV4RealCryptoBackendError, match="bytes"):
        encode_binary_signature_material(b"", field="signature")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="b64u"):
        decode_binary_signature_material("abc", field="signature")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="non-empty"):
        decode_binary_signature_material("b64u:", field="signature")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="unpadded"):
        decode_binary_signature_material("b64u:YWJj=", field="signature")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="invalid"):
        decode_binary_signature_material("b64u:****", field="signature")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="invalid"):
        decode_binary_signature_material("b64u:A", field="signature")
