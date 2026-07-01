from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pytest

import shield_orchestrator.v4.oqs_mldsa_backend as oqs_backend_module
from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import KeyRegistryEntry
from shield_orchestrator.v4.oqs_mldsa_backend import OQS_ML_DSA_MECHANISM, OqsMlDsaBackend
from shield_orchestrator.v4.real_crypto_backend import (
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoBackendUnavailable,
    build_real_crypto_signature_input,
    build_signature_entry_with_real_backend,
    decode_binary_signature_material,
    encode_binary_signature_material,
    verify_signature_entry_with_real_backend,
)

PAYLOAD_HASH = "c" * 64
PUBLIC_KEY_BYTES = b"shield-v4-real-ml-dsa-public-key"
PRIVATE_KEY_BYTES = PUBLIC_KEY_BYTES


class FakeOqsSignature:
    def __init__(self, mechanism: str, secret_key: bytes | None = None) -> None:
        self.mechanism = mechanism
        self.secret_key = secret_key

    def __enter__(self) -> "FakeOqsSignature":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def sign(self, message: bytes) -> bytes:
        assert self.mechanism == OQS_ML_DSA_MECHANISM
        assert self.secret_key is not None
        return hashlib.sha256(b"oqs-sign|" + self.secret_key + message).digest()

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        assert self.mechanism == OQS_ML_DSA_MECHANISM
        expected = hashlib.sha256(b"oqs-sign|" + public_key + message).digest()
        return signature == expected


@dataclass(frozen=True)
class FakeOqsModule:
    enabled: tuple[str, ...] = (OQS_ML_DSA_MECHANISM,)

    def get_enabled_sig_mechanisms(self) -> tuple[str, ...]:
        return self.enabled

    def oqs_version(self) -> str:
        return "fake-liboqs"

    def oqs_python_version(self) -> str:
        return "fake-liboqs-python"

    Signature = FakeOqsSignature


def resolver(reference: str) -> bytes:
    if reference == "hsm://shield-orchestrator/ml-dsa/v1":
        return PRIVATE_KEY_BYTES
    return b""


def real_key() -> KeyRegistryEntry:
    return KeyRegistryEntry(
        role="shield_orchestrator",
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
        algorithm="ml-dsa",
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        status="active",
        public_key=encode_binary_signature_material(PUBLIC_KEY_BYTES, field="public_key"),
    )


def test_v48d_oqs_mldsa_backend_builds_real_b64u_signature_entry_and_verifies() -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    entry = build_signature_entry_with_real_backend(
        algorithm="ml-dsa",
        standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
        private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
        backend=backend,
    )

    assert entry["signature"].startswith("b64u:")
    assert "fake-liboqs" in backend.backend_version
    assert verify_signature_entry_with_real_backend(entry, real_key(), backend=backend) is True

    tampered = dict(entry)
    tampered["signature"] = encode_binary_signature_material(b"wrong-signature", field="signature")
    assert verify_signature_entry_with_real_backend(tampered, real_key(), backend=backend) is False


def test_v48d_oqs_mldsa_backend_rejects_wrong_algorithm_and_mechanism() -> None:
    with pytest.raises(ShieldV4RealCryptoBackendError, match="private_key_resolver"):
        OqsMlDsaBackend(private_key_resolver="not-callable")  # type: ignore[arg-type]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="ML-DSA-65"):
        OqsMlDsaBackend(private_key_resolver=resolver, mechanism="ML-DSA-44")

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    message = build_real_crypto_signature_input(
        algorithm="ml-dsa",
        standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
    )
    with pytest.raises(ShieldV4RealCryptoBackendUnavailable, match="ml-dsa"):
        backend.sign_message(
            algorithm="fn-dsa",
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            message=message,
        )
    with pytest.raises(ShieldV4RealCryptoBackendUnavailable, match="ml-dsa"):
        backend.verify_signature(
            algorithm="classical-ed25519",
            public_key=real_key().public_key,
            message=message,
            signature=encode_binary_signature_material(b"sig", field="signature"),
        )


def test_v48d_oqs_mldsa_backend_fails_closed_when_oqs_missing_or_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver)
    monkeypatch.setattr(
        oqs_backend_module.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError(name)),
    )
    with pytest.raises(ShieldV4RealCryptoBackendUnavailable, match="import oqs"):
        _ = backend.backend_version

    disabled_backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule(enabled=("FN-DSA-512",)))
    with pytest.raises(ShieldV4RealCryptoBackendUnavailable, match="not enabled"):
        disabled_backend.sign_message(
            algorithm="ml-dsa",
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            message=b"message",
        )


def test_v48d_oqs_mldsa_backend_rejects_bad_binary_material() -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    with pytest.raises(ShieldV4RealCryptoBackendError, match="message"):
        backend.sign_message(
            algorithm="ml-dsa",
            private_key_reference="hsm://shield-orchestrator/ml-dsa/v1",
            message=b"",
        )
    with pytest.raises(ShieldV4RealCryptoBackendError, match="secret_key"):
        backend.sign_message(algorithm="ml-dsa", private_key_reference="unknown", message=b"message")
    with pytest.raises(ShieldV4RealCryptoBackendError, match="public_key"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key="not-b64u",
            message=b"message",
            signature=encode_binary_signature_material(b"sig", field="signature"),
        )
    with pytest.raises(ShieldV4RealCryptoBackendError, match="signature"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature="b64u:bad=",
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


class NativeOqsError(RuntimeError):
    pass


class VersionDiscoveryFailureModule(FakeOqsModule):
    def oqs_version(self) -> str:
        raise NativeOqsError("native version discovery failure")


class MechanismDiscoveryFailureModule(FakeOqsModule):
    def get_enabled_sig_mechanisms(self) -> tuple[str, ...]:
        raise NativeOqsError("native mechanism discovery failure")


class NativeSignFailure(FakeOqsSignature):
    def sign(self, message: bytes) -> bytes:
        raise NativeOqsError("native sign rejected material")


class NativeVerifyFailure(FakeOqsSignature):
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NativeOqsError("native verify rejected material")


class NonBoolVerify(FakeOqsSignature):
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> object:
        return 1


class SignatureConstructorFailureModule(FakeOqsModule):
    @property
    def Signature(self) -> type[FakeOqsSignature]:  # type: ignore[override]
        raise NativeOqsError("native signature constructor lookup failure")


def failing_resolver(reference: str) -> bytes:
    raise NativeOqsError("native hsm resolver failure")


def test_v48g_oqs_mldsa_backend_wraps_all_native_exception_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver)
    monkeypatch.setattr(
        oqs_backend_module.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(NativeOqsError("native import failure")),
    )
    with pytest.raises(ShieldV4RealCryptoBackendError, match="import failed closed") as import_error:
        _ = backend.backend_version
    assert isinstance(import_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=VersionDiscoveryFailureModule())
    with pytest.raises(ShieldV4RealCryptoBackendError, match="version discovery failed closed") as version_error:
        _ = backend.backend_version
    assert isinstance(version_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=MechanismDiscoveryFailureModule())
    with pytest.raises(ShieldV4RealCryptoBackendError, match="mechanism discovery failed closed") as mechanism_error:
        backend.sign_message(algorithm="ml-dsa", private_key_reference="hsm://shield-orchestrator/ml-dsa/v1", message=b"message")
    assert isinstance(mechanism_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=failing_resolver, oqs_module=FakeOqsModule())
    with pytest.raises(ShieldV4RealCryptoBackendError, match="private key resolution failed closed") as resolver_error:
        backend.sign_message(algorithm="ml-dsa", private_key_reference="hsm://shield-orchestrator/ml-dsa/v1", message=b"message")
    assert isinstance(resolver_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=SignatureConstructorFailureModule())
    with pytest.raises(ShieldV4RealCryptoBackendError, match="sign failed closed") as constructor_error:
        backend.sign_message(algorithm="ml-dsa", private_key_reference="hsm://shield-orchestrator/ml-dsa/v1", message=b"message")
    assert isinstance(constructor_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NativeSignFailure)  # type: ignore[misc]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="sign failed closed") as sign_error:
        backend.sign_message(algorithm="ml-dsa", private_key_reference="hsm://shield-orchestrator/ml-dsa/v1", message=b"message")
    assert isinstance(sign_error.value.__cause__, NativeOqsError)

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NativeVerifyFailure)  # type: ignore[misc]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="verify failed closed") as verify_error:
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )
    assert isinstance(verify_error.value.__cause__, NativeOqsError)


def test_v48g_oqs_mldsa_backend_rejects_truthy_non_bool_verify() -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NonBoolVerify)  # type: ignore[misc]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="verify must return bool"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )

class LengthCheckedOqsSignature(FakeOqsSignature):
    details = {
        "length_public_key": len(PUBLIC_KEY_BYTES),
        "length_signature": hashlib.sha256(b"").digest_size,
    }


def test_v48g_oqs_mldsa_backend_rejects_wrong_binary_lengths_before_native_verify() -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", LengthCheckedOqsSignature)  # type: ignore[misc]

    with pytest.raises(ShieldV4RealCryptoBackendError, match="public_key byte length"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=encode_binary_signature_material(PUBLIC_KEY_BYTES[:-1], field="public_key"),
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    with pytest.raises(ShieldV4RealCryptoBackendError, match="signature byte length"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )

class NonMappingDetailsOqsSignature(FakeOqsSignature):
    details = "bad-details"


class MissingLengthDetailsOqsSignature(FakeOqsSignature):
    details: dict[str, int] = {}


class InvalidLengthDetailsOqsSignature(FakeOqsSignature):
    details = {"length_public_key": True, "length_signature": hashlib.sha256(b"").digest_size}


def test_v48g_oqs_mldsa_backend_validates_optional_backend_length_metadata() -> None:
    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NonMappingDetailsOqsSignature)  # type: ignore[misc]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="details must be a mapping"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", InvalidLengthDetailsOqsSignature)  # type: ignore[misc]
    with pytest.raises(ShieldV4RealCryptoBackendError, match="length_public_key"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=real_key().public_key,
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    backend = OqsMlDsaBackend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", MissingLengthDetailsOqsSignature)  # type: ignore[misc]
    message = build_real_crypto_signature_input(
        algorithm="ml-dsa",
        standard_profile=default_standard_profile_for_algorithm("ml-dsa"),
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        key_id="shield_orchestrator-ml-dsa-v1",
        key_version=1,
    )
    signature = encode_binary_signature_material(
        hashlib.sha256(b"oqs-sign|" + PUBLIC_KEY_BYTES + message).digest(),
        field="signature",
    )
    assert backend.verify_signature(
        algorithm="ml-dsa",
        public_key=real_key().public_key,
        message=message,
        signature=signature,
    ) is True
