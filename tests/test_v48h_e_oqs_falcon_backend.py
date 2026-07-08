from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

import shield_orchestrator.v4.oqs_falcon_backend as oqs_falcon_module
from shield_orchestrator.v4.oqs_falcon_backend import OQS_FALCON_MECHANISM, OqsFalcon1024Backend
from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN as DOMAIN_TAG
from shield_orchestrator.v4.crypto_algorithms import FIPS206_DRAFT_FALCON1024_PROFILE
from shield_orchestrator.v4.real_crypto_backend import (
    ShieldV4RealCryptoBackendError as BackendError,
    ShieldV4RealCryptoBackendUnavailable as BackendUnavailable,
    build_real_crypto_signature_input,
    build_signature_entry_with_real_backend,
    encode_binary_signature_material,
    verify_signature_entry_with_real_backend,
)
from shield_orchestrator.v4.key_registry import KeyRegistryEntry

PAYLOAD_HASH = "e" * 64
PUBLIC_KEY_BYTES = b'shield-v48h-e-orchestrator-falcon-public-key'
PRIVATE_KEY_BYTES = PUBLIC_KEY_BYTES
PRIVATE_KEY_REFERENCE = "hsm://shield-orchestrator/fn-dsa-falcon1024/v1"


class FakeOqsSignature:
    def __init__(self, mechanism: str, secret_key: bytes | None = None) -> None:
        self.mechanism = mechanism
        self.secret_key = secret_key

    def __enter__(self) -> "FakeOqsSignature":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def sign(self, message: bytes) -> bytes:
        assert self.mechanism == OQS_FALCON_MECHANISM
        assert self.secret_key is not None
        return hashlib.sha256(b"oqs-falcon-sign|" + self.secret_key + message).digest()

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        assert self.mechanism == OQS_FALCON_MECHANISM
        expected = hashlib.sha256(b"oqs-falcon-sign|" + public_key + message).digest()
        return signature == expected


@dataclass(frozen=True)
class FakeOqsModule:
    enabled: tuple[str, ...] = (OQS_FALCON_MECHANISM,)

    def get_enabled_sig_mechanisms(self) -> tuple[str, ...]:
        return self.enabled

    def oqs_version(self) -> str:
        return "fake-liboqs"

    def oqs_python_version(self) -> str:
        return "fake-liboqs-python"

    Signature = FakeOqsSignature


class NativeOqsError(RuntimeError):
    pass


def trusted_key() -> KeyRegistryEntry:
    return KeyRegistryEntry(
        role="shield_orchestrator",
        key_id="prod-shield_orchestrator-fn-dsa-v1",
        key_version=1,
        algorithm="fn-dsa",
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        status="active",
        public_key=encode_binary_signature_material(PUBLIC_KEY_BYTES, field="public_key"),
    )


def key_role() -> str:
    return "shield_orchestrator"


def resolver(reference: str) -> bytes:
    if reference == PRIVATE_KEY_REFERENCE:
        return PRIVATE_KEY_BYTES
    return b""


def public_key_value() -> str:
    key = trusted_key()
    return str(key["public_key"] if isinstance(key, dict) else key.public_key)


def signature_message() -> bytes:
    return build_real_crypto_signature_input(
        algorithm="fn-dsa",
        standard_profile=FIPS206_DRAFT_FALCON1024_PROFILE,
        domain_tag=DOMAIN_TAG,
        signed_payload_hash=PAYLOAD_HASH,
        key_id=f"prod-{key_role()}-fn-dsa-v1",
        key_version=1,
    )


def test_v48h_e_oqs_falcon_backend_builds_real_b64u_signature_entry_and_verifies() -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    entry = build_signature_entry_with_real_backend(
        algorithm="fn-dsa",
        standard_profile=FIPS206_DRAFT_FALCON1024_PROFILE,
        domain_tag=DOMAIN_TAG,
        signed_payload_hash=PAYLOAD_HASH,
        key_id=f"prod-{key_role()}-fn-dsa-v1",
        key_version=1,
        private_key_reference=PRIVATE_KEY_REFERENCE,
        backend=backend,
    )

    assert entry["standard_profile"] == FIPS206_DRAFT_FALCON1024_PROFILE
    assert entry["signature"].startswith("b64u:")
    assert "fake-liboqs" in backend.backend_version
    assert "Falcon-1024" in backend.backend_version
    assert verify_signature_entry_with_real_backend(entry, trusted_key(), backend=backend) is True

    tampered = dict(entry)
    tampered["signature"] = encode_binary_signature_material(b"wrong-signature", field="signature")
    assert verify_signature_entry_with_real_backend(tampered, trusted_key(), backend=backend) is False


def test_v48h_e_oqs_falcon_backend_rejects_wrong_algorithm_and_mechanism() -> None:
    with pytest.raises(BackendError, match="private_key_resolver"):
        OqsFalcon1024Backend(private_key_resolver="not-callable")  # type: ignore[arg-type]
    with pytest.raises(BackendError, match="Falcon-1024"):
        OqsFalcon1024Backend(private_key_resolver=resolver, mechanism="Falcon-512")

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    with pytest.raises(BackendUnavailable, match="fn-dsa"):
        backend.sign_message(algorithm="ml-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=signature_message())
    with pytest.raises(BackendUnavailable, match="fn-dsa"):
        backend.verify_signature(
            algorithm="classical-ed25519",
            public_key=public_key_value(),
            message=signature_message(),
            signature=encode_binary_signature_material(b"sig", field="signature"),
        )


def test_v48h_e_oqs_falcon_backend_fails_closed_when_oqs_missing_or_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver)
    monkeypatch.setattr(
        oqs_falcon_module.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError(name)),
    )
    with pytest.raises(BackendUnavailable, match="import oqs"):
        _ = backend.backend_version

    disabled_backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule(enabled=("ML-DSA-65",)))
    with pytest.raises(BackendUnavailable, match="not enabled"):
        disabled_backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"message")


def test_v48h_e_oqs_falcon_backend_rejects_bad_binary_material() -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    with pytest.raises(BackendError, match="message"):
        backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"")
    with pytest.raises(BackendError, match="secret_key"):
        backend.sign_message(algorithm="fn-dsa", private_key_reference="unknown", message=b"message")
    with pytest.raises(BackendError, match="public_key"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key="not-b64u",
            message=b"message",
            signature=encode_binary_signature_material(b"sig", field="signature"),
        )
    with pytest.raises(BackendError, match="signature"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature="b64u:bad=",
        )


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


def test_v48h_e_oqs_falcon_backend_wraps_all_native_exception_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver)
    monkeypatch.setattr(
        oqs_falcon_module.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(NativeOqsError("native import failure")),
    )
    with pytest.raises(BackendError, match="import failed closed") as import_error:
        _ = backend.backend_version
    assert isinstance(import_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=VersionDiscoveryFailureModule())
    with pytest.raises(BackendError, match="version discovery failed closed") as version_error:
        _ = backend.backend_version
    assert isinstance(version_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=MechanismDiscoveryFailureModule())
    with pytest.raises(BackendError, match="mechanism discovery failed closed") as mechanism_error:
        backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"message")
    assert isinstance(mechanism_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=failing_resolver, oqs_module=FakeOqsModule())
    with pytest.raises(BackendError, match="private key resolution failed closed") as resolver_error:
        backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"message")
    assert isinstance(resolver_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=SignatureConstructorFailureModule())
    with pytest.raises(BackendError, match="sign failed closed") as constructor_error:
        backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"message")
    assert isinstance(constructor_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NativeSignFailure)  # type: ignore[misc]
    with pytest.raises(BackendError, match="sign failed closed") as sign_error:
        backend.sign_message(algorithm="fn-dsa", private_key_reference=PRIVATE_KEY_REFERENCE, message=b"message")
    assert isinstance(sign_error.value.__cause__, NativeOqsError)

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NativeVerifyFailure)  # type: ignore[misc]
    with pytest.raises(BackendError, match="verify failed closed") as verify_error:
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )
    assert isinstance(verify_error.value.__cause__, NativeOqsError)


def test_v48h_e_oqs_falcon_backend_rejects_truthy_non_bool_verify() -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NonBoolVerify)  # type: ignore[misc]
    with pytest.raises(BackendError, match="verify must return bool"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )


class LengthCheckedOqsSignature(FakeOqsSignature):
    details = {
        "length_public_key": len(PUBLIC_KEY_BYTES),
        "length_signature": hashlib.sha256(b"").digest_size,
    }


class NonMappingDetailsOqsSignature(FakeOqsSignature):
    details = "bad-details"


class MissingLengthDetailsOqsSignature(FakeOqsSignature):
    details: dict[str, int] = {}


class InvalidLengthDetailsOqsSignature(FakeOqsSignature):
    details = {"length_public_key": True, "length_signature": hashlib.sha256(b"").digest_size}


def test_v48h_e_oqs_falcon_backend_rejects_wrong_binary_lengths_before_native_verify() -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", LengthCheckedOqsSignature)  # type: ignore[misc]

    with pytest.raises(BackendError, match="public_key byte length"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=encode_binary_signature_material(PUBLIC_KEY_BYTES[:-1], field="public_key"),
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    with pytest.raises(BackendError, match="signature byte length"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature=encode_binary_signature_material(b"short-signature", field="signature"),
        )


def test_v48h_e_oqs_falcon_backend_validates_optional_backend_length_metadata() -> None:
    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", NonMappingDetailsOqsSignature)  # type: ignore[misc]
    with pytest.raises(BackendError, match="details must be a mapping"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", InvalidLengthDetailsOqsSignature)  # type: ignore[misc]
    with pytest.raises(BackendError, match="length_public_key"):
        backend.verify_signature(
            algorithm="fn-dsa",
            public_key=public_key_value(),
            message=b"message",
            signature=encode_binary_signature_material(b"0" * hashlib.sha256(b"").digest_size, field="signature"),
        )

    backend = OqsFalcon1024Backend(private_key_resolver=resolver, oqs_module=FakeOqsModule())
    object.__setattr__(backend._oqs_module, "Signature", MissingLengthDetailsOqsSignature)  # type: ignore[misc]
    signature = encode_binary_signature_material(
        hashlib.sha256(b"oqs-falcon-sign|" + PUBLIC_KEY_BYTES + signature_message()).digest(),
        field="signature",
    )
    assert backend.verify_signature(
        algorithm="fn-dsa",
        public_key=public_key_value(),
        message=signature_message(),
        signature=signature,
    ) is True
