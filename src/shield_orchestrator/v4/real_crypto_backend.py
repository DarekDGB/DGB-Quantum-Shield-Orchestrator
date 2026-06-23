from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.crypto_algorithms import SIGNATURE_POLICY_V1
from shield_orchestrator.v4.key_registry import KeyRegistryEntry

REAL_CRYPTO_SIGNATURE_INPUT_PREFIX = "DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT"
_ALLOWED_DOMAIN_TAGS = frozenset({COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN})
_TEST_ONLY_MARKERS = ("test-only",)
_TEST_ONLY_PREFIXES = ("test-",)


class ShieldV4RealCryptoBackendError(ValueError):
    """Base fail-closed error for Shield v4 real crypto backend wiring."""


class ShieldV4RealCryptoBackendUnavailable(ShieldV4RealCryptoBackendError):
    """Raised when a required production backend/algorithm is not available."""


class ShieldV4RealCryptoMaterialError(ShieldV4RealCryptoBackendError):
    """Raised when test-only material reaches the real-crypto adapter boundary."""


class ShieldV4RealCryptoBackend(Protocol):
    """Minimal production crypto backend contract for Shield v4 signatures.

    Implementations may wrap liboqs, a FIPS-validated module, an HSM, or another
    deployment-controlled backend. This protocol intentionally avoids importing a
    concrete PQC library so CI cannot silently depend on a local machine backend.
    """

    backend_name: str
    backend_version: str
    supported_algorithms: tuple[str, ...]

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        """Return a signature encoding for the supplied message."""

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        """Return True only when the signature verifies under the supplied public key."""


RealCryptoSignatureVerifier = Callable[[dict[str, Any], KeyRegistryEntry], bool]


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty string")
    return value.strip()


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShieldV4RealCryptoBackendError(f"{field} must be positive integer")
    return value


def _require_supported_algorithm(value: Any) -> str:
    algorithm = _require_non_empty_str(value, field="algorithm")
    if algorithm not in SIGNATURE_POLICY_V1.allowed_algorithms:
        raise ShieldV4RealCryptoBackendError("unsupported Shield v4 signature algorithm")
    return algorithm


def _require_hash(value: Any, *, field: str) -> str:
    clean = _require_non_empty_str(value, field=field)
    if len(clean) != 64:
        raise ShieldV4RealCryptoBackendError(f"{field} must be 64-character sha256 hex")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} must be sha256 hex") from exc
    if clean != clean.lower():
        raise ShieldV4RealCryptoBackendError(f"{field} must be lowercase sha256 hex")
    return clean


def _reject_test_only_text(value: str, *, field: str) -> None:
    clean = value.strip().lower()
    if any(marker in clean for marker in _TEST_ONLY_MARKERS) or any(
        clean.startswith(prefix) for prefix in _TEST_ONLY_PREFIXES
    ):
        raise ShieldV4RealCryptoMaterialError(f"{field} must not contain test-only material")


def reject_test_only_key_material(key: KeyRegistryEntry) -> None:
    """Fail closed if deterministic-test keys reach the real backend boundary."""

    _reject_test_only_text(key.key_id, field="key_id")
    _reject_test_only_text(key.public_key, field="public_key")


def reject_test_only_private_key_reference(private_key_reference: str) -> str:
    clean = _require_non_empty_str(private_key_reference, field="private_key_reference")
    _reject_test_only_text(clean, field="private_key_reference")
    return clean


def build_real_crypto_signature_input(
    *,
    algorithm: str,
    domain_tag: str,
    signed_payload_hash: str,
    key_id: str,
    key_version: int,
) -> bytes:
    """Build the exact production-signature message bytes for Shield v4.

    The signed payload hash is already domain-separated over the canonical JSON
    payload. The backend message binds that hash to the signature role, algorithm,
    key id, and key version so entries cannot be spliced across bundles.
    """

    clean_algorithm = _require_supported_algorithm(algorithm)
    clean_domain = _require_non_empty_str(domain_tag, field="domain_tag")
    if clean_domain not in _ALLOWED_DOMAIN_TAGS:
        raise ShieldV4RealCryptoBackendError("domain_tag must be a Shield v4 signing domain")
    clean_hash = _require_hash(signed_payload_hash, field="signed_payload_hash")
    clean_key_id = _require_non_empty_str(key_id, field="key_id")
    clean_key_version = _require_positive_int(key_version, field="key_version")
    return "\n".join(
        (
            REAL_CRYPTO_SIGNATURE_INPUT_PREFIX,
            clean_domain,
            clean_hash,
            clean_algorithm,
            clean_key_id,
            str(clean_key_version),
        )
    ).encode("utf-8")


def _require_backend_supports_algorithm(backend: ShieldV4RealCryptoBackend, algorithm: str) -> None:
    supported = tuple(getattr(backend, "supported_algorithms", ()))
    if algorithm not in supported:
        raise ShieldV4RealCryptoBackendUnavailable("real crypto backend does not support required algorithm")


def build_signature_entry_with_real_backend(
    *,
    algorithm: str,
    domain_tag: str,
    signed_payload_hash: str,
    key_id: str,
    key_version: int,
    private_key_reference: str,
    backend: ShieldV4RealCryptoBackend,
) -> dict[str, Any]:
    """Build a Shield v4 signature entry using a real backend implementation."""

    message = build_real_crypto_signature_input(
        algorithm=algorithm,
        domain_tag=domain_tag,
        signed_payload_hash=signed_payload_hash,
        key_id=key_id,
        key_version=key_version,
    )
    clean_private_ref = reject_test_only_private_key_reference(private_key_reference)
    _require_backend_supports_algorithm(backend, algorithm)
    signature = backend.sign_message(
        algorithm=algorithm,
        private_key_reference=clean_private_ref,
        message=message,
    )
    return {
        "algorithm": algorithm,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": signed_payload_hash,
        "domain_tag": domain_tag,
        "signature": _require_non_empty_str(signature, field="signature"),
    }


def verify_signature_entry_with_real_backend(
    entry: dict[str, Any],
    key: KeyRegistryEntry,
    *,
    backend: ShieldV4RealCryptoBackend,
) -> bool:
    """Verify one Shield v4 signature entry with a production backend."""

    reject_test_only_key_material(key)
    algorithm = _require_non_empty_str(entry.get("algorithm"), field="algorithm")
    key_id = _require_non_empty_str(entry.get("key_id"), field="key_id")
    key_version = _require_positive_int(entry.get("key_version"), field="key_version")
    if (key.algorithm, key.key_id, key.key_version) != (algorithm, key_id, key_version):
        raise ShieldV4RealCryptoBackendError("signature entry does not match registry key")
    _require_backend_supports_algorithm(backend, algorithm)
    message = build_real_crypto_signature_input(
        algorithm=algorithm,
        domain_tag=_require_non_empty_str(entry.get("domain_tag"), field="domain_tag"),
        signed_payload_hash=_require_hash(entry.get("signed_payload_hash"), field="signed_payload_hash"),
        key_id=key_id,
        key_version=key_version,
    )
    signature = _require_non_empty_str(entry.get("signature"), field="signature")
    return bool(
        backend.verify_signature(
            algorithm=algorithm,
            public_key=key.public_key,
            message=message,
            signature=signature,
        )
    )


def make_real_crypto_signature_verifier(
    backend: ShieldV4RealCryptoBackend,
) -> RealCryptoSignatureVerifier:
    """Adapt a real crypto backend to the existing Shield v4 bundle verifier."""

    def _verify(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        return verify_signature_entry_with_real_backend(entry, key, backend=backend)

    return _verify
