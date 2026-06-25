from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType
from typing import Any, NoReturn

from shield_orchestrator.v4.real_crypto_backend import (
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoBackendUnavailable,
    decode_binary_signature_material,
    encode_binary_signature_material,
    reject_test_only_private_key_reference,
)

OQS_ML_DSA_ALGORITHM = "ml-dsa"
OQS_ML_DSA_MECHANISM = "ML-DSA-65"
OQS_BACKEND_NAME = "open-quantum-safe-liboqs-python"

PrivateKeyResolver = Callable[[str], bytes]


class OqsMlDsaBackend:
    """liboqs-python backed ML-DSA signer/verifier for Shield v4 evidence.

    This class is intentionally limited to the Shield policy algorithm ``ml-dsa``.
    In policy.v1, this optional backend maps that policy name to the OQS
    mechanism ``ML-DSA-65``. It signs and verifies Shield evidence bytes only; it
    does not sign transactions and does not broadcast anything.
    """

    supported_algorithms = (OQS_ML_DSA_ALGORITHM,)

    def __init__(
        self,
        *,
        private_key_resolver: PrivateKeyResolver,
        oqs_module: ModuleType | Any | None = None,
        mechanism: str = OQS_ML_DSA_MECHANISM,
    ) -> None:
        if not callable(private_key_resolver):
            raise ShieldV4RealCryptoBackendError("private_key_resolver must be callable")
        if mechanism != OQS_ML_DSA_MECHANISM:
            raise ShieldV4RealCryptoBackendError("Shield v4 policy.v1 requires OQS ML-DSA-65")
        self._private_key_resolver = private_key_resolver
        self._oqs_module = oqs_module
        self.mechanism = mechanism
        self.backend_name = OQS_BACKEND_NAME

    @property
    def backend_version(self) -> str:
        oqs = self._load_oqs()
        try:
            oqs_version = getattr(oqs, "oqs_version", lambda: "unknown")()
            python_version = getattr(oqs, "oqs_python_version", lambda: "unknown")()
        except Exception as exc:
            self._raise_oqs_error("version discovery", exc)
        return f"liboqs={oqs_version};liboqs-python={python_version};mechanism={self.mechanism}"

    def _load_oqs(self) -> Any:
        if self._oqs_module is not None:
            return self._oqs_module
        try:
            return importlib.import_module("oqs")
        except ImportError as exc:
            raise ShieldV4RealCryptoBackendUnavailable("liboqs-python import oqs is required for ML-DSA") from exc
        except Exception as exc:
            self._raise_oqs_error("import", exc)

    def _raise_oqs_error(self, operation: str, exc: Exception) -> NoReturn:
        raise ShieldV4RealCryptoBackendError(f"OQS ML-DSA {operation} failed closed") from exc

    def _require_mechanism_enabled(self) -> Any:
        oqs = self._load_oqs()
        try:
            enabled = tuple(getattr(oqs, "get_enabled_sig_mechanisms", lambda: ())())
        except Exception as exc:
            self._raise_oqs_error("mechanism discovery", exc)
        if self.mechanism not in enabled:
            raise ShieldV4RealCryptoBackendUnavailable("OQS ML-DSA-65 mechanism is not enabled")
        return oqs

    def _require_bytes(self, value: Any, *, field: str) -> bytes:
        if not isinstance(value, bytes) or not value:
            raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty bytes")
        return value

    def _require_expected_binary_length(
        self,
        value: bytes,
        *,
        details: Any,
        detail_key: str,
        field: str,
    ) -> None:
        if details is None:
            return
        if not isinstance(details, dict):
            raise ShieldV4RealCryptoBackendError("OQS ML-DSA details must be a mapping")
        expected = details.get(detail_key)
        if expected is None:
            return
        if isinstance(expected, bool) or not isinstance(expected, int) or expected <= 0:
            raise ShieldV4RealCryptoBackendError(f"OQS ML-DSA {detail_key} must be a positive integer")
        if len(value) != expected:
            raise ShieldV4RealCryptoBackendError(f"{field} byte length must be {expected} for OQS ML-DSA-65")

    def _resolve_private_key(self, private_key_reference: str) -> bytes:
        clean_reference = reject_test_only_private_key_reference(private_key_reference)
        try:
            secret_key = self._private_key_resolver(clean_reference)
        except Exception as exc:
            self._raise_oqs_error("private key resolution", exc)
        return self._require_bytes(secret_key, field="secret_key")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        """Sign Shield v4 evidence bytes using OQS ML-DSA-65."""

        if algorithm != OQS_ML_DSA_ALGORITHM:
            raise ShieldV4RealCryptoBackendUnavailable("OQS backend only supports Shield v4 ml-dsa")
        message_bytes = self._require_bytes(message, field="message")
        secret_key = self._resolve_private_key(private_key_reference)
        oqs = self._require_mechanism_enabled()
        try:
            with oqs.Signature(self.mechanism, secret_key) as signer:
                signature = signer.sign(message_bytes)
        except Exception as exc:
            self._raise_oqs_error("sign", exc)
        else:
            return encode_binary_signature_material(self._require_bytes(signature, field="signature"), field="signature")

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        """Verify a Shield v4 ML-DSA signature using OQS ML-DSA-65."""

        if algorithm != OQS_ML_DSA_ALGORITHM:
            raise ShieldV4RealCryptoBackendUnavailable("OQS backend only supports Shield v4 ml-dsa")
        message_bytes = self._require_bytes(message, field="message")
        public_key_bytes = decode_binary_signature_material(public_key, field="public_key")
        signature_bytes = decode_binary_signature_material(signature, field="signature")
        oqs = self._require_mechanism_enabled()
        try:
            with oqs.Signature(self.mechanism) as verifier:
                details = getattr(verifier, "details", None)
                self._require_expected_binary_length(
                    public_key_bytes,
                    details=details,
                    detail_key="length_public_key",
                    field="public_key",
                )
                self._require_expected_binary_length(
                    signature_bytes,
                    details=details,
                    detail_key="length_signature",
                    field="signature",
                )
                verified = verifier.verify(message_bytes, signature_bytes, public_key_bytes)
        except ShieldV4RealCryptoBackendError:
            raise
        except Exception as exc:
            self._raise_oqs_error("verify", exc)
        else:
            if not isinstance(verified, bool):
                raise ShieldV4RealCryptoBackendError("OQS ML-DSA verify must return bool")
            return verified
