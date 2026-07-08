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

OQS_FALCON_ALGORITHM = "fn-dsa"
OQS_FALCON_MECHANISM = "Falcon-1024"
OQS_BACKEND_NAME = "open-quantum-safe-liboqs-python"

PrivateKeyResolver = Callable[[str], bytes]


class OqsFalcon1024Backend:
    """liboqs-python backed Falcon-1024 signer/verifier for optional FN-DSA evidence.

    This backend maps Shield policy algorithm ``fn-dsa`` with standard profile
    ``fips206-draft-falcon1024-v1`` to the liboqs round-3 mechanism
    ``Falcon-1024``. It signs and verifies Shield evidence bytes only; it does
    not sign transactions and does not broadcast anything. It is not a final
    FIPS 206 claim.
    """

    supported_algorithms = (OQS_FALCON_ALGORITHM,)

    def __init__(
        self,
        *,
        private_key_resolver: PrivateKeyResolver,
        oqs_module: ModuleType | Any | None = None,
        mechanism: str = OQS_FALCON_MECHANISM,
    ) -> None:
        if not callable(private_key_resolver):
            raise ShieldV4RealCryptoBackendError("private_key_resolver must be callable")
        if mechanism != OQS_FALCON_MECHANISM:
            raise ShieldV4RealCryptoBackendError("Shield v4.8H requires OQS Falcon-1024 for draft FN-DSA evidence")
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
            raise ShieldV4RealCryptoBackendUnavailable("liboqs-python import oqs is required for Falcon-1024") from exc
        except Exception as exc:
            self._raise_oqs_error("import", exc)

    def _raise_oqs_error(self, operation: str, exc: Exception) -> NoReturn:
        raise ShieldV4RealCryptoBackendError(f"OQS Falcon-1024 {operation} failed closed") from exc

    def _require_mechanism_enabled(self) -> Any:
        oqs = self._load_oqs()
        try:
            enabled = tuple(getattr(oqs, "get_enabled_sig_mechanisms", lambda: ())())
        except Exception as exc:
            self._raise_oqs_error("mechanism discovery", exc)
        if self.mechanism not in enabled:
            raise ShieldV4RealCryptoBackendUnavailable("OQS Falcon-1024 mechanism is not enabled")
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
        allow_shorter: bool = False,
    ) -> None:
        if details is None:
            return
        if not isinstance(details, dict):
            raise ShieldV4RealCryptoBackendError("OQS Falcon-1024 details must be a mapping")
        expected = details.get(detail_key)
        if expected is None:
            return
        if isinstance(expected, bool) or not isinstance(expected, int) or expected <= 0:
            raise ShieldV4RealCryptoBackendError(f"OQS Falcon-1024 {detail_key} must be a positive integer")
        actual = len(value)
        if allow_shorter:
            if actual > expected:
                raise ShieldV4RealCryptoBackendError(f"{field} byte length must be <= {expected} for OQS Falcon-1024")
            return
        if actual != expected:
            raise ShieldV4RealCryptoBackendError(f"{field} byte length must be {expected} for OQS Falcon-1024")

    def _resolve_private_key(self, private_key_reference: str) -> bytes:
        clean_reference = reject_test_only_private_key_reference(private_key_reference)
        try:
            secret_key = self._private_key_resolver(clean_reference)
        except Exception as exc:
            self._raise_oqs_error("private key resolution", exc)
        return self._require_bytes(secret_key, field="secret_key")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        """Sign Shield v4 evidence bytes using OQS Falcon-1024."""

        if algorithm != OQS_FALCON_ALGORITHM:
            raise ShieldV4RealCryptoBackendUnavailable("OQS Falcon backend only supports Shield v4 fn-dsa")
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
        """Verify a Shield v4 FN-DSA/Falcon-1024 signature using liboqs."""

        if algorithm != OQS_FALCON_ALGORITHM:
            raise ShieldV4RealCryptoBackendUnavailable("OQS Falcon backend only supports Shield v4 fn-dsa")
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
                    allow_shorter=True,
                )
                verified = verifier.verify(message_bytes, signature_bytes, public_key_bytes)
        except ShieldV4RealCryptoBackendError:
            raise
        except Exception as exc:
            self._raise_oqs_error("verify", exc)
        else:
            if not isinstance(verified, bool):
                raise ShieldV4RealCryptoBackendError("OQS Falcon-1024 verify must return bool")
            return verified
