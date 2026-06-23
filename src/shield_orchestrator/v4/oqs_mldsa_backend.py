from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType
from typing import Any

from shield_orchestrator.v4.real_crypto_backend import (
    ShieldV4RealCryptoBackendError,
    ShieldV4RealCryptoBackendUnavailable,
    decode_binary_signature_material,
    encode_binary_signature_material,
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
        oqs_version = getattr(oqs, "oqs_version", lambda: "unknown")()
        python_version = getattr(oqs, "oqs_python_version", lambda: "unknown")()
        return f"liboqs={oqs_version};liboqs-python={python_version};mechanism={self.mechanism}"

    def _load_oqs(self) -> Any:
        if self._oqs_module is not None:
            return self._oqs_module
        try:
            return importlib.import_module("oqs")
        except ImportError as exc:
            raise ShieldV4RealCryptoBackendUnavailable("liboqs-python import oqs is required for ML-DSA") from exc

    def _require_mechanism_enabled(self) -> Any:
        oqs = self._load_oqs()
        enabled = getattr(oqs, "get_enabled_sig_mechanisms", lambda: ())()
        if self.mechanism not in tuple(enabled):
            raise ShieldV4RealCryptoBackendUnavailable("OQS ML-DSA-65 mechanism is not enabled")
        return oqs

    def _require_bytes(self, value: Any, *, field: str) -> bytes:
        if not isinstance(value, bytes) or not value:
            raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty bytes")
        return value

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        """Sign Shield v4 evidence bytes using OQS ML-DSA-65."""

        if algorithm != OQS_ML_DSA_ALGORITHM:
            raise ShieldV4RealCryptoBackendUnavailable("OQS backend only supports Shield v4 ml-dsa")
        message_bytes = self._require_bytes(message, field="message")
        secret_key = self._require_bytes(self._private_key_resolver(private_key_reference), field="secret_key")
        oqs = self._require_mechanism_enabled()
        with oqs.Signature(self.mechanism, secret_key) as signer:
            signature = signer.sign(message_bytes)
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
        with oqs.Signature(self.mechanism) as verifier:
            return bool(verifier.verify(message_bytes, signature_bytes, public_key_bytes))
