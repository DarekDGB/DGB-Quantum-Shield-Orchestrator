from __future__ import annotations

import os

import pytest

if os.environ.get("SHIELD_V4_REAL_OQS") != "1":
    pytest.skip("set SHIELD_V4_REAL_OQS=1 to run the real liboqs ML-DSA proof", allow_module_level=True)

try:
    oqs = pytest.importorskip("oqs")
except SystemExit as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)
except Exception as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)

from shield_orchestrator.v4.oqs_mldsa_backend import OQS_ML_DSA_MECHANISM, OqsMlDsaBackend  # noqa: E402
from shield_orchestrator.v4.real_crypto_backend import (  # noqa: E402
    ShieldV4RealCryptoBackendError,
    decode_binary_signature_material,
    encode_binary_signature_material,
)

MESSAGE = b"DGB Shield v4.8G real liboqs ML-DSA proof: orchestrator"
PRIVATE_KEY_REFERENCE = "hsm://shield-orchestrator/real-oqs-ml-dsa/v1"


def _generate_mldsa65_keypair() -> tuple[bytes, bytes]:
    with oqs.Signature(OQS_ML_DSA_MECHANISM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    assert isinstance(public_key, bytes) and public_key
    assert isinstance(secret_key, bytes) and secret_key
    return public_key, secret_key


def _tamper(encoded_signature: str) -> str:
    signature = bytearray(decode_binary_signature_material(encoded_signature, field="signature"))
    assert signature
    signature[0] ^= 0x01
    return encode_binary_signature_material(bytes(signature), field="signature")


def test_v48g_real_oqs_mldsa65_orchestrator_backend_round_trip_and_negatives() -> None:
    assert OQS_ML_DSA_MECHANISM in tuple(oqs.get_enabled_sig_mechanisms())

    public_key, secret_key = _generate_mldsa65_keypair()
    other_public_key, _ = _generate_mldsa65_keypair()
    backend = OqsMlDsaBackend(private_key_resolver=lambda reference: secret_key)

    signature = backend.sign_message(
        algorithm="ml-dsa",
        private_key_reference=PRIVATE_KEY_REFERENCE,
        message=MESSAGE,
    )
    public_key_b64u = encode_binary_signature_material(public_key, field="public_key")

    assert backend.verify_signature(
        algorithm="ml-dsa",
        public_key=public_key_b64u,
        message=MESSAGE,
        signature=signature,
    ) is True

    assert backend.verify_signature(
        algorithm="ml-dsa",
        public_key=public_key_b64u,
        message=MESSAGE,
        signature=_tamper(signature),
    ) is False

    assert backend.verify_signature(
        algorithm="ml-dsa",
        public_key=encode_binary_signature_material(other_public_key, field="public_key"),
        message=MESSAGE,
        signature=signature,
    ) is False

    with pytest.raises(ShieldV4RealCryptoBackendError, match="public_key byte length"):
        backend.verify_signature(
            algorithm="ml-dsa",
            public_key=encode_binary_signature_material(public_key[:-1], field="public_key"),
            message=MESSAGE,
            signature=signature,
        )
