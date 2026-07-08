from __future__ import annotations

import os

import pytest

if os.environ.get("SHIELD_V4_REAL_OQS_FALCON") != "1":
    pytest.skip("set SHIELD_V4_REAL_OQS_FALCON=1 to run the real liboqs Falcon-1024 proof", allow_module_level=True)

try:
    oqs = pytest.importorskip("oqs")
except SystemExit as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)
except Exception as exc:
    pytest.skip(f"could not import oqs/liboqs: {exc}", allow_module_level=True)

from shield_orchestrator.v4.oqs_falcon_backend import OQS_FALCON_MECHANISM, OqsFalcon1024Backend  # noqa: E402
from shield_orchestrator.v4.real_crypto_backend import (  # noqa: E402
    decode_binary_signature_material,
    encode_binary_signature_material,
)

MESSAGE = b"DGB Shield v4.8H-E real liboqs Falcon-1024 proof"
PRIVATE_KEY_REFERENCE = "hsm://shield-orchestrator/fn-dsa-falcon1024/v1"


def _generate_falcon_keypair() -> tuple[bytes, bytes]:
    with oqs.Signature(OQS_FALCON_MECHANISM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    assert isinstance(public_key, bytes) and public_key
    assert isinstance(secret_key, bytes) and secret_key
    return public_key, secret_key


def _tamper(encoded_signature: str) -> str:
    raw = bytearray(decode_binary_signature_material(encoded_signature, field="signature"))
    assert raw
    raw[0] ^= 0x01
    return encode_binary_signature_material(bytes(raw), field="signature")


def test_v48h_e_real_oqs_falcon1024_backend_round_trip_and_negatives() -> None:
    assert OQS_FALCON_MECHANISM in tuple(oqs.get_enabled_sig_mechanisms())

    public_key, secret_key = _generate_falcon_keypair()
    other_public_key, _ = _generate_falcon_keypair()
    backend = OqsFalcon1024Backend(private_key_resolver=lambda reference: secret_key)

    signature = backend.sign_message(
        algorithm="fn-dsa",
        private_key_reference=PRIVATE_KEY_REFERENCE,
        message=MESSAGE,
    )
    public_key_b64u = encode_binary_signature_material(public_key, field="public_key")

    assert backend.verify_signature(
        algorithm="fn-dsa",
        public_key=public_key_b64u,
        message=MESSAGE,
        signature=signature,
    ) is True
    assert backend.verify_signature(
        algorithm="fn-dsa",
        public_key=public_key_b64u,
        message=MESSAGE,
        signature=_tamper(signature),
    ) is False
    assert backend.verify_signature(
        algorithm="fn-dsa",
        public_key=encode_binary_signature_material(other_public_key, field="public_key"),
        message=MESSAGE,
        signature=signature,
    ) is False
