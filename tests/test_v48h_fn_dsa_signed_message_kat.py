from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shield_orchestrator.v4.crypto_algorithms import FIPS206_DRAFT_FALCON1024_PROFILE
from shield_orchestrator.v4.real_crypto_backend import build_real_crypto_signature_input

KAT_PATH = Path(__file__).resolve().parent / "fixtures" / "v4" / "fn_dsa_signed_message_draft_profile_kat.json"


def test_v48h_fn_dsa_signed_message_draft_profile_kat_is_frozen() -> None:
    kat = json.loads(KAT_PATH.read_text(encoding="utf-8"))
    message = build_real_crypto_signature_input(
        algorithm=kat["algorithm"],
        standard_profile=kat["standard_profile"],
        domain_tag=kat["domain_tag"],
        signed_payload_hash=kat["signed_payload_hash"],
        key_id=kat["key_id"],
        key_version=kat["key_version"],
    )

    assert kat["author_attribution"] == "DarekDGB"
    assert kat["schema_version"] == "shield.v4.8h.fn_dsa_signed_message_kat.v1"
    assert kat["algorithm"] == "fn-dsa"
    assert kat["standard_profile"] == FIPS206_DRAFT_FALCON1024_PROFILE
    assert kat["falcon_parameter_set"] == "Falcon-1024"
    assert kat["message_utf8"] == message.decode("utf-8")
    assert kat["message_hex"] == message.hex()
    assert kat["message_sha256"] == hashlib.sha256(message).hexdigest()
    assert "fips206-draft-falcon1024-v1" in kat["message_utf8"]
    assert "production" in kat["warning"]
