from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shield_orchestrator.v4.component_verdicts import (
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import validate_receipt_envelope
from shield_orchestrator.v4.orchestrate import verify_test_only_orchestrator_signature

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "v4" / "full_multi_repo_v4_allow_flow.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def receipt_fixture() -> tuple[dict, dict, str, str, str]:
    fixture = load_fixture()
    return (
        fixture["receipt"],
        fixture["trusted_key_registry"],
        fixture["expected_context_hash"],
        fixture["expected_request_id"],
        fixture["verification_time"],
    )


def test_v4_full_multi_repo_fixture_revalidates_all_components_and_final_receipt() -> None:
    receipt, registry, expected_context_hash, expected_request_id, verification_time = receipt_fixture()

    verified_components, component_summaries = verify_component_verdicts(
        receipt["component_verdicts"],
        expected_context_hash=expected_context_hash,
        registry=registry,
        verification_time=verification_time,
        verifier=verify_test_only_component_signature,
    )
    checked_receipt = validate_receipt_envelope(
        receipt,
        expected_context_hash=expected_context_hash,
        registry=registry,
        verification_time=verification_time,
        verifier=verify_test_only_orchestrator_signature,
    )

    assert receipt["request_id"] == expected_request_id
    assert checked_receipt["final_outcome"] == "ALLOW"
    assert checked_receipt["adamantineos_handoff"]["handoff_allowed"] is True
    assert [item["component_id"] for item in verified_components] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert [item["component_id"] for item in component_summaries] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert checked_receipt["verification_summary"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]


def test_v4_full_multi_repo_fixture_rejects_missing_component() -> None:
    receipt, registry, expected_context_hash, _, verification_time = receipt_fixture()
    missing = copy.deepcopy(receipt["component_verdicts"][:-1])

    with pytest.raises(ValueError, match="every required Shield v4 component"):
        verify_component_verdicts(
            missing,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v4_full_multi_repo_fixture_rejects_wrong_component_key() -> None:
    receipt, registry, expected_context_hash, _, verification_time = receipt_fixture()
    tampered = copy.deepcopy(receipt["component_verdicts"])
    tampered[0]["signature_bundle"]["signatures"][0]["key_id"] = "test-shield_component_qwg-classical-ed25519-v1"

    with pytest.raises(ValueError, match="trusted key not found"):
        verify_component_verdicts(
            tampered,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v4_full_multi_repo_fixture_rejects_signature_context_mismatch() -> None:
    receipt, registry, _, _, verification_time = receipt_fixture()

    with pytest.raises(ValueError, match="context_hash mismatch"):
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash="b" * 64,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v4_full_multi_repo_fixture_rejects_component_downgrade_to_v3() -> None:
    receipt, registry, expected_context_hash, _, verification_time = receipt_fixture()
    downgraded = copy.deepcopy(receipt["component_verdicts"])
    downgraded[0]["contract_version"] = 3

    with pytest.raises(ValueError, match="contract mismatch"):
        verify_component_verdicts(
            downgraded,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v4_full_multi_repo_fixture_rejects_tampered_final_receipt() -> None:
    receipt, registry, expected_context_hash, _, verification_time = receipt_fixture()
    tampered_signature = copy.deepcopy(receipt)
    tampered_signature["signature_bundle"]["signatures"][0]["signature"] = "0" * 64

    with pytest.raises(ValueError, match="signature verification failed"):
        validate_receipt_envelope(
            tampered_signature,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_orchestrator_signature,
        )

    tampered_hash = copy.deepcopy(receipt)
    tampered_hash["receipt_hash"] = "0" * 64
    with pytest.raises(ValueError, match="receipt hash mismatch"):
        validate_receipt_envelope(
            tampered_hash,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_orchestrator_signature,
        )
