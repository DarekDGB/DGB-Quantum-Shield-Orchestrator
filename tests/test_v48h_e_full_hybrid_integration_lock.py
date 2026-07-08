from __future__ import annotations

import copy

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.component_verdicts import (
    SUPPORTED_COMPONENTS,
    build_test_component_signature_entry,
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import build_unsigned_receipt_payload, validate_receipt_envelope
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import build_test_registry
from shield_orchestrator.v4.orchestrate import build_test_only_signed_v4_receipt, verify_test_only_orchestrator_signature
from shield_orchestrator.v4.signature_bundle import build_signature_bundle

CTX = "a" * 64
EVIDENCE = "b" * 64
VERIFICATION_TIME = "2026-06-21T00:01:00Z"
NOT_BEFORE = "2026-06-21T00:00:00Z"
NOT_AFTER = "2026-06-21T00:05:00Z"
REASONS = {
    "adn": "ADN_OK_COORDINATION_ALLOW",
    "dqsn": "DQSN_OK_NETWORK_ALLOW",
    "guardian_wallet": "GW_OK_HEALTHY_ALLOW",
    "qwg": "QWG_OK_POSTURE_ALLOW",
    "sentinel_ai": "SNTL_OK_TELEMETRY_ALLOW",
}
EVIDENCE_FAMILIES = {
    "adn": "defense_signal",
    "dqsn": "network_observation",
    "guardian_wallet": "wallet_context",
    "qwg": "wallet_posture",
    "sentinel_ai": "telemetry",
}
EXPECTED_ALGORITHMS = ["classical-ed25519", "ml-dsa", "fn-dsa"]
EXPECTED_PROFILES = [default_standard_profile_for_algorithm(algorithm) for algorithm in EXPECTED_ALGORITHMS]


def unsigned_component(component_id: str) -> dict[str, object]:
    return {
        "component_id": component_id,
        "contract_version": 4,
        "schema_version": "shield.verdict.v2",
        "request_id": "req-v48h-e-full-hybrid",
        "context_hash": CTX,
        "freshness_nonce": f"nonce-v48h-e-{component_id}",
        "not_before": NOT_BEFORE,
        "not_after": NOT_AFTER,
        "decision": "ALLOW",
        "reason_ids": [REASONS[component_id]],
        "evidence_hash": EVIDENCE,
        "evidence_families": [EVIDENCE_FAMILIES[component_id]],
        "metadata": {"source": component_id, "integration_harness": "shield-v4.8h-e-full-hybrid"},
        "fail_closed": True,
        "canonicalization_profile": "shield-v4-canon.v1",
        "signature_policy": "policy.v1",
        "key_registry_version": 1,
    }


def signed_component(component_id: str) -> dict[str, object]:
    unsigned = unsigned_component(component_id)
    payload_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=unsigned)
    signatures = [
        build_test_component_signature_entry(component_id=component_id, algorithm=algorithm, signed_hash=payload_hash)
        for algorithm in EXPECTED_ALGORITHMS
    ]
    return {
        **unsigned,
        "signed_payload_hash": payload_hash,
        "signature_bundle": build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    }


def signed_components() -> list[dict[str, object]]:
    return [signed_component(component_id) for component_id in SUPPORTED_COMPONENTS]


def full_hybrid_receipt() -> dict[str, object]:
    return build_test_only_signed_v4_receipt(
        component_verdicts=signed_components(),
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time=VERIFICATION_TIME,
        request_id="req-v48h-e-full-hybrid",
        freshness_nonce="nonce-v48h-e-final",
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        adamantineos_handoff={"handoff_allowed": True, "handoff_reason": "ORCH_OK_ALL_COMPONENTS_ALLOW"},
        include_optional_fn_dsa=True,
    )


def test_v48h_e_full_hybrid_fn_dsa_present_everywhere_is_accepted_and_reported() -> None:
    receipt = full_hybrid_receipt()

    assert receipt["final_outcome"] == "ALLOW"
    assert receipt["verification_summary"]["verified_algorithms"] == EXPECTED_ALGORITHMS
    assert receipt["verification_summary"]["verified_standard_profiles"] == EXPECTED_PROFILES
    assert [entry["algorithm"] for entry in receipt["signature_bundle"]["signatures"]] == EXPECTED_ALGORITHMS
    for result in receipt["component_signature_results"]:
        assert result["verified_algorithms"] == EXPECTED_ALGORITHMS
        assert result["verified_standard_profiles"] == EXPECTED_PROFILES


def test_v48h_e_fn_dsa_cannot_rescue_component_required_mldsa_failure() -> None:
    components = signed_components()
    components[0]["signature_bundle"]["signatures"][1]["signature"] = "0" * 64

    with pytest.raises(ValueError, match="signature verification failed"):
        verify_component_verdicts(
            components,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v48h_e_fn_dsa_cannot_rescue_orchestrator_required_mldsa_failure() -> None:
    receipt = copy.deepcopy(full_hybrid_receipt())
    receipt["signature_bundle"]["signatures"][1]["signature"] = "0" * 64

    with pytest.raises(ValueError, match="signature verification failed"):
        validate_receipt_envelope(
            receipt,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_orchestrator_signature,
        )


def test_v48h_e_component_summary_profile_matrix_fails_closed() -> None:
    receipt = full_hybrid_receipt()
    base_kwargs = {
        "request_id": "req-v48h-e-summary-negative",
        "context_hash": CTX,
        "freshness_nonce": "nonce-v48h-e-summary-negative",
        "not_before": NOT_BEFORE,
        "not_after": NOT_AFTER,
        "component_verdicts": receipt["component_verdicts"],
        "component_signature_results": receipt["component_signature_results"],
        "final_outcome": "ALLOW",
        "dominant_reason_ids": ["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        "key_registry_version": 1,
        "adamantineos_handoff": {"handoff_allowed": True},
    }

    bad_algorithms = copy.deepcopy(base_kwargs)
    bad_algorithms["component_signature_results"][0]["verified_algorithms"] = "fn-dsa"
    with pytest.raises(ValueError, match="algorithms must be non-empty strings"):
        build_unsigned_receipt_payload(**bad_algorithms)

    duplicate_algorithm = copy.deepcopy(base_kwargs)
    duplicate_algorithm["component_signature_results"][0]["verified_algorithms"] = ["classical-ed25519", "ml-dsa", "ml-dsa"]
    duplicate_algorithm["component_signature_results"][0]["verified_standard_profiles"] = [
        default_standard_profile_for_algorithm("classical-ed25519"),
        default_standard_profile_for_algorithm("ml-dsa"),
        default_standard_profile_for_algorithm("ml-dsa"),
    ]
    with pytest.raises(ValueError, match="duplicate algorithm"):
        build_unsigned_receipt_payload(**duplicate_algorithm)

    unsupported_algorithm = copy.deepcopy(base_kwargs)
    unsupported_algorithm["component_signature_results"][0]["verified_algorithms"] = ["classical-ed25519", "ml-dsa", "pqc-falcon"]
    unsupported_algorithm["component_signature_results"][0]["verified_standard_profiles"] = [
        default_standard_profile_for_algorithm("classical-ed25519"),
        default_standard_profile_for_algorithm("ml-dsa"),
        "fips206-draft-falcon1024-v1",
    ]
    with pytest.raises(ValueError, match="unsupported algorithm"):
        build_unsigned_receipt_payload(**unsupported_algorithm)
