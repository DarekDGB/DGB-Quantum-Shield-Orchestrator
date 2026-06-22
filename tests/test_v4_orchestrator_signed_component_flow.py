from __future__ import annotations

import copy

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.component_verdicts import (
    SUPPORTED_COMPONENTS,
    build_test_component_signature_entry,
)
from shield_orchestrator.v4.key_registry import build_test_registry
from shield_orchestrator.v4.orchestrate import (
    build_test_only_orchestrator_signature_entry,
    build_test_only_signed_v4_receipt,
    verify_test_only_orchestrator_signature,
)
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


def unsigned_component(component_id: str, *, decision: str = "ALLOW") -> dict[str, object]:
    return {
        "component_id": component_id,
        "contract_version": 4,
        "schema_version": "shield.verdict.v2",
        "request_id": "req-v4-component",
        "context_hash": CTX,
        "freshness_nonce": f"nonce-{component_id}",
        "not_before": NOT_BEFORE,
        "not_after": NOT_AFTER,
        "decision": decision,
        "reason_ids": [REASONS[component_id]],
        "evidence_hash": EVIDENCE,
        "evidence_families": [EVIDENCE_FAMILIES[component_id]],
        "metadata": {"source": component_id},
        "fail_closed": True,
        "canonicalization_profile": "shield-v4-canon.v1",
        "signature_policy": "policy.v1",
        "key_registry_version": 1,
    }


def signed_component(component_id: str, *, decision: str = "ALLOW") -> dict[str, object]:
    unsigned = unsigned_component(component_id, decision=decision)
    payload_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=unsigned)
    signatures = [
        build_test_component_signature_entry(component_id=component_id, algorithm="classical-ed25519", signed_hash=payload_hash),
        build_test_component_signature_entry(component_id=component_id, algorithm="ml-dsa", signed_hash=payload_hash),
    ]
    return {
        **unsigned,
        "signed_payload_hash": payload_hash,
        "signature_bundle": build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    }


def signed_components(*, decision_overrides: dict[str, str] | None = None) -> list[dict[str, object]]:
    overrides = {} if decision_overrides is None else decision_overrides
    return [signed_component(component_id, decision=overrides.get(component_id, "ALLOW")) for component_id in SUPPORTED_COMPONENTS]


def test_v4_orchestrator_accepts_all_valid_signed_components_and_signs_final_receipt():
    receipt = build_test_only_signed_v4_receipt(
        component_verdicts=signed_components(),
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time=VERIFICATION_TIME,
        request_id="req-v4-final",
        freshness_nonce="nonce-final",
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        adamantineos_handoff={"handoff_allowed": True, "handoff_reason": "ORCH_OK_ALL_COMPONENTS_ALLOW"},
    )
    assert receipt["final_outcome"] == "ALLOW"
    assert receipt["dominant_reason_ids"] == ["ORCH_OK_ALL_COMPONENTS_ALLOW"]
    assert receipt["verification_summary"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert [item["component_id"] for item in receipt["component_signature_results"]] == list(SUPPORTED_COMPONENTS)
    assert all(item["signature_policy"] == "policy.v1" for item in receipt["component_signature_results"])


def test_v4_orchestrator_signed_flow_denies_and_human_reviews_from_component_decisions():
    denied = build_test_only_signed_v4_receipt(
        component_verdicts=signed_components(decision_overrides={"qwg": "DENY"}),
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time=VERIFICATION_TIME,
        request_id="req-v4-deny",
        freshness_nonce="nonce-deny",
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        adamantineos_handoff={"handoff_allowed": False, "handoff_reason": "COMPONENT_DENY"},
    )
    assert denied["final_outcome"] == "DENY"
    assert denied["dominant_reason_ids"] == ["QWG_OK_POSTURE_ALLOW"]

    review = build_test_only_signed_v4_receipt(
        component_verdicts=signed_components(decision_overrides={"adn": "ESCALATE"}),
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time=VERIFICATION_TIME,
        request_id="req-v4-review",
        freshness_nonce="nonce-review",
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        adamantineos_handoff={"handoff_allowed": False, "handoff_reason": "COMPONENT_ESCALATE"},
    )
    assert review["final_outcome"] == "HUMAN_REVIEW_REQUIRED"
    assert review["dominant_reason_ids"] == ["ADN_OK_COORDINATION_ALLOW"]


def test_v4_orchestrator_rejects_component_signature_tampering_before_receipt():
    components = signed_components()
    components[0]["signature_bundle"]["signatures"][0]["signature"] = "00"
    with pytest.raises(ValueError, match="signature verification failed"):
        build_test_only_signed_v4_receipt(
            component_verdicts=components,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            request_id="req-v4-final",
            freshness_nonce="nonce-final",
            not_before=NOT_BEFORE,
            not_after=NOT_AFTER,
            adamantineos_handoff={"handoff_allowed": True},
        )


def test_v4_orchestrator_receipt_signature_helper_detects_tampering():
    registry = build_test_registry()
    signature = build_test_only_orchestrator_signature_entry(algorithm="ml-dsa", signed_hash="d" * 64)
    key = next(entry for entry in registry["entries"] if entry["role"] == "shield_orchestrator" and entry["algorithm"] == "ml-dsa")
    key_obj = type("Key", (), key)()
    assert verify_test_only_orchestrator_signature(signature, key_obj) is True
    tampered = copy.deepcopy(signature)
    tampered["signature"] = "00"
    assert verify_test_only_orchestrator_signature(tampered, key_obj) is False
