from __future__ import annotations

import copy

import pytest

from shield_orchestrator.v4 import CANONICALIZATION_PROFILE, POLICY_VERSION, VERDICT_SCHEMA_VERSION
from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.component_verdicts import (
    COMPONENT_ROLES,
    SUPPORTED_COMPONENTS,
    build_test_component_signature_entry,
    component_role_for,
    unsigned_component_payload,
    validate_component_verdict_envelope,
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.key_registry import build_test_registry, load_key_registry
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
        "schema_version": VERDICT_SCHEMA_VERSION,
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
        "canonicalization_profile": CANONICALIZATION_PROFILE,
        "signature_policy": POLICY_VERSION,
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


def signed_components() -> list[dict[str, object]]:
    return [signed_component(component_id) for component_id in reversed(SUPPORTED_COMPONENTS)]


def test_v4_orchestrator_verifies_all_valid_signed_components():
    verified, summaries = verify_component_verdicts(
        signed_components(),
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time=VERIFICATION_TIME,
        verifier=verify_test_only_component_signature,
    )
    assert [item["component_id"] for item in verified] == list(SUPPORTED_COMPONENTS)
    assert [item["component_id"] for item in summaries] == list(SUPPORTED_COMPONENTS)
    assert all(item["verified"] is True for item in summaries)
    assert summaries[0]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]


def test_v4_orchestrator_rejects_unsigned_component():
    component = signed_component("qwg")
    component.pop("signature_bundle")
    with pytest.raises(ValueError, match="fields"):
        validate_component_verdict_envelope(
            component,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_orchestrator_rejects_wrong_component_key():
    component = signed_component("adn")
    component["signature_bundle"]["signatures"][0]["key_id"] = "test-shield_component_qwg-classical-ed25519-v1"
    with pytest.raises(ValueError, match="trusted key"):
        validate_component_verdict_envelope(
            component,
            expected_context_hash=CTX,
            registry=load_key_registry(build_test_registry()),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_orchestrator_rejects_signature_context_mismatch():
    component = signed_component("dqsn")
    component["context_hash"] = "c" * 64
    with pytest.raises(ValueError, match="context_hash mismatch"):
        validate_component_verdict_envelope(
            component,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_orchestrator_rejects_component_downgrade_to_v3():
    with pytest.raises(ValueError, match="fields"):
        validate_component_verdict_envelope(
            {
                "component_id": "qwg",
                "schema_version": "shield.verdict.v1",
                "contract_version": 3,
                "context_hash": CTX,
                "decision": "ALLOW",
            },
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_orchestrator_rejects_duplicate_and_missing_component_set():
    duplicate = signed_components()
    duplicate[-1] = signed_component("qwg")
    with pytest.raises(ValueError, match="duplicate"):
        verify_component_verdicts(
            duplicate,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )
    with pytest.raises(ValueError, match="every required"):
        verify_component_verdicts(
            signed_components()[:-1],
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_component_verdict_shape_and_policy_edges():
    base = signed_component("guardian_wallet")
    mutations = [
        lambda item: item.__setitem__("component_id", "bad"),
        lambda item: item.__setitem__("contract_version", 3),
        lambda item: item.__setitem__("schema_version", "bad"),
        lambda item: item.__setitem__("canonicalization_profile", "bad"),
        lambda item: item.__setitem__("signature_policy", "policy.v0"),
        lambda item: item.__setitem__("fail_closed", False),
        lambda item: item.__setitem__("decision", "MAYBE"),
        lambda item: item.__setitem__("metadata", []),
        lambda item: item.__setitem__("metadata", {"events": [{"override": True}]}),
        lambda item: item.__setitem__("request_id", ""),
        lambda item: item.__setitem__("context_hash", "bad"),
        lambda item: item.__setitem__("context_hash", "A" * 64),
        lambda item: item.__setitem__("freshness_nonce", ""),
        lambda item: item.__setitem__("not_before", ""),
        lambda item: item.__setitem__("not_after", ""),
        lambda item: item.__setitem__("reason_ids", []),
        lambda item: item.__setitem__("reason_ids", ["GW_OK_HEALTHY_ALLOW", "GW_OK_HEALTHY_ALLOW"]),
        lambda item: item.__setitem__("evidence_hash", "g" * 64),
        lambda item: item.__setitem__("evidence_hash", "B" * 64),
        lambda item: item.__setitem__("evidence_families", []),
        lambda item: item.__setitem__("evidence_families", ["wallet_context", "wallet_context"]),
        lambda item: item.__setitem__("key_registry_version", 0),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(base)
        mutate(candidate)
        with pytest.raises(ValueError):
            unsigned_component_payload(candidate)
    with pytest.raises(ValueError, match="must be dict"):
        unsigned_component_payload("bad")
    with pytest.raises(ValueError, match="unsupported Shield"):
        component_role_for("bad")
    with pytest.raises(ValueError, match="non-empty"):
        component_role_for("")


def test_v4_component_verdict_rejects_hash_and_registry_mismatch():
    bad_hash = signed_component("qwg")
    bad_hash["signed_payload_hash"] = "d" * 64
    with pytest.raises(ValueError, match="signed payload hash"):
        validate_component_verdict_envelope(
            bad_hash,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )

    bad_registry = signed_component("qwg")
    bad_registry["key_registry_version"] = 2
    rebuilt_payload = unsigned_component_payload(bad_registry)
    bad_registry["signed_payload_hash"] = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=rebuilt_payload)
    for signature in bad_registry["signature_bundle"]["signatures"]:
        signature["signed_payload_hash"] = bad_registry["signed_payload_hash"]
        signature["signature"] = build_test_component_signature_entry(
            component_id="qwg",
            algorithm=signature["algorithm"],
            signed_hash=bad_registry["signed_payload_hash"],
        )["signature"]
    with pytest.raises(ValueError, match="key registry version"):
        validate_component_verdict_envelope(
            bad_registry,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time=VERIFICATION_TIME,
            verifier=verify_test_only_component_signature,
        )


def test_v4_component_signature_helpers_reject_bad_inputs_and_unknown_role():
    with pytest.raises(ValueError, match="supported"):
        build_test_component_signature_entry(component_id="qwg", algorithm="bad", signed_hash="d" * 64)
    with pytest.raises(ValueError, match="sha256"):
        build_test_component_signature_entry(component_id="qwg", algorithm="ml-dsa", signed_hash="g" * 64)
    entry = build_test_component_signature_entry(component_id="qwg", algorithm="ml-dsa", signed_hash="d" * 64)
    wrong_key = load_key_registry(
        {
            "schema_version": "shield.key_registry.v1",
            "registry_version": 1,
            "entries": [
                {
                    "role": "shield_orchestrator",
                    "key_id": "test-shield_orchestrator-ml-dsa-v1",
                    "key_version": 1,
                    "algorithm": "ml-dsa",
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                    "status": "active",
                    "public_key": "TEST-ONLY-PUBLIC-shield_orchestrator-ml-dsa-v1",
                }
            ],
        }
    ).entries[0]
    assert verify_test_only_component_signature(entry, wrong_key) is False
    assert set(COMPONENT_ROLES) == set(SUPPORTED_COMPONENTS)
