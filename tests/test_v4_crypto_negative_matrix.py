from __future__ import annotations

import copy
import hmac

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.contracts.v4_receipt import (
    SUPPORTED_COMPONENTS,
    build_signed_receipt_envelope,
    build_unsigned_receipt_payload,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import build_test_registry
from shield_orchestrator.v4.signature_bundle import build_signature_bundle

CTX = "a" * 64


def _test_verifier(entry, key):
    expected = hmac.new(
        key.public_key.encode("utf-8"),
        f"{entry['domain_tag']}|{entry['signed_payload_hash']}|{entry['algorithm']}|{entry['standard_profile']}|{entry['key_id']}|{entry['key_version']}".encode("utf-8"),
        "sha256",
    ).hexdigest()
    return hmac.compare_digest(entry["signature"], expected)


def component_verdicts() -> list[dict[str, object]]:
    return [
        {
            "component_id": component,
            "schema_version": "shield.verdict.v2",
            "contract_version": 4,
            "context_hash": CTX,
            "decision": "ALLOW",
        }
        for component in reversed(SUPPORTED_COMPONENTS)
    ]


def component_signature_results() -> list[dict[str, object]]:
    return [{"component_id": component, "verified": True} for component in reversed(SUPPORTED_COMPONENTS)]


def signature_for(algorithm: str, payload_hash: str) -> dict[str, object]:
    key_id = f"test-shield_orchestrator-{algorithm}-v1"
    key_version = 1
    standard_profile = default_standard_profile_for_algorithm(algorithm)
    public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
    return {
        "algorithm": algorithm,
        "standard_profile": standard_profile,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": payload_hash,
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signature": hmac.new(
            public_key.encode("utf-8"),
            f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{payload_hash}|{algorithm}|{standard_profile}|{key_id}|{key_version}".encode("utf-8"),
            "sha256",
        ).hexdigest(),
    }


def signed_receipt() -> dict[str, object]:
    unsigned = build_unsigned_receipt_payload(
        request_id="req-v4-kat",
        context_hash=CTX,
        freshness_nonce="nonce-v4-kat",
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        component_verdicts=component_verdicts(),
        component_signature_results=component_signature_results(),
        final_outcome="ALLOW",
        dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        key_registry_version=1,
        adamantineos_handoff={"handoff_allowed": True, "handoff_reason": "ORCH_OK_ALL_COMPONENTS_ALLOW"},
    )
    shell = build_signed_receipt_envelope(
        unsigned_payload=unsigned,
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=[]),
    )
    signatures = [signature_for("classical-ed25519", shell["signed_payload_hash"]), signature_for("ml-dsa", shell["signed_payload_hash"])]
    return build_signed_receipt_envelope(
        unsigned_payload=unsigned,
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    )


def assert_rejected(receipt: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        validate_receipt_envelope(
            receipt,
            expected_context_hash=CTX,
            registry=build_test_registry(),
            verification_time="2026-06-21T00:01:00Z",
            verifier=_test_verifier,
        )


def test_v4_negative_matrix_rejects_signature_and_policy_abuse():
    base = signed_receipt()
    mutations = [
        lambda item: item["signature_bundle"].__setitem__("signatures", []),
        lambda item: item["signature_bundle"]["signatures"].pop(),
        lambda item: item["signature_bundle"]["signatures"][0].__setitem__("algorithm", "fn-dsa"),
        lambda item: item["signature_bundle"]["signatures"][0].__setitem__("domain_tag", COMPONENT_VERDICT_DOMAIN),
        lambda item: item["signature_bundle"]["signatures"][0].__setitem__("key_id", "test-shield_component_qwg-classical-ed25519-v1"),
        lambda item: item["signature_bundle"]["signatures"][0].__setitem__("signature", "00"),
        lambda item: item["signature_bundle"].__setitem__("policy_version", "policy.v0"),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(base)
        mutate(candidate)
        assert_rejected(candidate)


def test_v4_negative_matrix_rejects_payload_tamper_and_replay_fields():
    base = signed_receipt()
    mutations = [
        lambda item: item.__setitem__("request_id", "req-splice"),
        lambda item: item.__setitem__("freshness_nonce", "nonce-splice"),
        lambda item: item.__setitem__("not_after", "2026-06-21T00:10:00Z"),
        lambda item: item["component_verdicts"][0].__setitem__("decision", "DENY"),
        lambda item: item["component_signature_results"][0].__setitem__("verified", False),
        lambda item: item.__setitem__("final_outcome", "DENY"),
        lambda item: item.__setitem__("dominant_reason_ids", ["ORCH_DENY_DOMINATES"]),
        lambda item: item["adamantineos_handoff"].__setitem__("handoff_allowed", False),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(base)
        mutate(candidate)
        assert_rejected(candidate)


def test_v4_negative_matrix_rejects_v3_downgrade_and_future_or_stale_windows():
    receipt = signed_receipt()
    receipt["schema_version"] = "shield.receipt.v1"
    receipt["contract_version"] = 3
    assert_rejected(receipt)

    future = signed_receipt()
    future["not_before"] = "2031-01-01T00:00:00Z"
    future["not_after"] = "2031-01-01T00:05:00Z"
    assert_rejected(future)

    stale = signed_receipt()
    stale["not_before"] = "2025-01-01T00:00:00Z"
    stale["not_after"] = "2025-01-01T00:05:00Z"
    assert_rejected(stale)
