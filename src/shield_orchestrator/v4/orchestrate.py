from __future__ import annotations

import hmac
from typing import Any

from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.component_verdicts import (
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import (
    build_signed_receipt_envelope,
    build_unsigned_receipt_payload,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import KeyRegistry, KeyRegistryEntry, load_key_registry
from shield_orchestrator.v4.signature_bundle import build_signature_bundle

DENYING_COMPONENT_DECISIONS = {"DENY", "ERROR"}
ESCALATING_COMPONENT_DECISIONS = {"ESCALATE", "SKIPPED"}


def _dominant_reason_ids(component_verdicts: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for verdict in component_verdicts:
        if verdict["decision"] != "ALLOW":
            reasons.extend(verdict["reason_ids"])
    if not reasons:
        return ["ORCH_OK_ALL_COMPONENTS_ALLOW"]
    return sorted(dict.fromkeys(reasons))


def _final_outcome(component_verdicts: list[dict[str, Any]]) -> str:
    decisions = {verdict["decision"] for verdict in component_verdicts}
    if decisions & DENYING_COMPONENT_DECISIONS:
        return "DENY"
    if decisions & ESCALATING_COMPONENT_DECISIONS:
        return "HUMAN_REVIEW_REQUIRED"
    return "ALLOW"


def build_test_only_orchestrator_signature_entry(*, algorithm: str, signed_hash: str) -> dict[str, Any]:
    key_id = f"test-shield_orchestrator-{algorithm}-v1"
    key_version = 1
    standard_profile = default_standard_profile_for_algorithm(algorithm)
    public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
    return {
        "algorithm": algorithm,
        "standard_profile": standard_profile,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": signed_hash,
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signature": hmac.new(
            public_key.encode("utf-8"),
            f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{signed_hash}|{algorithm}|{standard_profile}|{key_id}|{key_version}".encode("utf-8"),
            "sha256",
        ).hexdigest(),
    }


def verify_test_only_orchestrator_signature(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
    expected = hmac.new(
        key.public_key.encode("utf-8"),
        f"{entry['domain_tag']}|{entry['signed_payload_hash']}|{entry['algorithm']}|{entry['standard_profile']}|{entry['key_id']}|{entry['key_version']}".encode("utf-8"),
        "sha256",
    ).hexdigest()
    return hmac.compare_digest(entry["signature"], expected)


def build_test_only_signed_v4_receipt(
    *,
    component_verdicts: list[dict[str, Any]],
    expected_context_hash: str,
    registry: KeyRegistry | dict[str, Any],
    verification_time: str,
    request_id: str,
    freshness_nonce: str,
    not_before: str,
    not_after: str,
    adamantineos_handoff: dict[str, Any],
    include_optional_fn_dsa: bool = False,
) -> dict[str, Any]:
    loaded_registry = load_key_registry(registry) if isinstance(registry, dict) else registry
    verified_components, component_signature_results = verify_component_verdicts(
        component_verdicts,
        expected_context_hash=expected_context_hash,
        registry=loaded_registry,
        verification_time=verification_time,
        verifier=verify_test_only_component_signature,
    )
    unsigned_payload = build_unsigned_receipt_payload(
        request_id=request_id,
        context_hash=expected_context_hash,
        freshness_nonce=freshness_nonce,
        not_before=not_before,
        not_after=not_after,
        component_verdicts=verified_components,
        component_signature_results=component_signature_results,
        final_outcome=_final_outcome(verified_components),
        dominant_reason_ids=_dominant_reason_ids(verified_components),
        key_registry_version=loaded_registry.registry_version,
        adamantineos_handoff=adamantineos_handoff,
    )
    shell = build_signed_receipt_envelope(
        unsigned_payload=unsigned_payload,
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=[]),
    )
    algorithms = ["classical-ed25519", "ml-dsa"]
    if include_optional_fn_dsa:
        algorithms.append("fn-dsa")
    signatures = [
        build_test_only_orchestrator_signature_entry(
            algorithm=algorithm,
            signed_hash=shell["signed_payload_hash"],
        )
        for algorithm in algorithms
    ]
    receipt = build_signed_receipt_envelope(
        unsigned_payload=unsigned_payload,
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    )
    return validate_receipt_envelope(
        receipt,
        expected_context_hash=expected_context_hash,
        registry=loaded_registry,
        verification_time=verification_time,
        verifier=verify_test_only_orchestrator_signature,
    )
