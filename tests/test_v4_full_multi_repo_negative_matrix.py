from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.component_verdicts import (
    build_test_component_signature_entry,
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import (
    UNSIGNED_RECEIPT_EXCLUDED_FIELDS,
    _validate_receipt_payload_semantics,
    build_receipt_hash,
    build_unsigned_receipt_payload,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.orchestrate import verify_test_only_orchestrator_signature

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "v4" / "full_multi_repo_v4_allow_flow.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def fixture_parts() -> tuple[dict, dict, str, str]:
    fixture = load_fixture()
    return (
        fixture["receipt"],
        fixture["trusted_key_registry"],
        fixture["expected_context_hash"],
        fixture["verification_time"],
    )


def unsigned_receipt_payload(receipt: dict) -> dict:
    return {key: receipt[key] for key in receipt if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS}


def refresh_receipt_hashes_without_resigning(receipt: dict) -> None:
    unsigned = unsigned_receipt_payload(receipt)
    receipt["receipt_hash"] = build_receipt_hash(unsigned)
    receipt["signed_payload_hash"] = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned)


def assert_components_rejected(component_verdicts: list[dict], match: str) -> None:
    _, registry, expected_context_hash, verification_time = fixture_parts()
    with pytest.raises(ValueError, match=match):
        verify_component_verdicts(
            component_verdicts,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v48b_orchestrator_rejects_pqc_required_signature_stripped_even_with_fn_dsa_present() -> None:
    receipt, _, _, _ = fixture_parts()
    components = copy.deepcopy(receipt["component_verdicts"])
    component = components[0]
    component["signature_bundle"]["signatures"] = [
        entry
        for entry in component["signature_bundle"]["signatures"]
        if entry["algorithm"] == "classical-ed25519"
    ]
    component["signature_bundle"]["signatures"].append(
        build_test_component_signature_entry(
            component_id=component["component_id"],
            algorithm="fn-dsa",
            signed_hash=component["signed_payload_hash"],
        )
    )

    assert_components_rejected(components, "requirements")


def test_v48b_orchestrator_rejects_duplicate_component_signature_algorithm() -> None:
    receipt, _, _, _ = fixture_parts()
    components = copy.deepcopy(receipt["component_verdicts"])
    components[0]["signature_bundle"]["signatures"].append(
        copy.deepcopy(components[0]["signature_bundle"]["signatures"][0])
    )

    assert_components_rejected(components, "duplicate signature algorithm")


def test_v48b_orchestrator_rejects_component_domain_replay() -> None:
    receipt, _, _, _ = fixture_parts()
    components = copy.deepcopy(receipt["component_verdicts"])
    components[0]["signature_bundle"]["signatures"][0]["domain_tag"] = ORCHESTRATOR_RECEIPT_DOMAIN

    assert_components_rejected(components, "domain tag mismatch")


def test_v48b_orchestrator_rejects_revoked_and_out_of_window_component_keys() -> None:
    receipt, registry, expected_context_hash, verification_time = fixture_parts()
    revoked_registry = copy.deepcopy(registry)
    revoked_registry["entries"][0]["status"] = "revoked"
    with pytest.raises(ValueError, match="revoked"):
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash=expected_context_hash,
            registry=revoked_registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )

    narrow_registry = copy.deepcopy(registry)
    narrow_registry["entries"][0]["not_before"] = "2026-06-21T00:01:00Z"
    narrow_registry["entries"][0]["not_after"] = "2026-06-21T00:03:00Z"
    with pytest.raises(ValueError, match="outside key validity"):
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash=expected_context_hash,
            registry=narrow_registry,
            verification_time=verification_time,
            verifier=verify_test_only_component_signature,
        )


def test_v48b_orchestrator_rejects_cross_receipt_signature_splice() -> None:
    receipt, registry, expected_context_hash, verification_time = fixture_parts()
    spliced = copy.deepcopy(receipt)
    spliced["request_id"] = "req-spliced-from-another-receipt"
    refresh_receipt_hashes_without_resigning(spliced)

    with pytest.raises(ValueError, match="signed_payload_hash mismatch"):
        validate_receipt_envelope(
            spliced,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_orchestrator_signature,
        )


def test_v48b_orchestrator_rejects_receipt_authority_and_semantic_bypass() -> None:
    receipt, registry, expected_context_hash, verification_time = fixture_parts()
    authority = copy.deepcopy(receipt)
    authority["adamantineos_handoff"]["final_approval"] = True
    refresh_receipt_hashes_without_resigning(authority)
    with pytest.raises(ValueError, match="forbidden authority"):
        validate_receipt_envelope(
            authority,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_orchestrator_signature,
        )

    mismatch = copy.deepcopy(receipt)
    mismatch["final_outcome"] = "DENY"
    mismatch["adamantineos_handoff"]["handoff_allowed"] = False
    refresh_receipt_hashes_without_resigning(mismatch)
    with pytest.raises(ValueError, match="final_outcome"):
        validate_receipt_envelope(
            mismatch,
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verify_test_only_orchestrator_signature,
        )


def test_v48b_orchestrator_receipt_semantic_guards_cover_component_edges() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    payload = unsigned_receipt_payload(receipt)

    component_mutations = [
        (lambda item: item.__setitem__("component_verdicts", ["bad", *item["component_verdicts"][1:]]), "component verdict must be dict"),
        (lambda item: item["component_verdicts"][0].__setitem__("component_id", "unknown"), "unsupported component verdict"),
        (lambda item: item["component_verdicts"][1].__setitem__("component_id", item["component_verdicts"][0]["component_id"]), "duplicate component verdict"),
        (lambda item: item["component_verdicts"][0].__setitem__("schema_version", "shield.verdict.v1"), "schema mismatch"),
        (lambda item: item["component_verdicts"][0].__setitem__("context_hash", "b" * 64), "context mismatch"),
        (lambda item: item["component_verdicts"][0].__setitem__("decision", "MAYBE"), "unsupported component verdict decision"),
    ]
    for mutate, match in component_mutations:
        candidate = copy.deepcopy(payload)
        mutate(candidate)
        with pytest.raises(ValueError, match=match):
            _validate_receipt_payload_semantics(candidate, expected_context_hash=expected_context_hash)


def test_v48b_orchestrator_receipt_semantic_guards_cover_signature_summary_edges() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    payload = unsigned_receipt_payload(receipt)

    result_mutations = [
        (lambda item: item.__setitem__("component_signature_results", ["bad", *item["component_signature_results"][1:]]), "component signature result must be dict"),
        (lambda item: item["component_signature_results"][0].__setitem__("component_id", "unknown"), "unsupported component signature result"),
        (lambda item: item["component_signature_results"][1].__setitem__("component_id", item["component_signature_results"][0]["component_id"]), "duplicate component signature result"),
        (lambda item: item["component_signature_results"][0].__setitem__("component_role", "wrong_role"), "role mismatch"),
        (lambda item: item["component_signature_results"][0].__setitem__("signature_policy", "policy.v0"), "policy mismatch"),
        (lambda item: item["component_signature_results"][0].__setitem__("verified_algorithms", ["classical-ed25519"]), "missing required algorithms"),
    ]
    for mutate, match in result_mutations:
        candidate = copy.deepcopy(payload)
        mutate(candidate)
        with pytest.raises(ValueError, match=match):
            _validate_receipt_payload_semantics(candidate, expected_context_hash=expected_context_hash)


def test_v48b_orchestrator_receipt_semantic_guards_cover_receipt_edges() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    payload = unsigned_receipt_payload(receipt)

    receipt_mutations = [
        (lambda item: item.pop("schema_version"), "fields"),
        (lambda item: item.__setitem__("schema_version", "shield.receipt.v1"), "schema mismatch"),
        (lambda item: item.__setitem__("contract_version", 3), "contract mismatch"),
        (lambda item: item.__setitem__("fail_closed", False), "fail_closed"),
        (lambda item: item.__setitem__("canonicalization_profile", "bad"), "canonicalization"),
        (lambda item: item.__setitem__("signature_policy", "policy.v0"), "signature policy"),
        (lambda item: item.__setitem__("final_outcome", "MAYBE"), "unsupported final outcome"),
        (lambda item: item.__setitem__("dominant_reason_ids", [""]), "dominant_reason_id"),
        (lambda item: item.__setitem__("key_registry_version", False), "key_registry_version"),
        (lambda item: item.__setitem__("adamantineos_handoff", []), "adamantineos_handoff must be dict"),
    ]
    for mutate, match in receipt_mutations:
        candidate = copy.deepcopy(payload)
        mutate(candidate)
        with pytest.raises(ValueError, match=match):
            _validate_receipt_payload_semantics(candidate, expected_context_hash=expected_context_hash)


def test_v48b_orchestrator_receipt_semantic_guards_cover_context_empty_reasons_and_nonallow_handoff() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    payload = unsigned_receipt_payload(receipt)

    context_mismatch = copy.deepcopy(payload)
    context_mismatch["context_hash"] = "b" * 64
    with pytest.raises(ValueError, match="receipt context mismatch"):
        _validate_receipt_payload_semantics(context_mismatch, expected_context_hash=expected_context_hash)

    empty_reasons = copy.deepcopy(payload)
    empty_reasons["dominant_reason_ids"] = []
    with pytest.raises(ValueError, match="dominant_reason_ids"):
        _validate_receipt_payload_semantics(empty_reasons, expected_context_hash=expected_context_hash)

    nonallow_handoff = copy.deepcopy(payload)
    nonallow_handoff["component_verdicts"][0]["decision"] = "DENY"
    nonallow_handoff["final_outcome"] = "DENY"
    nonallow_handoff["adamantineos_handoff"]["handoff_allowed"] = True
    with pytest.raises(ValueError, match="non-ALLOW"):
        _validate_receipt_payload_semantics(nonallow_handoff, expected_context_hash=expected_context_hash)


def test_v48b_orchestrator_builder_rejects_non_allow_handoff_true() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    component_verdicts = copy.deepcopy(receipt["component_verdicts"])
    component_verdicts[0]["decision"] = "DENY"

    with pytest.raises(ValueError, match="non-ALLOW"):
        build_unsigned_receipt_payload(
            request_id="req-v4-deny",
            context_hash=expected_context_hash,
            freshness_nonce="nonce-v4-deny",
            not_before="2026-06-21T00:00:00Z",
            not_after="2026-06-21T00:05:00Z",
            component_verdicts=component_verdicts,
            component_signature_results=receipt["component_signature_results"],
            final_outcome="DENY",
            dominant_reason_ids=["ORCH_DENY_DOMINATES"],
            key_registry_version=1,
            adamantineos_handoff={"handoff_allowed": True},
        )


def test_v48b_orchestrator_builder_rejects_final_outcome_component_mismatch() -> None:
    receipt, _, expected_context_hash, _ = fixture_parts()
    component_verdicts = copy.deepcopy(receipt["component_verdicts"])
    component_verdicts[0]["decision"] = "DENY"

    with pytest.raises(ValueError, match="final_outcome"):
        build_unsigned_receipt_payload(
            request_id="req-v4-mismatch",
            context_hash=expected_context_hash,
            freshness_nonce="nonce-v4-mismatch",
            not_before="2026-06-21T00:00:00Z",
            not_after="2026-06-21T00:05:00Z",
            component_verdicts=component_verdicts,
            component_signature_results=receipt["component_signature_results"],
            final_outcome="ALLOW",
            dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
            key_registry_version=1,
            adamantineos_handoff={"handoff_allowed": True},
        )
