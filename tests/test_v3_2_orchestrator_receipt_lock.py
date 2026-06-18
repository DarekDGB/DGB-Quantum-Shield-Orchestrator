from __future__ import annotations

import json
from pathlib import Path

import pytest

from shield_orchestrator.v3.contracts.v3_2_receipt import (
    COMPONENT_EVIDENCE_FAMILIES,
    COMPONENT_REASON_IDS,
    SUPPORTED_COMPONENTS,
    build_manifest,
    build_receipt,
    canonical_sha256,
    validate_component_verdict,
    validate_receipt,
)

CTX = "a" * 64
EVID = "b" * 64


def verdict(component_id: str, decision: str = "ALLOW") -> dict[str, object]:
    return {
        "component_id": component_id,
        "contract_version": 3,
        "schema_version": "shield.verdict.v1",
        "request_id": "req-1",
        "context_hash": CTX,
        "decision": decision,
        "reason_ids": [COMPONENT_REASON_IDS[component_id][0]],
        "evidence_hash": EVID,
        "evidence_families": [COMPONENT_EVIDENCE_FAMILIES[component_id][0]],
        "metadata": {},
        "fail_closed": True,
    }


def all_verdicts(decision: str = "ALLOW") -> list[dict[str, object]]:
    return [verdict(component, decision) for component in SUPPORTED_COMPONENTS]


def test_v3_2_shared_adamantine_fixture_matches_orchestrator_receipt_contract():
    fixture_path = Path(__file__).parent / "fixtures" / "adamantine" / "shield_orchestrator_receipt_v3_2_component_baseline.json"
    fixture = json.loads(fixture_path.read_text())
    expected = build_receipt(
        request_id="req-milestone-16c-shared-vector",
        context_hash=CTX,
        component_verdicts=[
            {**verdict(component), "request_id": "req-milestone-16c-shared-vector"}
            for component in SUPPORTED_COMPONENTS
        ],
    )

    assert fixture == expected
    assert validate_receipt(fixture, expected_context_hash=CTX) == expected


def test_v3_2_orchestrator_manifest_declares_single_boundary():
    manifest = build_manifest()
    assert manifest["component_id"] == "shield_orchestrator"
    assert manifest["package_version"] == "3.2.0"
    assert manifest["supported_components"] == list(SUPPORTED_COMPONENTS)
    assert "AdamantineOS consumes Shield only through" in manifest["adamantineos_visibility"]
    assert "does not sign" in manifest["authority_boundary"]


def test_v3_2_receipt_is_deterministic_and_orders_components():
    receipt_a = build_receipt(request_id="req-1", context_hash=CTX, component_verdicts=list(reversed(all_verdicts())))
    receipt_b = build_receipt(request_id="req-1", context_hash=CTX, component_verdicts=all_verdicts())
    assert receipt_a == receipt_b
    assert [item["component_id"] for item in receipt_a["component_verdicts"]] == sorted(SUPPORTED_COMPONENTS)
    assert receipt_a["final_outcome"] == "ALLOW"
    assert receipt_a["adamantineos_handoff"]["handoff_allowed"] is True
    assert validate_receipt(receipt_a, expected_context_hash=CTX) == receipt_a


def test_v3_2_receipt_hash_vector_stays_stable_with_strict_json_nan_lock():
    receipt = build_receipt(request_id="req-1", context_hash=CTX, component_verdicts=all_verdicts())

    assert receipt["receipt_hash"] == "c282da0d9aa6587116271012f82b2399974c0cbfd82dcb7a9545bcb957b4bdfc"
    assert canonical_sha256({"ok": True, "n": 1, "s": "DigiByte"}) == "57191193452bcc05c491b175f9778d9aab8d1d6829fcf55756f1e0ea77967c14"


def test_v3_2_receipt_hash_rejects_non_finite_json_numbers():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="Out of range float values"):
            canonical_sha256({"non_finite": value})


@pytest.mark.parametrize(
    ("decision", "outcome", "handoff"),
    [
        ("DENY", "DENY", False),
        ("ERROR", "DENY", False),
        ("ESCALATE", "HUMAN_REVIEW_REQUIRED", False),
    ],
)



def test_v3_2_receipt_policy_deny_and_escalate(decision, outcome, handoff):
    verdicts = all_verdicts()
    verdicts[0] = verdict(SUPPORTED_COMPONENTS[0], decision)
    receipt = build_receipt(request_id="req-2", context_hash=CTX, component_verdicts=verdicts)
    assert receipt["final_outcome"] == outcome
    assert receipt["adamantineos_handoff"]["handoff_allowed"] is handoff


@pytest.mark.parametrize(
    "mutator",
    [
        lambda items: items.pop(),
        lambda items: items.append(dict(items[0])),
        lambda items: items[0].__setitem__("component_id", "unknown"),
        lambda items: items[0].__setitem__("contract_version", 4),
        lambda items: items[0].__setitem__("schema_version", "bad"),
        lambda items: items[0].__setitem__("context_hash", "c" * 64),
        lambda items: items[0].__setitem__("decision", "MAYBE"),
        lambda items: items[0].__setitem__("reason_ids", []),
        lambda items: items[0].__setitem__("reason_ids", [""]),
        lambda items: items[0].__setitem__("reason_ids", ["UNKNOWN_REASON"]),
        lambda items: items[0].__setitem__("evidence_hash", "bad"),
        lambda items: items[0].__setitem__("evidence_families", []),
        lambda items: items[0].__setitem__("evidence_families", ["unknown_family"]),
        lambda items: items[0].__setitem__("evidence_families", [COMPONENT_EVIDENCE_FAMILIES[items[0]["component_id"]][0], COMPONENT_EVIDENCE_FAMILIES[items[0]["component_id"]][0]]),
        lambda items: items[0].__setitem__("metadata", []),
        lambda items: items[0].__setitem__("fail_closed", False),
        lambda items: items[0].pop("request_id"),
    ],
)
def test_v3_2_malformed_component_verdicts_fail_closed(mutator):
    items = all_verdicts()
    mutator(items)
    with pytest.raises(ValueError):
        build_receipt(request_id="req-3", context_hash=CTX, component_verdicts=items)


def test_v3_2_receipt_skipped_component_fails_closed_not_allow():
    verdicts = all_verdicts()
    verdicts[0] = verdict(SUPPORTED_COMPONENTS[0], "SKIPPED")

    receipt = build_receipt(request_id="req-skipped", context_hash=CTX, component_verdicts=verdicts)

    assert receipt["final_outcome"] == "DENY"
    assert receipt["dominant_reason_ids"] == ["ORCH_ERROR_MISSING_REQUIRED_VERDICT"]
    assert receipt["adamantineos_handoff"] == {
        "handoff_allowed": False,
        "handoff_reason": "ORCH_ERROR_MISSING_REQUIRED_VERDICT",
    }


def test_v3_2_component_metadata_authority_fields_fail_closed():
    verdicts = all_verdicts()
    verdicts[0]["metadata"] = {"nested": {"final_approval": True}}

    with pytest.raises(ValueError, match="forbidden authority"):
        build_receipt(request_id="req-authority", context_hash=CTX, component_verdicts=verdicts)

    list_nested = all_verdicts()
    list_nested[0]["metadata"] = {"events": [{"override": True}]}
    with pytest.raises(ValueError, match="forbidden authority"):
        build_receipt(request_id="req-authority-list", context_hash=CTX, component_verdicts=list_nested)

    safe_scalar = all_verdicts()
    safe_scalar[0]["metadata"] = {"note": "observed"}
    receipt = build_receipt(request_id="req-safe-metadata", context_hash=CTX, component_verdicts=safe_scalar)
    assert receipt["final_outcome"] == "ALLOW"


def test_v3_2_hashes_must_be_lowercase_sha256_hex():
    verdicts = all_verdicts()
    verdicts[0]["evidence_hash"] = "B" * 64
    with pytest.raises(ValueError, match="lowercase"):
        build_receipt(request_id="req-uppercase-evidence", context_hash=CTX, component_verdicts=verdicts)

    with pytest.raises(ValueError, match="lowercase"):
        build_receipt(request_id="req-uppercase-context", context_hash="A" * 64, component_verdicts=all_verdicts())


def test_v3_2_receipt_tampering_and_bad_inputs_fail_closed():
    receipt = build_receipt(request_id="req-4", context_hash=CTX, component_verdicts=all_verdicts())
    tampered = dict(receipt)
    tampered["final_outcome"] = "DENY"
    with pytest.raises(ValueError):
        validate_receipt(tampered, expected_context_hash=CTX)
    with pytest.raises(ValueError):
        validate_receipt("bad", expected_context_hash=CTX)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        validate_receipt({**receipt, "extra": True}, expected_context_hash=CTX)
    with pytest.raises(ValueError):
        validate_receipt({**receipt, "schema_version": "bad"}, expected_context_hash=CTX)
    with pytest.raises(ValueError):
        validate_receipt({**receipt, "contract_version": 4}, expected_context_hash=CTX)
    with pytest.raises(ValueError):
        validate_receipt({**receipt, "fail_closed": False}, expected_context_hash=CTX)
    with pytest.raises(ValueError):
        validate_receipt(receipt, expected_context_hash="c" * 64)
    with pytest.raises(ValueError):
        build_receipt(request_id="", context_hash=CTX, component_verdicts=all_verdicts())
    with pytest.raises(ValueError):
        build_receipt(request_id="req", context_hash="bad", component_verdicts=all_verdicts())
    with pytest.raises(ValueError):
        build_receipt(request_id="req", context_hash=CTX, component_verdicts="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        validate_component_verdict("bad", expected_context_hash=CTX)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        canonical_sha256("bad")  # type: ignore[arg-type]
    bad_hash_verdicts = all_verdicts()
    bad_hash_verdicts[0]["context_hash"] = "g" * 64
    with pytest.raises(ValueError):
        build_receipt(request_id="req", context_hash=CTX, component_verdicts=bad_hash_verdicts)
    empty_component = all_verdicts()
    empty_component[0]["component_id"] = ""
    with pytest.raises(ValueError):
        build_receipt(request_id="req", context_hash=CTX, component_verdicts=empty_component)
    no_hash_match = dict(receipt)
    no_hash_match["receipt_hash"] = "c" * 64
    with pytest.raises(ValueError):
        validate_receipt(no_hash_match, expected_context_hash=CTX)
