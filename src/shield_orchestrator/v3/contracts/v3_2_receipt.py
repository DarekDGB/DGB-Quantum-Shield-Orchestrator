from __future__ import annotations

import hashlib
import json
from typing import Any

CONTRACT_VERSION = 3
PACKAGE_VERSION = "3.2.0"
VERDICT_SCHEMA_VERSION = "shield.verdict.v1"
RECEIPT_SCHEMA_VERSION = "shield.receipt.v1"
COMPONENT_ID = "shield_orchestrator"
COMPONENT_NAME = "DGB Quantum Shield Orchestrator"
SUPPORTED_COMPONENTS = ("adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai")
SUPPORTED_DECISIONS = ("ALLOW", "ESCALATE", "DENY", "ERROR", "SKIPPED")
FINAL_OUTCOMES = ("ALLOW", "DENY", "HUMAN_REVIEW_REQUIRED")
SUPPORTED_REASON_IDS = (
    "ORCH_OK_ALL_COMPONENTS_ALLOW",
    "ORCH_HUMAN_REVIEW_ESCALATE_PRESENT",
    "ORCH_DENY_DOMINATES",
    "ORCH_ERROR_MISSING_REQUIRED_VERDICT",
    "ORCH_ERROR_DUPLICATED_COMPONENT_VERDICT",
    "ORCH_ERROR_CONTEXT_HASH_MISMATCH",
    "ORCH_ERROR_INVALID_COMPONENT_VERDICT",
    "ORCH_ERROR_RECEIPT_TAMPERED",
    "ORCH_ERROR_REPLAY_DETECTED",
    "SHIELD_ERROR_AI_AUTHORITY_BYPASS_ATTEMPT",
    "SHIELD_ERROR_HUMAN_APPROVAL_CONTEXT_MISMATCH",
)
SUPPORTED_EVIDENCE_FAMILIES = (
    "component_verdict",
    "component_manifest",
    "receipt_context",
    "final_policy",
)

COMPONENT_REASON_IDS = {
    "guardian_wallet": (
        "GW_OK_HEALTHY_ALLOW",
        "GW_ESCALATE_QID_REQUIRED",
        "GW_DENY_POLICY_BLOCKED",
        "GW_ERROR_INVALID_VERDICT",
        "GW_ERROR_CONTEXT_HASH_MISMATCH",
    ),
    "adn": (
        "ADN_OK_COORDINATION_ALLOW",
        "ADN_ESCALATE_POLICY_REVIEW",
        "ADN_DENY_DEFENSE_TRIGGERED",
        "ADN_ERROR_INVALID_VERDICT",
        "ADN_ERROR_CONTEXT_HASH_MISMATCH",
    ),
    "sentinel_ai": (
        "SNTL_OK_TELEMETRY_ALLOW",
        "SNTL_ESCALATE_THREAT_REVIEW",
        "SNTL_DENY_THREAT_DETECTED",
        "SNTL_ERROR_AI_OUTPUT_UNTRUSTED",
        "SNTL_ERROR_CONTEXT_HASH_MISMATCH",
    ),
    "dqsn": (
        "DQSN_OK_NETWORK_ALLOW",
        "DQSN_ESCALATE_QUANTUM_SIGNAL",
        "DQSN_DENY_NETWORK_RISK",
        "DQSN_ERROR_INVALID_VERDICT",
        "DQSN_ERROR_CONTEXT_HASH_MISMATCH",
    ),
    "qwg": (
        "QWG_OK_POSTURE_ALLOW",
        "QWG_ESCALATE_QUANTUM_POSTURE",
        "QWG_DENY_KEY_RISK",
        "QWG_ERROR_INVALID_VERDICT",
        "QWG_ERROR_CONTEXT_HASH_MISMATCH",
    ),
}

COMPONENT_EVIDENCE_FAMILIES = {
    "guardian_wallet": (
        "wallet_context",
        "transaction_context",
        "qid_auth_context",
        "sentinel_signal",
        "device_signal",
    ),
    "adn": (
        "defense_signal",
        "policy_context",
        "coordination_state",
    ),
    "sentinel_ai": (
        "telemetry",
        "monitor_signal",
        "threat_observation",
        "adaptive_core_bridge_event",
    ),
    "dqsn": (
        "network_observation",
        "quantum_signal",
        "node_state",
        "aggregate_signal",
    ),
    "qwg": (
        "wallet_posture",
        "quantum_risk_context",
        "key_age_context",
        "dormancy_context",
    ),
}
REQUIRED_VERDICT_FIELDS = frozenset({
    "component_id",
    "contract_version",
    "schema_version",
    "request_id",
    "context_hash",
    "decision",
    "reason_ids",
    "evidence_hash",
    "evidence_families",
    "metadata",
    "fail_closed",
})
REQUIRED_RECEIPT_FIELDS = frozenset({
    "schema_version",
    "contract_version",
    "request_id",
    "context_hash",
    "component_verdicts",
    "final_outcome",
    "dominant_reason_ids",
    "receipt_hash",
    "adamantineos_handoff",
    "fail_closed",
})


def canonical_json(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _require_hash(value: str, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be 64-character sha256 hex")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be sha256 hex") from exc
    return value.lower()


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty str")
    return value.strip()


def build_manifest() -> dict[str, Any]:
    return {
        "component_id": COMPONENT_ID,
        "component_name": COMPONENT_NAME,
        "contract_version": CONTRACT_VERSION,
        "package_version": PACKAGE_VERSION,
        "supported_components": list(SUPPORTED_COMPONENTS),
        "supported_final_outcomes": list(FINAL_OUTCOMES),
        "supported_component_decisions": list(SUPPORTED_DECISIONS),
        "supported_reason_ids": list(SUPPORTED_REASON_IDS),
        "supported_evidence_families": list(SUPPORTED_EVIDENCE_FAMILIES),
        "output_schema_version": RECEIPT_SCHEMA_VERSION,
        "authority_boundary": "single Shield boundary; does not sign, broadcast, hold keys, or grant final AdamantineOS execution authority",
        "adamantineos_visibility": "AdamantineOS consumes Shield only through this deterministic Orchestrator receipt",
        "fail_closed_guarantees": "missing, malformed, duplicated, stale, replayed, context-mismatched, or unknown component verdicts produce deterministic DENY",
    }


def validate_component_verdict(verdict: dict[str, Any], *, expected_context_hash: str) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        raise ValueError("component verdict must be dict")
    if set(verdict.keys()) != REQUIRED_VERDICT_FIELDS:
        raise ValueError("component verdict fields must match required schema")
    component_id = _require_non_empty_str(verdict["component_id"], field="component_id")
    if component_id not in SUPPORTED_COMPONENTS:
        raise ValueError("unknown component_id")
    if verdict["contract_version"] != CONTRACT_VERSION:
        raise ValueError("contract_version mismatch")
    if verdict["schema_version"] != VERDICT_SCHEMA_VERSION:
        raise ValueError("schema_version mismatch")
    if verdict["fail_closed"] is not True:
        raise ValueError("component verdict fail_closed must be true")
    if _require_hash(verdict["context_hash"], field="context_hash") != _require_hash(expected_context_hash, field="expected_context_hash"):
        raise ValueError("context_hash mismatch")
    decision = _require_non_empty_str(verdict["decision"], field="decision")
    if decision not in SUPPORTED_DECISIONS:
        raise ValueError("unsupported decision")
    if not isinstance(verdict["reason_ids"], list) or not verdict["reason_ids"]:
        raise ValueError("reason_ids must be non-empty list")
    allowed_reason_ids = set(COMPONENT_REASON_IDS[component_id])
    for reason_id in verdict["reason_ids"]:
        clean_reason_id = _require_non_empty_str(reason_id, field="reason_id")
        if clean_reason_id not in allowed_reason_ids:
            raise ValueError("unknown component reason_id")
    _require_hash(verdict["evidence_hash"], field="evidence_hash")
    if not isinstance(verdict["evidence_families"], list) or not verdict["evidence_families"]:
        raise ValueError("evidence_families must be non-empty list")
    if len(set(verdict["evidence_families"])) != len(verdict["evidence_families"]):
        raise ValueError("duplicated evidence family")
    allowed_evidence_families = set(COMPONENT_EVIDENCE_FAMILIES[component_id])
    for evidence_family in verdict["evidence_families"]:
        clean_evidence_family = _require_non_empty_str(evidence_family, field="evidence_family")
        if clean_evidence_family not in allowed_evidence_families:
            raise ValueError("unknown component evidence family")
    if not isinstance(verdict["metadata"], dict):
        raise ValueError("metadata must be dict")
    return dict(verdict)


def _classify(verdicts: list[dict[str, Any]]) -> tuple[str, list[str], dict[str, Any]]:
    decisions = [v["decision"] for v in verdicts]
    if "DENY" in decisions:
        return "DENY", ["ORCH_DENY_DOMINATES"], {"handoff_allowed": False, "handoff_reason": "ORCH_DENY_DOMINATES"}
    if "ERROR" in decisions:
        return "DENY", ["ORCH_ERROR_INVALID_COMPONENT_VERDICT"], {"handoff_allowed": False, "handoff_reason": "ORCH_ERROR_INVALID_COMPONENT_VERDICT"}
    if "ESCALATE" in decisions:
        return "HUMAN_REVIEW_REQUIRED", ["ORCH_HUMAN_REVIEW_ESCALATE_PRESENT"], {"handoff_allowed": False, "handoff_reason": "ORCH_HUMAN_REVIEW_ESCALATE_PRESENT"}
    return "ALLOW", ["ORCH_OK_ALL_COMPONENTS_ALLOW"], {"handoff_allowed": True, "handoff_reason": "ORCH_OK_ALL_COMPONENTS_ALLOW"}


def build_receipt(*, request_id: str, context_hash: str, component_verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    request_id = _require_non_empty_str(request_id, field="request_id")
    context_hash = _require_hash(context_hash, field="context_hash")
    if not isinstance(component_verdicts, list):
        raise ValueError("component_verdicts must be list")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for verdict in component_verdicts:
        valid = validate_component_verdict(verdict, expected_context_hash=context_hash)
        component_id = valid["component_id"]
        if component_id in seen:
            raise ValueError("duplicated component verdict")
        seen.add(component_id)
        checked.append(valid)
    missing = set(SUPPORTED_COMPONENTS) - seen
    if missing:
        raise ValueError("missing required component verdict")
    checked.sort(key=lambda item: item["component_id"])
    final_outcome, dominant_reason_ids, handoff = _classify(checked)
    receipt_without_hash = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "request_id": request_id,
        "context_hash": context_hash,
        "component_verdicts": checked,
        "final_outcome": final_outcome,
        "dominant_reason_ids": dominant_reason_ids,
        "receipt_hash": "",
        "adamantineos_handoff": handoff,
        "fail_closed": True,
    }
    receipt = dict(receipt_without_hash)
    receipt["receipt_hash"] = canonical_sha256(receipt_without_hash)
    return receipt


def validate_receipt(receipt: dict[str, Any], *, expected_context_hash: str) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be dict")
    if set(receipt.keys()) != REQUIRED_RECEIPT_FIELDS:
        raise ValueError("receipt fields must match required schema")
    if receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ValueError("receipt schema mismatch")
    if receipt["contract_version"] != CONTRACT_VERSION:
        raise ValueError("receipt contract mismatch")
    if receipt["fail_closed"] is not True:
        raise ValueError("receipt fail_closed must be true")
    rebuilt = build_receipt(
        request_id=receipt["request_id"],
        context_hash=receipt["context_hash"],
        component_verdicts=receipt["component_verdicts"],
    )
    if rebuilt["receipt_hash"] != receipt["receipt_hash"]:
        raise ValueError("receipt hash mismatch")
    if rebuilt["context_hash"] != _require_hash(expected_context_hash, field="expected_context_hash"):
        raise ValueError("receipt context mismatch")
    if rebuilt != receipt:
        raise ValueError("receipt content mismatch")
    return rebuilt
