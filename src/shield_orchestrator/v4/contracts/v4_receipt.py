from __future__ import annotations

import hashlib
from typing import Any

from shield_orchestrator.v4 import CANONICALIZATION_PROFILE, POLICY_VERSION, RECEIPT_SCHEMA_VERSION
from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN, signed_payload_hash, to_canonical_json
from shield_orchestrator.v4.crypto_algorithms import ALGORITHM_STANDARD_PROFILES, SIGNATURE_POLICY_V1
from shield_orchestrator.v4.key_registry import KeyRegistry, load_key_registry
from shield_orchestrator.v4.signature_bundle import SignatureVerifier, verify_signature_bundle

CONTRACT_VERSION = 4
SUPPORTED_COMPONENTS = ("adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai")
COMPONENT_ROLES = {
    "adn": "shield_component_adn",
    "dqsn": "shield_component_dqsn",
    "guardian_wallet": "shield_component_guardian_wallet",
    "qwg": "shield_component_qwg",
    "sentinel_ai": "shield_component_sentinel_ai",
}
FINAL_OUTCOMES = ("ALLOW", "DENY", "HUMAN_REVIEW_REQUIRED")
DENYING_COMPONENT_DECISIONS = frozenset({"DENY", "ERROR"})
ESCALATING_COMPONENT_DECISIONS = frozenset({"ESCALATE", "SKIPPED"})
REQUIRED_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "contract_version",
        "request_id",
        "context_hash",
        "freshness_nonce",
        "not_before",
        "not_after",
        "component_verdicts",
        "component_signature_results",
        "final_outcome",
        "dominant_reason_ids",
        "receipt_hash",
        "canonicalization_profile",
        "signed_payload_hash",
        "signature_policy",
        "signature_bundle",
        "key_registry_version",
        "adamantineos_handoff",
        "fail_closed",
    }
)
OPTIONAL_RECEIPT_FIELDS = frozenset({"verification_summary"})
UNSIGNED_RECEIPT_EXCLUDED_FIELDS = frozenset({"receipt_hash", "signed_payload_hash", "signature_bundle", "verification_summary"})
UNSIGNED_RECEIPT_FIELDS = REQUIRED_RECEIPT_FIELDS - {"receipt_hash", "signed_payload_hash", "signature_bundle"}
FORBIDDEN_METADATA_AUTHORITY_KEYS = frozenset(
    {
        "allow",
        "approved",
        "authority",
        "auto_approve",
        "broadcast",
        "bypass",
        "can_sign",
        "decision",
        "execute",
        "final_approval",
        "force_allow",
        "human_approved",
        "override",
        "sign",
        "trusted",
    }
)

COMPONENT_SIGNATURE_RESULT_FIELDS = frozenset(
    {
        "component_id",
        "component_role",
        "verified",
        "verified_algorithms",
        "verified_standard_profiles",
        "signature_policy",
    }
)


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty string")
    return value.strip()


def _require_hash(value: Any, *, field: str) -> str:
    clean = _require_non_empty_str(value, field=field)
    if len(clean) != 64:
        raise ValueError(f"{field} must be 64-character sha256 hex")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be sha256 hex") from exc
    if clean != clean.lower():
        raise ValueError(f"{field} must be lowercase sha256 hex")
    return clean


def _contains_forbidden_metadata_authority(value: Any) -> bool:
    if isinstance(value, dict):
        if set(value) & FORBIDDEN_METADATA_AUTHORITY_KEYS:
            return True
        return any(_contains_forbidden_metadata_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_metadata_authority(item) for item in value)
    return False


def _expected_final_outcome(component_verdicts: list[dict[str, Any]]) -> str:
    decisions = {verdict["decision"] for verdict in component_verdicts}
    if decisions & DENYING_COMPONENT_DECISIONS:
        return "DENY"
    if decisions & ESCALATING_COMPONENT_DECISIONS:
        return "HUMAN_REVIEW_REQUIRED"
    return "ALLOW"


def _validate_component_verdicts_for_receipt(
    component_verdicts: Any,
    *,
    expected_context_hash: str,
) -> list[dict[str, Any]]:
    if not isinstance(component_verdicts, list) or len(component_verdicts) != len(SUPPORTED_COMPONENTS):
        raise ValueError("component_verdicts must contain every required component")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for verdict in component_verdicts:
        if not isinstance(verdict, dict):
            raise ValueError("component verdict must be dict")
        component_id = _require_non_empty_str(verdict.get("component_id"), field="component_id")
        if component_id not in COMPONENT_ROLES:
            raise ValueError("unsupported component verdict")
        if component_id in seen:
            raise ValueError("duplicate component verdict")
        seen.add(component_id)
        if verdict.get("contract_version") != CONTRACT_VERSION:
            raise ValueError("component verdict contract mismatch")
        if verdict.get("schema_version") != "shield.verdict.v2":
            raise ValueError("component verdict schema mismatch")
        if _require_hash(verdict.get("context_hash"), field="component context_hash") != expected_context_hash:
            raise ValueError("component verdict context mismatch")
        decision = _require_non_empty_str(verdict.get("decision"), field="component decision")
        if decision not in {"ALLOW", "ESCALATE", "DENY", "ERROR", "SKIPPED"}:
            raise ValueError("unsupported component verdict decision")
        checked.append({**verdict, "component_id": component_id, "decision": decision})
    return checked


def _validate_component_signature_results_for_receipt(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list) or len(results) != len(SUPPORTED_COMPONENTS):
        raise ValueError("component_signature_results must contain every required component")
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("component signature result must be dict")
        if set(result.keys()) != COMPONENT_SIGNATURE_RESULT_FIELDS:
            raise ValueError("component signature result fields must match required schema")
        component_id = _require_non_empty_str(result.get("component_id"), field="component_id")
        if component_id not in COMPONENT_ROLES:
            raise ValueError("unsupported component signature result")
        if component_id in seen:
            raise ValueError("duplicate component signature result")
        seen.add(component_id)
        if result.get("component_role") != COMPONENT_ROLES[component_id]:
            raise ValueError("component signature result role mismatch")
        if result.get("verified") is not True:
            raise ValueError("component signature result must be verified")
        if result.get("signature_policy") != POLICY_VERSION:
            raise ValueError("component signature result policy mismatch")
        algorithms = result["verified_algorithms"]
        profiles = result["verified_standard_profiles"]
        if not isinstance(algorithms, list) or not algorithms or any(not isinstance(item, str) or not item for item in algorithms):
            raise ValueError("component signature result algorithms must be non-empty strings")
        if len(set(algorithms)) != len(algorithms):
            raise ValueError("component signature result duplicate algorithm")
        if not set(SIGNATURE_POLICY_V1.required_algorithms).issubset(algorithms):
            raise ValueError("component signature result missing required algorithms")
        if any(algorithm not in ALGORITHM_STANDARD_PROFILES for algorithm in algorithms):
            raise ValueError("component signature result contains unsupported algorithm")
        if not isinstance(profiles, list) or len(profiles) != len(algorithms) or any(not isinstance(item, str) or not item for item in profiles):
            raise ValueError("component signature result profiles must match algorithms")
        for algorithm, profile in zip(algorithms, profiles, strict=True):
            if profile not in ALGORITHM_STANDARD_PROFILES[algorithm]:
                raise ValueError("component signature result contains unsupported standard_profile")
        checked.append(dict(result))
    return checked


def _validate_receipt_payload_semantics(payload: dict[str, Any], *, expected_context_hash: str) -> None:
    if set(payload.keys()) != UNSIGNED_RECEIPT_FIELDS:
        raise ValueError("unsigned receipt payload fields must match required schema")
    if payload["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ValueError("receipt schema mismatch")
    if payload["contract_version"] != CONTRACT_VERSION:
        raise ValueError("receipt contract mismatch")
    if payload["fail_closed"] is not True:
        raise ValueError("receipt fail_closed must be true")
    if payload["canonicalization_profile"] != CANONICALIZATION_PROFILE:
        raise ValueError("canonicalization profile mismatch")
    if payload["signature_policy"] != SIGNATURE_POLICY_V1.policy_version:
        raise ValueError("signature policy mismatch")
    if _require_hash(payload["context_hash"], field="context_hash") != expected_context_hash:
        raise ValueError("receipt context mismatch")
    _require_non_empty_str(payload["request_id"], field="request_id")
    _require_non_empty_str(payload["freshness_nonce"], field="freshness_nonce")
    _require_non_empty_str(payload["not_before"], field="not_before")
    _require_non_empty_str(payload["not_after"], field="not_after")
    component_verdicts = _validate_component_verdicts_for_receipt(
        payload["component_verdicts"],
        expected_context_hash=expected_context_hash,
    )
    _validate_component_signature_results_for_receipt(payload["component_signature_results"])
    if payload["final_outcome"] not in FINAL_OUTCOMES:
        raise ValueError("unsupported final outcome")
    expected_outcome = _expected_final_outcome(component_verdicts)
    if payload["final_outcome"] != expected_outcome:
        raise ValueError("receipt final_outcome does not match component decisions")
    if not isinstance(payload["dominant_reason_ids"], list) or not payload["dominant_reason_ids"]:
        raise ValueError("dominant_reason_ids must be non-empty list")
    for reason_id in payload["dominant_reason_ids"]:
        _require_non_empty_str(reason_id, field="dominant_reason_id")
    if isinstance(payload["key_registry_version"], bool) or not isinstance(payload["key_registry_version"], int) or payload["key_registry_version"] <= 0:
        raise ValueError("key_registry_version must be positive integer")
    if not isinstance(payload["adamantineos_handoff"], dict):
        raise ValueError("adamantineos_handoff must be dict")
    if _contains_forbidden_metadata_authority(payload["adamantineos_handoff"]):
        raise ValueError("adamantineos_handoff contains forbidden authority field")
    if payload["final_outcome"] != "ALLOW" and payload["adamantineos_handoff"].get("handoff_allowed") is True:
        raise ValueError("non-ALLOW receipt cannot carry handoff_allowed true")


def build_receipt_hash(unsigned_payload: dict[str, Any]) -> str:
    return hashlib.sha256(to_canonical_json(unsigned_payload).encode("utf-8")).hexdigest()


def build_unsigned_receipt_payload(
    *,
    request_id: str,
    context_hash: str,
    freshness_nonce: str,
    not_before: str,
    not_after: str,
    component_verdicts: list[dict[str, Any]],
    component_signature_results: list[dict[str, Any]],
    final_outcome: str,
    dominant_reason_ids: list[str],
    key_registry_version: int,
    adamantineos_handoff: dict[str, Any],
) -> dict[str, Any]:
    request_id = _require_non_empty_str(request_id, field="request_id")
    context_hash = _require_hash(context_hash, field="context_hash")
    freshness_nonce = _require_non_empty_str(freshness_nonce, field="freshness_nonce")
    _validate_component_verdicts_for_receipt(component_verdicts, expected_context_hash=context_hash)
    _validate_component_signature_results_for_receipt(component_signature_results)
    if final_outcome not in FINAL_OUTCOMES:
        raise ValueError("unsupported final outcome")
    if final_outcome != _expected_final_outcome(component_verdicts):
        raise ValueError("receipt final_outcome does not match component decisions")
    if not isinstance(dominant_reason_ids, list) or not dominant_reason_ids:
        raise ValueError("dominant_reason_ids must be non-empty list")
    for reason_id in dominant_reason_ids:
        _require_non_empty_str(reason_id, field="dominant_reason_id")
    if isinstance(key_registry_version, bool) or not isinstance(key_registry_version, int) or key_registry_version <= 0:
        raise ValueError("key_registry_version must be positive integer")
    if not isinstance(adamantineos_handoff, dict):
        raise ValueError("adamantineos_handoff must be dict")
    if _contains_forbidden_metadata_authority(adamantineos_handoff):
        raise ValueError("adamantineos_handoff contains forbidden authority field")
    if final_outcome != "ALLOW" and adamantineos_handoff.get("handoff_allowed") is True:
        raise ValueError("non-ALLOW receipt cannot carry handoff_allowed true")
    payload = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "request_id": request_id,
        "context_hash": context_hash,
        "freshness_nonce": freshness_nonce,
        "not_before": _require_non_empty_str(not_before, field="not_before"),
        "not_after": _require_non_empty_str(not_after, field="not_after"),
        "component_verdicts": sorted(component_verdicts, key=lambda item: item["component_id"]),
        "component_signature_results": sorted(
            component_signature_results,
            key=lambda item: _require_non_empty_str(item.get("component_id"), field="component_id"),
        ),
        "final_outcome": final_outcome,
        "dominant_reason_ids": dominant_reason_ids,
        "canonicalization_profile": CANONICALIZATION_PROFILE,
        "signature_policy": POLICY_VERSION,
        "key_registry_version": key_registry_version,
        "adamantineos_handoff": dict(adamantineos_handoff),
        "fail_closed": True,
    }
    return payload


def build_signed_receipt_envelope(*, unsigned_payload: dict[str, Any], signature_bundle: dict[str, Any]) -> dict[str, Any]:
    if set(unsigned_payload.keys()) != UNSIGNED_RECEIPT_FIELDS:
        raise ValueError("unsigned receipt payload fields must match required schema")
    receipt_hash = build_receipt_hash(unsigned_payload)
    payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned_payload)
    return {
        **unsigned_payload,
        "receipt_hash": receipt_hash,
        "signed_payload_hash": payload_hash,
        "signature_bundle": signature_bundle,
    }


def validate_receipt_envelope(
    receipt: dict[str, Any],
    *,
    expected_context_hash: str,
    registry: KeyRegistry | dict[str, Any],
    verification_time: str,
    verifier: SignatureVerifier,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be dict")
    if set(receipt.keys()) - OPTIONAL_RECEIPT_FIELDS != REQUIRED_RECEIPT_FIELDS:
        raise ValueError("receipt fields must match required schema")
    if receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ValueError("receipt schema mismatch")
    if receipt["contract_version"] != CONTRACT_VERSION:
        raise ValueError("receipt contract mismatch")
    if receipt["fail_closed"] is not True:
        raise ValueError("receipt fail_closed must be true")
    if receipt["canonicalization_profile"] != CANONICALIZATION_PROFILE:
        raise ValueError("canonicalization profile mismatch")
    if receipt["signature_policy"] != SIGNATURE_POLICY_V1.policy_version:
        raise ValueError("signature policy mismatch")
    if _require_hash(receipt["context_hash"], field="context_hash") != _require_hash(expected_context_hash, field="expected_context_hash"):
        raise ValueError("receipt context mismatch")
    unsigned_payload = {key: receipt[key] for key in receipt if key not in UNSIGNED_RECEIPT_EXCLUDED_FIELDS}
    _validate_receipt_payload_semantics(unsigned_payload, expected_context_hash=_require_hash(expected_context_hash, field="expected_context_hash"))
    if build_receipt_hash(unsigned_payload) != receipt["receipt_hash"]:
        raise ValueError("receipt hash mismatch")
    expected_payload_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned_payload)
    if expected_payload_hash != _require_hash(receipt["signed_payload_hash"], field="signed_payload_hash"):
        raise ValueError("signed payload hash mismatch")
    loaded_registry = load_key_registry(registry) if isinstance(registry, dict) else registry
    if receipt["key_registry_version"] != loaded_registry.registry_version:
        raise ValueError("key registry version mismatch")
    verification = verify_signature_bundle(
        receipt["signature_bundle"],
        expected_signed_payload_hash=expected_payload_hash,
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        required_role="shield_orchestrator",
        registry=loaded_registry,
        verification_time=verification_time,
        artifact_not_before=receipt["not_before"],
        artifact_not_after=receipt["not_after"],
        verifier=verifier,
    )
    return {**receipt, "verification_summary": verification}
