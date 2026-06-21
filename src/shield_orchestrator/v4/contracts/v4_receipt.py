from __future__ import annotations

import hashlib
from typing import Any

from shield_orchestrator.v4 import CANONICALIZATION_PROFILE, POLICY_VERSION, RECEIPT_SCHEMA_VERSION
from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN, signed_payload_hash, to_canonical_json
from shield_orchestrator.v4.crypto_algorithms import SIGNATURE_POLICY_V1
from shield_orchestrator.v4.key_registry import KeyRegistry, load_key_registry
from shield_orchestrator.v4.signature_bundle import SignatureVerifier, verify_signature_bundle

CONTRACT_VERSION = 4
SUPPORTED_COMPONENTS = ("adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai")
FINAL_OUTCOMES = ("ALLOW", "DENY", "HUMAN_REVIEW_REQUIRED")
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
    if not isinstance(component_verdicts, list) or len(component_verdicts) != len(SUPPORTED_COMPONENTS):
        raise ValueError("component_verdicts must contain every required component")
    seen_components = [
        _require_non_empty_str(item.get("component_id"), field="component_id")
        for item in component_verdicts
        if isinstance(item, dict)
    ]
    if tuple(sorted(seen_components)) != SUPPORTED_COMPONENTS:
        raise ValueError("component_verdicts must match required component set")
    if not isinstance(component_signature_results, list) or len(component_signature_results) != len(SUPPORTED_COMPONENTS):
        raise ValueError("component_signature_results must contain every required component")
    if final_outcome not in FINAL_OUTCOMES:
        raise ValueError("unsupported final outcome")
    if not isinstance(dominant_reason_ids, list) or not dominant_reason_ids:
        raise ValueError("dominant_reason_ids must be non-empty list")
    if isinstance(key_registry_version, bool) or not isinstance(key_registry_version, int) or key_registry_version <= 0:
        raise ValueError("key_registry_version must be positive integer")
    if not isinstance(adamantineos_handoff, dict):
        raise ValueError("adamantineos_handoff must be dict")
    if _contains_forbidden_metadata_authority(adamantineos_handoff):
        raise ValueError("adamantineos_handoff contains forbidden authority field")
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
    if set(receipt.keys()) != REQUIRED_RECEIPT_FIELDS:
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
    unsigned_payload = {key: receipt[key] for key in UNSIGNED_RECEIPT_FIELDS}
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
