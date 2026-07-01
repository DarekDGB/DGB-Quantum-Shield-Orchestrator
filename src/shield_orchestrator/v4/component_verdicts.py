from __future__ import annotations

import hashlib
from typing import Any

from shield_orchestrator.v4 import CANONICALIZATION_PROFILE, POLICY_VERSION, VERDICT_SCHEMA_VERSION
from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.crypto_algorithms import SIGNATURE_POLICY_V1, default_standard_profile_for_algorithm, require_supported_algorithm
from shield_orchestrator.v4.key_registry import KeyRegistry, KeyRegistryEntry, load_key_registry
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
TEST_ONLY_SIGNATURE_PREFIXES = {
    "adn": "TEST-ONLY-ADN-SIGNATURE",
    "dqsn": "TEST-ONLY-DQSN-SIGNATURE",
    "guardian_wallet": "TEST-ONLY-GUARDIAN-WALLET-SIGNATURE",
    "qwg": "TEST-ONLY-QWG-SIGNATURE",
    "sentinel_ai": "TEST-ONLY-SENTINEL-AI-SIGNATURE",
}
SUPPORTED_DECISIONS = ("ALLOW", "ESCALATE", "DENY", "ERROR", "SKIPPED")
REQUIRED_UNSIGNED_VERDICT_FIELDS = frozenset(
    {
        "component_id",
        "contract_version",
        "schema_version",
        "request_id",
        "context_hash",
        "freshness_nonce",
        "not_before",
        "not_after",
        "decision",
        "reason_ids",
        "evidence_hash",
        "evidence_families",
        "metadata",
        "fail_closed",
        "canonicalization_profile",
        "signature_policy",
        "key_registry_version",
    }
)
REQUIRED_SIGNED_VERDICT_FIELDS = REQUIRED_UNSIGNED_VERDICT_FIELDS | {"signed_payload_hash", "signature_bundle"}
OPTIONAL_SIGNED_VERDICT_FIELDS = frozenset({"verification_summary"})
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


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


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


def _require_non_empty_str_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be non-empty list")
    output: list[str] = []
    seen: set[str] = set()
    for item in value:
        clean = _require_non_empty_str(item, field=f"{field} entry")
        if clean in seen:
            raise ValueError(f"{field} entries must be unique")
        seen.add(clean)
        output.append(clean)
    return output


def _contains_forbidden_metadata_authority(value: Any) -> bool:
    if isinstance(value, dict):
        if set(value) & FORBIDDEN_METADATA_AUTHORITY_KEYS:
            return True
        return any(_contains_forbidden_metadata_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_metadata_authority(item) for item in value)
    return False


def component_role_for(component_id: str) -> str:
    clean_component_id = _require_non_empty_str(component_id, field="component_id")
    try:
        return COMPONENT_ROLES[clean_component_id]
    except KeyError as exc:
        raise ValueError("unsupported Shield v4 component") from exc


def unsigned_component_payload(verdict: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        raise ValueError("component verdict must be dict")
    if set(verdict.keys()) - OPTIONAL_SIGNED_VERDICT_FIELDS != REQUIRED_SIGNED_VERDICT_FIELDS:
        raise ValueError("component verdict fields must match required schema")
    component_id = _require_non_empty_str(verdict["component_id"], field="component_id")
    component_role_for(component_id)
    if verdict["contract_version"] != CONTRACT_VERSION:
        raise ValueError("component verdict contract mismatch")
    if verdict["schema_version"] != VERDICT_SCHEMA_VERSION:
        raise ValueError("component verdict schema mismatch")
    if verdict["canonicalization_profile"] != CANONICALIZATION_PROFILE:
        raise ValueError("component canonicalization profile mismatch")
    if verdict["signature_policy"] != SIGNATURE_POLICY_V1.policy_version:
        raise ValueError("component signature policy mismatch")
    if verdict["fail_closed"] is not True:
        raise ValueError("component fail_closed must be true")
    if verdict["decision"] not in SUPPORTED_DECISIONS:
        raise ValueError("unsupported component decision")
    if not isinstance(verdict["metadata"], dict):
        raise ValueError("component metadata must be dict")
    if _contains_forbidden_metadata_authority(verdict["metadata"]):
        raise ValueError("component metadata contains forbidden authority field")
    return {
        "component_id": component_id,
        "contract_version": CONTRACT_VERSION,
        "schema_version": VERDICT_SCHEMA_VERSION,
        "request_id": _require_non_empty_str(verdict["request_id"], field="request_id"),
        "context_hash": _require_hash(verdict["context_hash"], field="context_hash"),
        "freshness_nonce": _require_non_empty_str(verdict["freshness_nonce"], field="freshness_nonce"),
        "not_before": _require_non_empty_str(verdict["not_before"], field="not_before"),
        "not_after": _require_non_empty_str(verdict["not_after"], field="not_after"),
        "decision": verdict["decision"],
        "reason_ids": _require_non_empty_str_list(verdict["reason_ids"], field="reason_ids"),
        "evidence_hash": _require_hash(verdict["evidence_hash"], field="evidence_hash"),
        "evidence_families": _require_non_empty_str_list(verdict["evidence_families"], field="evidence_families"),
        "metadata": dict(verdict["metadata"]),
        "fail_closed": True,
        "canonicalization_profile": CANONICALIZATION_PROFILE,
        "signature_policy": POLICY_VERSION,
        "key_registry_version": _require_positive_int(verdict["key_registry_version"], field="key_registry_version"),
    }


def build_test_component_signature_entry(*, component_id: str, algorithm: str, signed_hash: str) -> dict[str, Any]:
    role = component_role_for(component_id)
    clean_algorithm = require_supported_algorithm(_require_non_empty_str(algorithm, field="algorithm"))
    clean_hash = _require_hash(signed_hash, field="signed_hash")
    key_id = f"test-{role}-{clean_algorithm}-v1"
    standard_profile = default_standard_profile_for_algorithm(clean_algorithm)
    public_key = f"TEST-ONLY-PUBLIC-{role}-{clean_algorithm}-v1"
    signature = hashlib.sha256(
        f"{TEST_ONLY_SIGNATURE_PREFIXES[component_id]}\n{public_key}\n{clean_algorithm}\n{standard_profile}\n{clean_hash}".encode("utf-8")
    ).hexdigest()
    return {
        "algorithm": clean_algorithm,
        "standard_profile": standard_profile,
        "key_id": key_id,
        "key_version": 1,
        "signed_payload_hash": clean_hash,
        "domain_tag": COMPONENT_VERDICT_DOMAIN,
        "signature": signature,
    }


def verify_test_only_component_signature(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
    component_id = next(
        (candidate for candidate, role in COMPONENT_ROLES.items() if role == key.role),
        "",
    )
    if component_id not in TEST_ONLY_SIGNATURE_PREFIXES:
        return False
    expected = hashlib.sha256(
        f"{TEST_ONLY_SIGNATURE_PREFIXES[component_id]}\n{key.public_key}\n{entry['algorithm']}\n{entry['standard_profile']}\n{entry['signed_payload_hash']}".encode("utf-8")
    ).hexdigest()
    return entry["signature"] == expected


def validate_component_verdict_envelope(
    verdict: dict[str, Any],
    *,
    expected_context_hash: str,
    registry: KeyRegistry | dict[str, Any],
    verification_time: str,
    verifier: SignatureVerifier,
) -> dict[str, Any]:
    payload = unsigned_component_payload(verdict)
    if payload["context_hash"] != _require_hash(expected_context_hash, field="expected_context_hash"):
        raise ValueError("component context_hash mismatch")
    expected_payload_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=payload)
    if _require_hash(verdict["signed_payload_hash"], field="signed_payload_hash") != expected_payload_hash:
        raise ValueError("component signed payload hash mismatch")
    loaded_registry = load_key_registry(registry) if isinstance(registry, dict) else registry
    if payload["key_registry_version"] != loaded_registry.registry_version:
        raise ValueError("component key registry version mismatch")
    verification = verify_signature_bundle(
        verdict["signature_bundle"],
        expected_signed_payload_hash=expected_payload_hash,
        expected_domain_tag=COMPONENT_VERDICT_DOMAIN,
        required_role=component_role_for(payload["component_id"]),
        registry=loaded_registry,
        verification_time=verification_time,
        artifact_not_before=payload["not_before"],
        artifact_not_after=payload["not_after"],
        verifier=verifier,
    )
    return {**verdict, "verification_summary": verification}


def verify_component_verdicts(
    component_verdicts: list[dict[str, Any]],
    *,
    expected_context_hash: str,
    registry: KeyRegistry | dict[str, Any],
    verification_time: str,
    verifier: SignatureVerifier,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(component_verdicts, list) or len(component_verdicts) != len(SUPPORTED_COMPONENTS):
        raise ValueError("component_verdicts must contain every required Shield v4 component")
    loaded_registry = load_key_registry(registry) if isinstance(registry, dict) else registry
    verified: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for verdict in component_verdicts:
        checked = validate_component_verdict_envelope(
            verdict,
            expected_context_hash=expected_context_hash,
            registry=loaded_registry,
            verification_time=verification_time,
            verifier=verifier,
        )
        component_id = checked["component_id"]
        if component_id in seen:
            raise ValueError("duplicate component verdict")
        seen.add(component_id)
        verified.append(checked)
        summaries.append(
            {
                "component_id": component_id,
                "component_role": component_role_for(component_id),
                "verified": True,
                "verified_algorithms": list(checked["verification_summary"]["verified_algorithms"]),
                "signature_policy": checked["verification_summary"]["policy_version"],
            }
        )
    return (
        sorted(verified, key=lambda item: item["component_id"]),
        sorted(summaries, key=lambda item: item["component_id"]),
    )
