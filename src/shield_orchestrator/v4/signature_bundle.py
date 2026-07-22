from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeAlias

from shield_orchestrator.v4 import SIGNATURE_BUNDLE_SCHEMA_VERSION
from shield_orchestrator.v4.crypto_algorithms import (
    get_signature_policy,
    require_supported_algorithm,
    require_supported_standard_profile,
)
from shield_orchestrator.v4.key_registry import KeyRegistry, KeyRegistryEntry, find_key

SignatureVerifier: TypeAlias = Callable[[dict[str, Any], KeyRegistryEntry], bool]
SIGNATURE_ENTRY_FIELDS = frozenset(
    {
        "algorithm",
        "standard_profile",
        "key_id",
        "key_version",
        "signed_payload_hash",
        "domain_tag",
        "signature",
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


def build_signature_bundle(*, policy_version: str, signatures: list[dict[str, Any]]) -> dict[str, Any]:
    policy = get_signature_policy(_require_non_empty_str(policy_version, field="policy_version"))
    algorithm_rank = {algorithm: index for index, algorithm in enumerate(policy.allowed_algorithms)}

    def canonical_rank(entry: dict[str, Any]) -> int:
        if not isinstance(entry, dict):
            raise ValueError("signature entry must be dict")
        algorithm = require_supported_algorithm(_require_non_empty_str(entry.get("algorithm"), field="algorithm"))
        return algorithm_rank[algorithm]

    return {
        "schema_version": SIGNATURE_BUNDLE_SCHEMA_VERSION,
        "policy_version": policy.policy_version,
        "signatures": sorted(signatures, key=canonical_rank),
    }


def validate_signature_bundle_shape(bundle: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("signature bundle must be dict")
    if set(bundle.keys()) != {"schema_version", "policy_version", "signatures"}:
        raise ValueError("signature bundle fields must match required schema")
    if bundle["schema_version"] != SIGNATURE_BUNDLE_SCHEMA_VERSION:
        raise ValueError("signature bundle schema mismatch")
    get_signature_policy(_require_non_empty_str(bundle["policy_version"], field="policy_version"))
    if not isinstance(bundle["signatures"], list) or not bundle["signatures"]:
        raise ValueError("signature bundle signatures must be non-empty list")
    return dict(bundle)


def verify_signature_bundle(
    bundle: dict[str, Any],
    *,
    expected_signed_payload_hash: str,
    expected_domain_tag: str,
    required_role: str,
    registry: KeyRegistry,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
    verifier: SignatureVerifier,
) -> dict[str, Any]:
    checked_bundle = validate_signature_bundle_shape(bundle)
    policy = get_signature_policy(checked_bundle["policy_version"])
    expected_hash = _require_hash(expected_signed_payload_hash, field="expected_signed_payload_hash")
    seen_algorithms: set[str] = set()
    seen_keys: set[tuple[str, int]] = set()
    prepared_entries: list[tuple[dict[str, Any], str, str, str, int]] = []
    algorithm_sequence: list[str] = []
    results: list[dict[str, Any]] = []
    for entry in checked_bundle["signatures"]:
        if not isinstance(entry, dict):
            raise ValueError("signature entry must be dict")
        if set(entry.keys()) != SIGNATURE_ENTRY_FIELDS:
            raise ValueError("signature entry fields must match required schema")
        algorithm = require_supported_algorithm(_require_non_empty_str(entry["algorithm"], field="algorithm"))
        standard_profile = require_supported_standard_profile(
            algorithm=algorithm,
            standard_profile=_require_non_empty_str(entry["standard_profile"], field="standard_profile"),
        )
        if algorithm in seen_algorithms:
            raise ValueError("duplicate signature algorithm")
        seen_algorithms.add(algorithm)
        algorithm_sequence.append(algorithm)
        key_id = _require_non_empty_str(entry["key_id"], field="key_id")
        key_version = _require_positive_int(entry["key_version"], field="key_version")
        key_identity = (key_id, key_version)
        if key_identity in seen_keys:
            raise ValueError("duplicate signature key entry")
        seen_keys.add(key_identity)
        if _require_hash(entry["signed_payload_hash"], field="signed_payload_hash") != expected_hash:
            raise ValueError("signature signed_payload_hash mismatch")
        if _require_non_empty_str(entry["domain_tag"], field="domain_tag") != expected_domain_tag:
            raise ValueError("signature domain tag mismatch")
        prepared_entries.append((entry, algorithm, standard_profile, key_id, key_version))

    canonical_sequence = [algorithm for algorithm in policy.allowed_algorithms if algorithm in seen_algorithms]
    if algorithm_sequence != canonical_sequence:
        raise ValueError("signature algorithms must use canonical policy order")
    missing = set(policy.required_algorithms) - seen_algorithms
    if missing:
        raise ValueError("signature policy requirements not satisfied")

    for entry, algorithm, standard_profile, key_id, key_version in prepared_entries:
        key = find_key(
            registry,
            role=required_role,
            key_id=key_id,
            key_version=key_version,
            algorithm=algorithm,
            verification_time=verification_time,
            artifact_not_before=artifact_not_before,
            artifact_not_after=artifact_not_after,
        )
        try:
            verified = verifier(entry, key)
        except Exception as exc:
            raise ValueError("signature verifier failed closed") from exc
        if not isinstance(verified, bool):
            raise ValueError("signature verifier must return bool")
        if not verified:
            raise ValueError("signature verification failed")
        results.append(
            {
                "algorithm": algorithm,
                "standard_profile": standard_profile,
                "key_id": key_id,
                "key_version": key_version,
                "verified": True,
            }
        )
    return {
        "policy_version": policy.policy_version,
        "required_algorithms": list(policy.required_algorithms),
        "optional_algorithms": list(policy.optional_algorithms),
        "verified_algorithms": [result["algorithm"] for result in results],
        "verified_standard_profiles": [result["standard_profile"] for result in results],
        "results": results,
    }
