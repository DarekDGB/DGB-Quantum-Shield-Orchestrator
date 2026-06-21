from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable
from typing import Any

from shield_orchestrator.v4 import CANONICALIZATION_PROFILE

SIGNED_PAYLOAD_HASH_PREFIX = "DGB-SHIELD-V4-SIGNED-PAYLOAD"
COMPONENT_VERDICT_DOMAIN = "DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1"
ORCHESTRATOR_RECEIPT_DOMAIN = "DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1"


def _normalise(value: Any, *, path: str) -> Any:
    if value is None:
        raise ValueError(f"{path} must omit absent fields instead of using null")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError(f"{path} must not contain floats")
    if isinstance(value, list):
        return [_normalise(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, tuple):
        return [_normalise(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        normalised: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            clean_key = unicodedata.normalize("NFC", key)
            if clean_key in normalised:
                raise ValueError(f"{path} contains duplicate key after Unicode normalization")
            normalised[clean_key] = _normalise(item, path=f"{path}.{clean_key}")
        return normalised
    raise ValueError(f"{path} contains unsupported type {type(value).__name__}")


def to_canonical_json(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")
    normalised = _normalise(payload, path="$")
    return json.dumps(
        normalised,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def to_canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return to_canonical_json(payload).encode("utf-8")


def _reject_duplicate_json_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        clean_key = unicodedata.normalize("NFC", key)
        if clean_key in result:
            raise ValueError("json contains duplicate key")
        result[clean_key] = value
    return result


def parse_json_no_duplicate_keys(raw_json: str) -> dict[str, Any]:
    parsed = json.loads(raw_json, object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(parsed, dict):
        raise ValueError("json root must be object")
    return parsed


def domain_separated_payload_bytes(*, domain_tag: str, payload: dict[str, Any]) -> bytes:
    if domain_tag not in {COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN}:
        raise ValueError("unsupported Shield v4 domain tag")
    return (
        f"{SIGNED_PAYLOAD_HASH_PREFIX}\n{domain_tag}\n".encode("utf-8")
        + to_canonical_json_bytes(payload)
    )


def signed_payload_hash(*, domain_tag: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(domain_separated_payload_bytes(domain_tag=domain_tag, payload=payload)).hexdigest()


def canonicalization_manifest() -> dict[str, str]:
    return {
        "canonicalization_profile": CANONICALIZATION_PROFILE,
        "hash_prefix": SIGNED_PAYLOAD_HASH_PREFIX,
        "component_verdict_domain": COMPONENT_VERDICT_DOMAIN,
        "orchestrator_receipt_domain": ORCHESTRATOR_RECEIPT_DOMAIN,
    }
