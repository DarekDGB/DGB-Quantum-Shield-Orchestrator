from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from shield_orchestrator.v4 import KEY_REGISTRY_SCHEMA_VERSION
from shield_orchestrator.v4.crypto_algorithms import require_supported_algorithm

ACTIVE = "active"
REVOKED = "revoked"
SUPPORTED_ROLES = (
    "shield_component_adn",
    "shield_component_dqsn",
    "shield_component_guardian_wallet",
    "shield_component_qwg",
    "shield_component_sentinel_ai",
    "shield_orchestrator",
)


@dataclass(frozen=True)
class KeyRegistryEntry:
    role: str
    key_id: str
    key_version: int
    algorithm: str
    not_before: str
    not_after: str
    status: str
    public_key: str


@dataclass(frozen=True)
class KeyRegistry:
    schema_version: str
    registry_version: int
    entries: tuple[KeyRegistryEntry, ...]


def parse_utc_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be RFC3339 UTC timestamp ending in Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty string")
    return value.strip()


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


def load_key_registry(raw: dict[str, Any]) -> KeyRegistry:
    if not isinstance(raw, dict):
        raise ValueError("key registry must be dict")
    if set(raw.keys()) != {"schema_version", "registry_version", "entries"}:
        raise ValueError("key registry fields must match required schema")
    if raw["schema_version"] != KEY_REGISTRY_SCHEMA_VERSION:
        raise ValueError("key registry schema mismatch")
    registry_version = _require_positive_int(raw["registry_version"], field="registry_version")
    if not isinstance(raw["entries"], list) or not raw["entries"]:
        raise ValueError("key registry entries must be non-empty list")
    entries: list[KeyRegistryEntry] = []
    seen: set[tuple[str, int, str, str]] = set()
    for entry in raw["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("key registry entry must be dict")
        if set(entry.keys()) != {
            "role",
            "key_id",
            "key_version",
            "algorithm",
            "not_before",
            "not_after",
            "status",
            "public_key",
        }:
            raise ValueError("key registry entry fields must match required schema")
        role = _require_non_empty_str(entry["role"], field="role")
        if role not in SUPPORTED_ROLES:
            raise ValueError("unsupported key role")
        key_id = _require_non_empty_str(entry["key_id"], field="key_id")
        key_version = _require_positive_int(entry["key_version"], field="key_version")
        algorithm = require_supported_algorithm(_require_non_empty_str(entry["algorithm"], field="algorithm"))
        not_before = _require_non_empty_str(entry["not_before"], field="not_before")
        not_after = _require_non_empty_str(entry["not_after"], field="not_after")
        if parse_utc_timestamp(not_before, field="not_before") >= parse_utc_timestamp(not_after, field="not_after"):
            raise ValueError("key validity window is invalid")
        status = _require_non_empty_str(entry["status"], field="status")
        if status not in {ACTIVE, REVOKED}:
            raise ValueError("unsupported key status")
        public_key = _require_non_empty_str(entry["public_key"], field="public_key")
        identity = (role, key_version, algorithm, key_id)
        if identity in seen:
            raise ValueError("duplicate key registry entry")
        seen.add(identity)
        entries.append(
            KeyRegistryEntry(
                role=role,
                key_id=key_id,
                key_version=key_version,
                algorithm=algorithm,
                not_before=not_before,
                not_after=not_after,
                status=status,
                public_key=public_key,
            )
        )
    return KeyRegistry(
        schema_version=raw["schema_version"],
        registry_version=registry_version,
        entries=tuple(entries),
    )


def enforce_registry_floor(*, registry: KeyRegistry, minimum_registry_version: int) -> None:
    if registry.registry_version < minimum_registry_version:
        raise ValueError("key registry rollback detected")


def find_key(
    registry: KeyRegistry,
    *,
    role: str,
    key_id: str,
    key_version: int,
    algorithm: str,
    verification_time: str,
    artifact_not_before: str,
    artifact_not_after: str,
) -> KeyRegistryEntry:
    if role not in SUPPORTED_ROLES:
        raise ValueError("unsupported key role")
    require_supported_algorithm(algorithm)
    verification_dt = parse_utc_timestamp(verification_time, field="verification_time")
    artifact_start = parse_utc_timestamp(artifact_not_before, field="artifact_not_before")
    artifact_end = parse_utc_timestamp(artifact_not_after, field="artifact_not_after")
    if artifact_start >= artifact_end:
        raise ValueError("artifact freshness window is invalid")
    for entry in registry.entries:
        if (
            entry.role == role
            and entry.key_id == key_id
            and entry.key_version == key_version
            and entry.algorithm == algorithm
        ):
            if entry.status != ACTIVE:
                raise ValueError("key is revoked")
            key_start = parse_utc_timestamp(entry.not_before, field="key_not_before")
            key_end = parse_utc_timestamp(entry.not_after, field="key_not_after")
            if not (key_start <= verification_dt <= key_end):
                raise ValueError("key is not valid at verification time")
            if not (key_start <= artifact_start <= key_end and key_start <= artifact_end <= key_end):
                raise ValueError("artifact was produced outside key validity window")
            return entry
    raise ValueError("trusted key not found")


def build_test_registry() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for role in SUPPORTED_ROLES:
        for algorithm in ("classical-ed25519", "ml-dsa", "fn-dsa"):
            entries.append(
                {
                    "role": role,
                    "key_id": f"test-{role}-{algorithm}-v1",
                    "key_version": 1,
                    "algorithm": algorithm,
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                    "status": "active",
                    "public_key": f"TEST-ONLY-PUBLIC-{role}-{algorithm}-v1",
                }
            )
    return {
        "schema_version": KEY_REGISTRY_SCHEMA_VERSION,
        "registry_version": 1,
        "entries": entries,
    }
