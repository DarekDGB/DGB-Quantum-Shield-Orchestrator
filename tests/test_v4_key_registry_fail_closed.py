from __future__ import annotations

import copy

import pytest

from shield_orchestrator.v4.key_registry import (
    build_test_registry,
    enforce_registry_floor,
    find_key,
    load_key_registry,
    parse_utc_timestamp,
)


def test_v4_key_registry_loads_test_registry_and_finds_key():
    registry = load_key_registry(build_test_registry())
    key = find_key(
        registry,
        role="shield_orchestrator",
        key_id="test-shield_orchestrator-ml-dsa-v1",
        key_version=1,
        algorithm="ml-dsa",
        verification_time="2026-06-21T00:00:00Z",
        artifact_not_before="2026-06-21T00:00:00Z",
        artifact_not_after="2026-06-21T00:05:00Z",
    )
    assert key.role == "shield_orchestrator"
    assert key.algorithm == "ml-dsa"


def test_v4_key_registry_rejects_bad_registry_shapes():
    for raw in (
        "bad",
        {"schema_version": "bad", "registry_version": 1, "entries": []},
        {"schema_version": "shield.key_registry.v1", "registry_version": 0, "entries": []},
        {"schema_version": "shield.key_registry.v1", "registry_version": 1, "entries": []},
        {"schema_version": "shield.key_registry.v1", "registry_version": 1, "entries": ["bad"]},
    ):
        with pytest.raises(ValueError):
            load_key_registry(raw)  # type: ignore[arg-type]


def test_v4_key_registry_rejects_entry_mutations():
    raw = build_test_registry()
    base_entry = raw["entries"][0]
    mutations = [
        lambda entry: entry.pop("role"),
        lambda entry: entry.__setitem__("role", "qid_identity"),
        lambda entry: entry.__setitem__("key_id", ""),
        lambda entry: entry.__setitem__("key_version", True),
        lambda entry: entry.__setitem__("algorithm", "pqc-falcon"),
        lambda entry: entry.__setitem__("not_before", "2031-01-02T00:00:00Z"),
        lambda entry: entry.__setitem__("not_after", "bad"),
        lambda entry: entry.__setitem__("status", "disabled"),
        lambda entry: entry.__setitem__("public_key", ""),
    ]
    for mutate in mutations:
        candidate = {"schema_version": raw["schema_version"], "registry_version": 1, "entries": [copy.deepcopy(base_entry)]}
        mutate(candidate["entries"][0])
        with pytest.raises(ValueError):
            load_key_registry(candidate)


def test_v4_key_registry_rejects_duplicate_revoked_expired_and_rollback():
    raw = build_test_registry()
    duplicate = copy.deepcopy(raw)
    duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        load_key_registry(duplicate)

    revoked = copy.deepcopy(raw)
    revoked["entries"][0]["status"] = "revoked"
    registry = load_key_registry(revoked)
    with pytest.raises(ValueError, match="revoked"):
        find_key(
            registry,
            role=revoked["entries"][0]["role"],
            key_id=revoked["entries"][0]["key_id"],
            key_version=1,
            algorithm=revoked["entries"][0]["algorithm"],
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
        )

    active = load_key_registry(raw)
    with pytest.raises(ValueError, match="verification time"):
        find_key(
            active,
            role="shield_orchestrator",
            key_id="test-shield_orchestrator-ml-dsa-v1",
            key_version=1,
            algorithm="ml-dsa",
            verification_time="2031-01-01T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
        )
    with pytest.raises(ValueError, match="outside key"):
        find_key(
            active,
            role="shield_orchestrator",
            key_id="test-shield_orchestrator-ml-dsa-v1",
            key_version=1,
            algorithm="ml-dsa",
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2031-01-01T00:00:00Z",
            artifact_not_after="2031-01-01T00:05:00Z",
        )
    with pytest.raises(ValueError, match="freshness window"):
        find_key(
            active,
            role="shield_orchestrator",
            key_id="test-shield_orchestrator-ml-dsa-v1",
            key_version=1,
            algorithm="ml-dsa",
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:05:00Z",
            artifact_not_after="2026-06-21T00:00:00Z",
        )
    with pytest.raises(ValueError, match="rollback"):
        enforce_registry_floor(registry=active, minimum_registry_version=2)


def test_v4_key_registry_timestamp_and_lookup_guards():
    registry = load_key_registry(build_test_registry())
    for value in ("2026-01-01T00:00:00+00:00", "bad"):
        with pytest.raises(ValueError):
            parse_utc_timestamp(value, field="test")
    with pytest.raises(ValueError, match="unsupported key role"):
        find_key(
            registry,
            role="qid_identity",
            key_id="x",
            key_version=1,
            algorithm="ml-dsa",
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
        )
    with pytest.raises(ValueError, match="trusted key"):
        find_key(
            registry,
            role="shield_orchestrator",
            key_id="missing",
            key_version=1,
            algorithm="ml-dsa",
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
        )


def test_v4_key_registry_rejects_top_level_schema_field_mismatch():
    with pytest.raises(ValueError, match="fields"):
        load_key_registry({"schema_version": "shield.key_registry.v1", "registry_version": 1, "entries": [], "extra": True})
