from __future__ import annotations

import copy
import hmac

import pytest

from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.contracts.v4_receipt import (
    SUPPORTED_COMPONENTS,
    build_signed_receipt_envelope,
    build_unsigned_receipt_payload,
    validate_receipt_envelope,
)
from shield_orchestrator.v4.crypto_algorithms import default_standard_profile_for_algorithm
from shield_orchestrator.v4.key_registry import build_test_registry, load_key_registry
from shield_orchestrator.v4.signature_bundle import build_signature_bundle

CTX = "a" * 64


def _test_verifier(entry, key):
    expected = hmac.new(
        key.public_key.encode("utf-8"),
        f"{entry['domain_tag']}|{entry['signed_payload_hash']}|{entry['algorithm']}|{entry['standard_profile']}|{entry['key_id']}|{entry['key_version']}".encode("utf-8"),
        "sha256",
    ).hexdigest()
    return hmac.compare_digest(entry["signature"], expected)


def component_verdicts() -> list[dict[str, object]]:
    return [
        {
            "component_id": component,
            "schema_version": "shield.verdict.v2",
            "contract_version": 4,
            "context_hash": CTX,
            "decision": "ALLOW",
        }
        for component in reversed(SUPPORTED_COMPONENTS)
    ]


def component_signature_results() -> list[dict[str, object]]:
    return [
        {
            "component_id": component,
            "component_role": {
                "adn": "shield_component_adn",
                "dqsn": "shield_component_dqsn",
                "guardian_wallet": "shield_component_guardian_wallet",
                "qwg": "shield_component_qwg",
                "sentinel_ai": "shield_component_sentinel_ai",
            }[component],
            "verified": True,
            "verified_algorithms": ["classical-ed25519", "ml-dsa"],
            "verified_standard_profiles": [
                default_standard_profile_for_algorithm("classical-ed25519"),
                default_standard_profile_for_algorithm("ml-dsa"),
            ],
            "signature_policy": "policy.v1",
        }
        for component in reversed(SUPPORTED_COMPONENTS)
    ]


def signature_for(algorithm: str, payload_hash: str) -> dict[str, object]:
    key_id = f"test-shield_orchestrator-{algorithm}-v1"
    key_version = 1
    standard_profile = default_standard_profile_for_algorithm(algorithm)
    public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
    return {
        "algorithm": algorithm,
        "standard_profile": standard_profile,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": payload_hash,
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signature": hmac.new(
            public_key.encode("utf-8"),
            f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{payload_hash}|{algorithm}|{standard_profile}|{key_id}|{key_version}".encode("utf-8"),
            "sha256",
        ).hexdigest(),
    }


def unsigned_payload() -> dict[str, object]:
    return build_unsigned_receipt_payload(
        request_id="req-v4-kat",
        context_hash=CTX,
        freshness_nonce="nonce-v4-kat",
        not_before="2026-06-21T00:00:00Z",
        not_after="2026-06-21T00:05:00Z",
        component_verdicts=component_verdicts(),
        component_signature_results=component_signature_results(),
        final_outcome="ALLOW",
        dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        key_registry_version=1,
        adamantineos_handoff={"handoff_allowed": True, "handoff_reason": "ORCH_OK_ALL_COMPONENTS_ALLOW"},
    )


def signed_receipt() -> dict[str, object]:
    shell = build_signed_receipt_envelope(
        unsigned_payload=unsigned_payload(),
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=[]),
    )
    signatures = [signature_for("classical-ed25519", shell["signed_payload_hash"]), signature_for("ml-dsa", shell["signed_payload_hash"])]
    return build_signed_receipt_envelope(
        unsigned_payload=unsigned_payload(),
        signature_bundle=build_signature_bundle(policy_version="policy.v1", signatures=signatures),
    )


def test_v4_receipt_envelope_validates_and_locks_stable_kat_hashes():
    receipt = signed_receipt()
    assert receipt["receipt_hash"] == "9b46e013b5fdcc70df190219fa19548698f48909ce000ccdb64f9062cf4860b6"
    assert receipt["signed_payload_hash"] == "9004b38d7c55f7a2ed7b75b7b129279a64874c050b8c3b944b94e6dd8e80c8ad"
    verified = validate_receipt_envelope(
        receipt,
        expected_context_hash=CTX,
        registry=build_test_registry(),
        verification_time="2026-06-21T00:01:00Z",
        verifier=_test_verifier,
    )
    assert verified["verification_summary"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert [item["component_id"] for item in receipt["component_verdicts"]] == list(SUPPORTED_COMPONENTS)


def test_v4_receipt_builder_rejects_malformed_inputs():
    base_kwargs = {
        "request_id": "req-v4",
        "context_hash": CTX,
        "freshness_nonce": "nonce",
        "not_before": "2026-06-21T00:00:00Z",
        "not_after": "2026-06-21T00:05:00Z",
        "component_verdicts": component_verdicts(),
        "component_signature_results": component_signature_results(),
        "final_outcome": "ALLOW",
        "dominant_reason_ids": ["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        "key_registry_version": 1,
        "adamantineos_handoff": {"handoff_allowed": True},
    }
    mutations = [
        lambda data: data.__setitem__("request_id", ""),
        lambda data: data.__setitem__("context_hash", "bad"),
        lambda data: data.__setitem__("freshness_nonce", ""),
        lambda data: data.__setitem__("component_verdicts", []),
        lambda data: data.__setitem__("component_verdicts", [{"component_id": "adn"} for _ in SUPPORTED_COMPONENTS]),
        lambda data: data.__setitem__("component_signature_results", []),
        lambda data: data.__setitem__("final_outcome", "MAYBE"),
        lambda data: data.__setitem__("dominant_reason_ids", []),
        lambda data: data.__setitem__("key_registry_version", 0),
        lambda data: data.__setitem__("adamantineos_handoff", []),
        lambda data: data.__setitem__("adamantineos_handoff", {"override": True}),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(base_kwargs)
        mutate(candidate)
        with pytest.raises(ValueError):
            build_unsigned_receipt_payload(**candidate)


def test_v4_receipt_envelope_rejects_schema_tampering():
    registry = load_key_registry(build_test_registry())
    receipt = signed_receipt()
    mutations = [
        lambda item: item.pop("schema_version"),
        lambda item: item.__setitem__("schema_version", "bad"),
        lambda item: item.__setitem__("contract_version", 3),
        lambda item: item.__setitem__("fail_closed", False),
        lambda item: item.__setitem__("canonicalization_profile", "bad"),
        lambda item: item.__setitem__("signature_policy", "policy.v0"),
        lambda item: item.__setitem__("context_hash", "b" * 64),
        lambda item: item.__setitem__("receipt_hash", "b" * 64),
        lambda item: item.__setitem__("signed_payload_hash", "b" * 64),
        lambda item: item.__setitem__("key_registry_version", 2),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(receipt)
        mutate(candidate)
        with pytest.raises(ValueError):
            validate_receipt_envelope(
                candidate,
                expected_context_hash=CTX,
                registry=registry,
                verification_time="2026-06-21T00:01:00Z",
                verifier=_test_verifier,
            )
    with pytest.raises(ValueError, match="receipt must be dict"):
        validate_receipt_envelope(
            "bad",  # type: ignore[arg-type]
            expected_context_hash=CTX,
            registry=registry,
            verification_time="2026-06-21T00:01:00Z",
            verifier=_test_verifier,
        )
    with pytest.raises(ValueError, match="unsigned receipt"):
        build_signed_receipt_envelope(unsigned_payload={"bad": True}, signature_bundle={})


def test_v4_receipt_covers_hash_edge_and_list_metadata_authority():
    with pytest.raises(ValueError, match="sha256 hex"):
        build_unsigned_receipt_payload(
            request_id="req-v4",
            context_hash="g" * 64,
            freshness_nonce="nonce",
            not_before="2026-06-21T00:00:00Z",
            not_after="2026-06-21T00:05:00Z",
            component_verdicts=component_verdicts(),
            component_signature_results=component_signature_results(),
            final_outcome="ALLOW",
            dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
            key_registry_version=1,
            adamantineos_handoff={"handoff_allowed": True},
        )
    with pytest.raises(ValueError, match="lowercase"):
        build_unsigned_receipt_payload(
            request_id="req-v4",
            context_hash="A" * 64,
            freshness_nonce="nonce",
            not_before="2026-06-21T00:00:00Z",
            not_after="2026-06-21T00:05:00Z",
            component_verdicts=component_verdicts(),
            component_signature_results=component_signature_results(),
            final_outcome="ALLOW",
            dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
            key_registry_version=1,
            adamantineos_handoff={"handoff_allowed": True},
        )
    with pytest.raises(ValueError, match="forbidden authority"):
        build_unsigned_receipt_payload(
            request_id="req-v4",
            context_hash=CTX,
            freshness_nonce="nonce",
            not_before="2026-06-21T00:00:00Z",
            not_after="2026-06-21T00:05:00Z",
            component_verdicts=component_verdicts(),
            component_signature_results=component_signature_results(),
            final_outcome="ALLOW",
            dominant_reason_ids=["ORCH_OK_ALL_COMPONENTS_ALLOW"],
            key_registry_version=1,
            adamantineos_handoff={"events": [{"override": True}]},
        )


def test_v4_receipt_rejects_registry_version_mismatch_after_rehash():
    receipt = signed_receipt()
    registry = build_test_registry()
    registry["registry_version"] = 2
    with pytest.raises(ValueError, match="key registry version"):
        validate_receipt_envelope(
            receipt,
            expected_context_hash=CTX,
            registry=registry,
            verification_time="2026-06-21T00:01:00Z",
            verifier=_test_verifier,
        )


def test_v48h_e_component_signature_result_profiles_are_schema_locked():
    base_kwargs = {
        "request_id": "req-v48h-e",
        "context_hash": CTX,
        "freshness_nonce": "nonce-v48h-e",
        "not_before": "2026-06-21T00:00:00Z",
        "not_after": "2026-06-21T00:05:00Z",
        "component_verdicts": component_verdicts(),
        "component_signature_results": component_signature_results(),
        "final_outcome": "ALLOW",
        "dominant_reason_ids": ["ORCH_OK_ALL_COMPONENTS_ALLOW"],
        "key_registry_version": 1,
        "adamantineos_handoff": {"handoff_allowed": True},
    }

    missing_profile_field = copy.deepcopy(base_kwargs)
    missing_profile_field["component_signature_results"][0].pop("verified_standard_profiles")
    with pytest.raises(ValueError, match="component signature result fields"):
        build_unsigned_receipt_payload(**missing_profile_field)

    profile_mismatch = copy.deepcopy(base_kwargs)
    profile_mismatch["component_signature_results"][0]["verified_algorithms"] = [
        "classical-ed25519",
        "ml-dsa",
        "fn-dsa",
    ]
    profile_mismatch["component_signature_results"][0]["verified_standard_profiles"] = [
        default_standard_profile_for_algorithm("classical-ed25519"),
        default_standard_profile_for_algorithm("ml-dsa"),
        "fips206-final-falcon1024-v1",
    ]
    with pytest.raises(ValueError, match="unsupported standard_profile"):
        build_unsigned_receipt_payload(**profile_mismatch)

    profile_omitted = copy.deepcopy(base_kwargs)
    profile_omitted["component_signature_results"][0]["verified_algorithms"] = [
        "classical-ed25519",
        "ml-dsa",
        "fn-dsa",
    ]
    profile_omitted["component_signature_results"][0]["verified_standard_profiles"] = [
        default_standard_profile_for_algorithm("classical-ed25519"),
        default_standard_profile_for_algorithm("ml-dsa"),
    ]
    with pytest.raises(ValueError, match="profiles must match algorithms"):
        build_unsigned_receipt_payload(**profile_omitted)


def test_v4_kat_fixture_matches_generated_receipt_vector():
    import json
    from pathlib import Path

    fixture = json.loads((Path(__file__).parent / "fixtures" / "v4" / "orchestrator_receipt_policy_v1_kat.json").read_text())
    receipt = signed_receipt()
    assert fixture["receipt_hash"] == receipt["receipt_hash"]
    assert fixture["signed_payload_hash"] == receipt["signed_payload_hash"]
    assert fixture["signature_bundle"] == receipt["signature_bundle"]
    assert fixture["unsigned_payload"] == unsigned_payload()
    assert fixture["warning"].startswith("TEST-ONLY")
