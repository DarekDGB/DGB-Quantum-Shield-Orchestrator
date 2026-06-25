from __future__ import annotations

import copy
import hmac

import pytest

from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.key_registry import build_test_registry, load_key_registry
from shield_orchestrator.v4.signature_bundle import build_signature_bundle, validate_signature_bundle_shape, verify_signature_bundle

PAYLOAD_HASH = "a" * 64


def _test_verifier(entry, key):
    expected = hmac.new(
        key.public_key.encode("utf-8"),
        f"{entry['domain_tag']}|{entry['signed_payload_hash']}|{entry['algorithm']}|{entry['key_id']}|{entry['key_version']}".encode("utf-8"),
        "sha256",
    ).hexdigest()
    return hmac.compare_digest(entry["signature"], expected)


def sig(algorithm: str) -> dict[str, object]:
    key_id = f"test-shield_orchestrator-{algorithm}-v1"
    key_version = 1
    public_key = f"TEST-ONLY-PUBLIC-shield_orchestrator-{algorithm}-v1"
    signature = hmac.new(
        public_key.encode("utf-8"),
        f"{ORCHESTRATOR_RECEIPT_DOMAIN}|{PAYLOAD_HASH}|{algorithm}|{key_id}|{key_version}".encode("utf-8"),
        "sha256",
    ).hexdigest()
    return {
        "algorithm": algorithm,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": PAYLOAD_HASH,
        "domain_tag": ORCHESTRATOR_RECEIPT_DOMAIN,
        "signature": signature,
    }


def good_bundle(extra: bool = False) -> dict[str, object]:
    signatures = [sig("classical-ed25519"), sig("ml-dsa")]
    if extra:
        signatures.append(sig("fn-dsa"))
    return build_signature_bundle(policy_version="policy.v1", signatures=signatures)


def test_v4_signature_bundle_verifies_required_and_optional_paths():
    registry = load_key_registry(build_test_registry())
    summary = verify_signature_bundle(
        good_bundle(extra=True),
        expected_signed_payload_hash=PAYLOAD_HASH,
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        required_role="shield_orchestrator",
        registry=registry,
        verification_time="2026-06-21T00:00:00Z",
        artifact_not_before="2026-06-21T00:00:00Z",
        artifact_not_after="2026-06-21T00:05:00Z",
        verifier=_test_verifier,
    )
    assert summary["required_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert summary["optional_algorithms"] == ["fn-dsa"]
    assert summary["verified_algorithms"] == ["classical-ed25519", "ml-dsa", "fn-dsa"]


def test_v4_signature_bundle_rejects_bad_bundle_shapes():
    for bundle in (
        "bad",
        {"schema_version": "bad", "policy_version": "policy.v1", "signatures": []},
        {"schema_version": "shield.signature_bundle.v1", "policy_version": "policy.v9", "signatures": []},
        {"schema_version": "shield.signature_bundle.v1", "policy_version": "policy.v1", "signatures": []},
        {"schema_version": "shield.signature_bundle.v1", "policy_version": "policy.v1", "signatures": ["bad"]},
    ):
        with pytest.raises(ValueError):
            if isinstance(bundle, dict) and bundle["signatures"] == ["bad"]:
                verify_signature_bundle(
                    bundle,
                    expected_signed_payload_hash=PAYLOAD_HASH,
                    expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
                    required_role="shield_orchestrator",
                    registry=load_key_registry(build_test_registry()),
                    verification_time="2026-06-21T00:00:00Z",
                    artifact_not_before="2026-06-21T00:00:00Z",
                    artifact_not_after="2026-06-21T00:05:00Z",
                    verifier=_test_verifier,
                )
            else:
                validate_signature_bundle_shape(bundle)  # type: ignore[arg-type]


def test_v4_signature_bundle_negative_matrix():
    registry = load_key_registry(build_test_registry())
    mutations = [
        lambda item: item.pop("algorithm"),
        lambda item: item.__setitem__("algorithm", "pqc-falcon"),
        lambda item: item.__setitem__("key_id", ""),
        lambda item: item.__setitem__("key_version", False),
        lambda item: item.__setitem__("signed_payload_hash", "b" * 64),
        lambda item: item.__setitem__("signed_payload_hash", "A" * 64),
        lambda item: item.__setitem__("signed_payload_hash", "bad"),
        lambda item: item.__setitem__("domain_tag", "bad-domain"),
        lambda item: item.__setitem__("signature", "bad"),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(good_bundle())
        mutate(candidate["signatures"][0])
        with pytest.raises(ValueError):
            verify_signature_bundle(
                candidate,
                expected_signed_payload_hash=PAYLOAD_HASH,
                expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
                required_role="shield_orchestrator",
                registry=registry,
                verification_time="2026-06-21T00:00:00Z",
                artifact_not_before="2026-06-21T00:00:00Z",
                artifact_not_after="2026-06-21T00:05:00Z",
                verifier=_test_verifier,
            )


def test_v4_signature_bundle_rejects_missing_required_and_duplicates_and_wrong_role():
    registry = load_key_registry(build_test_registry())
    missing = build_signature_bundle(policy_version="policy.v1", signatures=[sig("classical-ed25519")])
    with pytest.raises(ValueError, match="requirements"):
        verify_signature_bundle(
            missing,
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )

    duplicate_algorithm = good_bundle()
    duplicate_algorithm["signatures"].append(copy.deepcopy(duplicate_algorithm["signatures"][0]))
    with pytest.raises(ValueError, match="duplicate signature algorithm"):
        verify_signature_bundle(
            duplicate_algorithm,
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )

    wrong_role = good_bundle()
    with pytest.raises(ValueError, match="trusted key"):
        verify_signature_bundle(
            wrong_role,
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_component_qwg",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )


def test_v4_signature_bundle_covers_invalid_hash_and_field_shape_edges():
    registry = load_key_registry(build_test_registry())
    with pytest.raises(ValueError, match="sha256 hex"):
        verify_signature_bundle(
            good_bundle(),
            expected_signed_payload_hash="g" * 64,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )
    bad_shape = good_bundle()
    bad_shape["signatures"][0]["extra"] = True
    with pytest.raises(ValueError, match="fields"):
        verify_signature_bundle(
            bad_shape,
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )
    duplicate_key = good_bundle()
    duplicate_key["signatures"][1]["key_id"] = duplicate_key["signatures"][0]["key_id"]
    duplicate_key["signatures"][1]["key_version"] = duplicate_key["signatures"][0]["key_version"]
    with pytest.raises(ValueError, match="duplicate signature key"):
        verify_signature_bundle(
            duplicate_key,
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=_test_verifier,
        )


def test_v4_signature_bundle_rejects_top_level_field_mismatch():
    with pytest.raises(ValueError, match="fields"):
        validate_signature_bundle_shape(
            {
                "schema_version": "shield.signature_bundle.v1",
                "policy_version": "policy.v1",
                "signatures": [sig("classical-ed25519")],
                "extra": True,
            }
        )


def test_v48g_signature_bundle_verifier_failure_surfaces_fail_closed() -> None:
    registry = load_key_registry(build_test_registry())

    class NativeVerifierError(RuntimeError):
        pass

    def raising_verifier(_entry, _key):
        raise NativeVerifierError("native verifier crash")

    with pytest.raises(ValueError, match="signature verifier failed closed") as excinfo:
        verify_signature_bundle(
            good_bundle(),
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=raising_verifier,
        )
    assert isinstance(excinfo.value.__cause__, NativeVerifierError)


def test_v48g_signature_bundle_rejects_truthy_non_bool_verifier_result() -> None:
    registry = load_key_registry(build_test_registry())

    def truthy_non_bool_verifier(_entry, _key):
        return 1

    with pytest.raises(ValueError, match="signature verifier must return bool"):
        verify_signature_bundle(
            good_bundle(),
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role="shield_orchestrator",
            registry=registry,
            verification_time="2026-06-21T00:00:00Z",
            artifact_not_before="2026-06-21T00:00:00Z",
            artifact_not_after="2026-06-21T00:05:00Z",
            verifier=truthy_non_bool_verifier,
        )
