from __future__ import annotations

import copy
import hmac

import pytest

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.crypto_algorithms import (
    FIPS206_DRAFT_FALCON1024_PROFILE,
    default_standard_profile_for_algorithm,
    require_supported_standard_profile,
)
from shield_orchestrator.v4.key_registry import build_test_registry, load_key_registry
from shield_orchestrator.v4.signature_bundle import build_signature_bundle, verify_signature_bundle

PAYLOAD_HASH = "b" * 64
VERIFICATION_TIME = "2026-06-21T00:01:00Z"
NOT_BEFORE = "2026-06-21T00:00:00Z"
NOT_AFTER = "2026-06-21T00:05:00Z"
ROLE = "shield_orchestrator"


def _signature_material(
    *,
    public_key: str,
    domain_tag: str,
    signed_payload_hash: str,
    algorithm: str,
    standard_profile: str,
    key_id: str,
    key_version: int,
) -> str:
    return hmac.new(
        public_key.encode("utf-8"),
        f"{domain_tag}|{signed_payload_hash}|{algorithm}|{standard_profile}|{key_id}|{key_version}".encode("utf-8"),
        "sha256",
    ).hexdigest()


def _test_verifier(entry, key):
    expected = _signature_material(
        public_key=key.public_key,
        domain_tag=entry["domain_tag"],
        signed_payload_hash=entry["signed_payload_hash"],
        algorithm=entry["algorithm"],
        standard_profile=entry["standard_profile"],
        key_id=entry["key_id"],
        key_version=entry["key_version"],
    )
    return hmac.compare_digest(entry["signature"], expected)


def signature_for(
    algorithm: str,
    *,
    role: str = ROLE,
    signed_payload_hash: str = PAYLOAD_HASH,
    domain_tag: str = ORCHESTRATOR_RECEIPT_DOMAIN,
) -> dict[str, object]:
    key_id = f"test-{role}-{algorithm}-v1"
    key_version = 1
    standard_profile = default_standard_profile_for_algorithm(algorithm)
    public_key = f"TEST-ONLY-PUBLIC-{role}-{algorithm}-v1"
    return {
        "algorithm": algorithm,
        "standard_profile": standard_profile,
        "key_id": key_id,
        "key_version": key_version,
        "signed_payload_hash": signed_payload_hash,
        "domain_tag": domain_tag,
        "signature": _signature_material(
            public_key=public_key,
            domain_tag=domain_tag,
            signed_payload_hash=signed_payload_hash,
            algorithm=algorithm,
            standard_profile=standard_profile,
            key_id=key_id,
            key_version=key_version,
        ),
    }


def verify(signatures: list[dict[str, object]]) -> dict[str, object]:
    return verify_signature_bundle(
        build_signature_bundle(policy_version="policy.v1", signatures=signatures),
        expected_signed_payload_hash=PAYLOAD_HASH,
        expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        required_role=ROLE,
        registry=load_key_registry(build_test_registry()),
        verification_time=VERIFICATION_TIME,
        artifact_not_before=NOT_BEFORE,
        artifact_not_after=NOT_AFTER,
        verifier=_test_verifier,
    )


def test_v48h_fn_dsa_absent_allowed_and_valid_optional_evidence_recorded() -> None:
    absent_summary = verify([signature_for("classical-ed25519"), signature_for("ml-dsa")])
    assert absent_summary["required_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert absent_summary["optional_algorithms"] == ["fn-dsa"]
    assert absent_summary["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]

    hybrid_summary = verify([signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa")])
    assert hybrid_summary["verified_algorithms"] == ["classical-ed25519", "ml-dsa", "fn-dsa"]
    assert hybrid_summary["results"][-1]["standard_profile"] == FIPS206_DRAFT_FALCON1024_PROFILE
    assert hybrid_summary["verified_standard_profiles"][-1] == FIPS206_DRAFT_FALCON1024_PROFILE


@pytest.mark.parametrize("required_algorithm", ["classical-ed25519", "ml-dsa"])
def test_v48h_valid_fn_dsa_cannot_rescue_required_signature_failure(required_algorithm: str) -> None:
    signatures = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa")]
    for entry in signatures:
        if entry["algorithm"] == required_algorithm:
            entry["signature"] = "0" * 64

    with pytest.raises(ValueError, match="signature verification failed"):
        verify(signatures)


def test_v48h_valid_fn_dsa_cannot_replace_missing_ml_dsa() -> None:
    signatures = [signature_for("classical-ed25519"), signature_for("fn-dsa")]

    with pytest.raises(ValueError, match="requirements"):
        verify(signatures)


def test_v48h_present_fn_dsa_invalid_unresolvable_or_wrong_role_is_fatal() -> None:
    invalid = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa")]
    invalid[-1]["signature"] = "0" * 64
    with pytest.raises(ValueError, match="signature verification failed"):
        verify(invalid)

    wrong_role = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa", role="shield_component_qwg")]
    with pytest.raises(ValueError, match="trusted key not found"):
        verify(wrong_role)

    duplicate = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa"), signature_for("fn-dsa")]
    with pytest.raises(ValueError, match="duplicate signature algorithm"):
        verify(duplicate)


def test_v48h_present_fn_dsa_no_registry_key_is_fatal_not_absent() -> None:
    raw_registry = build_test_registry()
    raw_registry["entries"] = [entry for entry in raw_registry["entries"] if not (entry["role"] == ROLE and entry["algorithm"] == "fn-dsa")]

    with pytest.raises(ValueError, match="trusted key not found"):
        verify_signature_bundle(
            build_signature_bundle(
                policy_version="policy.v1",
                signatures=[signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa")],
            ),
            expected_signed_payload_hash=PAYLOAD_HASH,
            expected_domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
            required_role=ROLE,
            registry=load_key_registry(raw_registry),
            verification_time=VERIFICATION_TIME,
            artifact_not_before=NOT_BEFORE,
            artifact_not_after=NOT_AFTER,
            verifier=_test_verifier,
        )


def test_v48h_fn_dsa_profile_and_payload_binding_fail_closed() -> None:
    unsupported_profile = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa")]
    unsupported_profile[-1]["standard_profile"] = "fips206-draft-falcon512-v1"
    with pytest.raises(ValueError, match="standard_profile"):
        verify(unsupported_profile)

    wrong_hash = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa", signed_payload_hash="c" * 64)]
    with pytest.raises(ValueError, match="signed_payload_hash mismatch"):
        verify(wrong_hash)

    wrong_domain = [signature_for("classical-ed25519"), signature_for("ml-dsa"), signature_for("fn-dsa", domain_tag=COMPONENT_VERDICT_DOMAIN)]
    with pytest.raises(ValueError, match="domain tag mismatch"):
        verify(wrong_domain)


def test_v48h_standard_profile_is_authenticated_not_metadata_only() -> None:
    entry = signature_for("fn-dsa")
    profile_flipped_after_signing = copy.deepcopy(entry)
    profile_flipped_after_signing["standard_profile"] = FIPS206_DRAFT_FALCON1024_PROFILE
    profile_flipped_after_signing["signature"] = _signature_material(
        public_key="TEST-ONLY-PUBLIC-shield_orchestrator-fn-dsa-v1",
        domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN,
        signed_payload_hash=PAYLOAD_HASH,
        algorithm="fn-dsa",
        standard_profile="fips206-draft-falcon512-v1",
        key_id="test-shield_orchestrator-fn-dsa-v1",
        key_version=1,
    )

    with pytest.raises(ValueError, match="signature verification failed"):
        verify([signature_for("classical-ed25519"), signature_for("ml-dsa"), profile_flipped_after_signing])


def test_v48h_standard_profile_allow_list_rejects_empty_profile() -> None:
    with pytest.raises(ValueError, match="standard_profile"):
        require_supported_standard_profile(algorithm="fn-dsa", standard_profile="")
