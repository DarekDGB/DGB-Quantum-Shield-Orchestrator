from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from shield_orchestrator.v4.component_verdicts import (
    verify_component_verdicts,
    verify_test_only_component_signature,
)
from shield_orchestrator.v4.contracts.v4_receipt import validate_receipt_envelope
from shield_orchestrator.v4.key_registry import KeyRegistryEntry
from shield_orchestrator.v4.orchestrate import verify_test_only_orchestrator_signature
from shield_orchestrator.v4.real_crypto_backend import (
    encode_binary_signature_material,
    make_real_crypto_signature_verifier,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "v4" / "full_multi_repo_v4_real_backend_allow_flow.json"


class FixtureRealBackend:
    """Deterministic real-backend contract double for V4.8G fixture verification.

    This backend uses explicit b64u binary material and non-TEST key identifiers. It
    exists only to prove cross-repo real-backend interface-contract wiring in CI without
    vendoring liboqs or requiring deployment keys.
    """

    backend_name = "shield-v4.8g-fixture-real-backend"
    backend_version = "contract-test-double;no-production-secrets"
    supported_algorithms = ("classical-ed25519", "ml-dsa")

    def _sign_for_public(self, *, algorithm: str, public_key: str, message: bytes) -> str:
        raw = hashlib.sha256(
            b"shield-v4.8g-real-backend|"
            + algorithm.encode("utf-8")
            + b"|"
            + public_key.encode("utf-8")
            + b"|"
            + message
        ).digest()
        return encode_binary_signature_material(raw, field="signature")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        raise AssertionError("V4.8G fixture verifier must not sign during verification")

    def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> bool:
        return signature == self._sign_for_public(algorithm=algorithm, public_key=public_key, message=message)


def load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def real_verifier():
    return make_real_crypto_signature_verifier(FixtureRealBackend())


def test_v48g_real_backend_fixture_verifies_components_and_orchestrator_receipt() -> None:
    fixture = load_fixture()
    receipt = fixture["receipt"]

    verified_components, component_summaries = verify_component_verdicts(
        receipt["component_verdicts"],
        expected_context_hash=fixture["expected_context_hash"],
        registry=fixture["trusted_key_registry"],
        verification_time=fixture["verification_time"],
        verifier=real_verifier(),
    )
    checked_receipt = validate_receipt_envelope(
        receipt,
        expected_context_hash=fixture["expected_context_hash"],
        registry=fixture["trusted_key_registry"],
        verification_time=fixture["verification_time"],
        verifier=real_verifier(),
    )

    assert fixture["author_attribution"] == "DarekDGB"
    assert fixture["schema_version"] == "shield.v4.8g.real_backend_fixture.v1"
    assert checked_receipt["request_id"] == fixture["expected_request_id"]
    assert checked_receipt["final_outcome"] == "ALLOW"
    assert checked_receipt["adamantineos_handoff"] == {"handoff_allowed": True}
    assert [item["component_id"] for item in verified_components] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert [item["component_id"] for item in component_summaries] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert checked_receipt["verification_summary"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]


def test_v48g_real_backend_fixture_uses_real_b64u_material_and_no_test_only_keys() -> None:
    fixture = load_fixture()
    registry_entries = fixture["trusted_key_registry"]["entries"]
    all_signatures = list(fixture["receipt"]["signature_bundle"]["signatures"])
    for component in fixture["receipt"]["component_verdicts"]:
        all_signatures.extend(component["signature_bundle"]["signatures"])
        summary = component.get("verification_summary")
        assert summary is None or set(summary) >= {"policy_version", "verified_algorithms"}
        assert component["metadata"] == {
            "component": component["component_id"],
            "integration_harness": "shield-v4.8g-real-backend",
            "real_backend_contract": "b64u-signature-material",
        }

    assert len(registry_entries) == 12
    for entry in registry_entries:
        assert not entry["key_id"].startswith("test-")
        assert "test-only" not in entry["public_key"].lower()
        assert entry["public_key"].startswith("b64u:")
    for signature in all_signatures:
        assert signature["signature"].startswith("b64u:")
        assert not signature["key_id"].startswith("test-")


def test_v48g_real_backend_fixture_rejects_test_only_verifier_fallback() -> None:
    fixture = load_fixture()
    receipt = fixture["receipt"]

    with pytest.raises(ValueError, match="signature verification failed"):
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash=fixture["expected_context_hash"],
            registry=fixture["trusted_key_registry"],
            verification_time=fixture["verification_time"],
            verifier=verify_test_only_component_signature,
        )

    with pytest.raises(ValueError, match="signature verification failed"):
        validate_receipt_envelope(
            receipt,
            expected_context_hash=fixture["expected_context_hash"],
            registry=fixture["trusted_key_registry"],
            verification_time=fixture["verification_time"],
            verifier=verify_test_only_orchestrator_signature,
        )


def test_v48g_real_backend_fixture_rejects_missing_mldsa_and_tamper() -> None:
    fixture = load_fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"] = [
        sig
        for sig in receipt["component_verdicts"][0]["signature_bundle"]["signatures"]
        if sig["algorithm"] == "classical-ed25519"
    ]

    with pytest.raises(ValueError, match="requirements"):
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash=fixture["expected_context_hash"],
            registry=fixture["trusted_key_registry"],
            verification_time=fixture["verification_time"],
            verifier=real_verifier(),
        )

    tampered = copy.deepcopy(fixture["receipt"])
    tampered["signature_bundle"]["signatures"][1]["signature"] = encode_binary_signature_material(
        b"tampered-real-backend-signature",
        field="signature",
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        validate_receipt_envelope(
            tampered,
            expected_context_hash=fixture["expected_context_hash"],
            registry=fixture["trusted_key_registry"],
            verification_time=fixture["verification_time"],
            verifier=real_verifier(),
        )


def test_v48g_real_backend_verifier_rejects_truthy_non_bool_integration_result() -> None:
    fixture = load_fixture()

    class NonBoolBackend(FixtureRealBackend):
        def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> object:
            return 1

    with pytest.raises(ValueError, match="signature verifier failed closed") as excinfo:
        validate_receipt_envelope(
            fixture["receipt"],
            expected_context_hash=fixture["expected_context_hash"],
            registry=fixture["trusted_key_registry"],
            verification_time=fixture["verification_time"],
            verifier=make_real_crypto_signature_verifier(NonBoolBackend()),
        )
    assert excinfo.value.__cause__ is not None
    assert "verify must return bool" in str(excinfo.value.__cause__)
