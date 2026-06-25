from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from shield_orchestrator.v4.canonical_json import ORCHESTRATOR_RECEIPT_DOMAIN, signed_payload_hash
from shield_orchestrator.v4.component_verdicts import COMPONENT_ROLES, verify_component_verdicts
from shield_orchestrator.v4.contracts.v4_receipt import build_receipt_hash, validate_receipt_envelope
from shield_orchestrator.v4.real_crypto_backend import (
    build_signature_entry_with_real_backend,
    decode_binary_signature_material,
    encode_binary_signature_material,
    make_real_crypto_signature_verifier,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "v4" / "full_multi_repo_v4_allow_flow.json"
ORCHESTRATOR_ROLE = "shield_orchestrator"


class IntegratedRealBackend:
    backend_name = "fixture-real-backend"
    backend_version = "v4.8g-test"
    supported_algorithms = ("classical-ed25519", "ml-dsa", "fn-dsa")

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        prefix = "hsm://shield-v4.8g/"
        if not private_key_reference.startswith(prefix):
            raise ValueError("unexpected private key reference")
        role, ref_algorithm, key_version_text = private_key_reference[len(prefix) :].split("/")
        if ref_algorithm != algorithm:
            raise ValueError("private key algorithm mismatch")
        public_key = _real_public_key(role=role, algorithm=algorithm, key_version=int(key_version_text))
        public_key_bytes = decode_binary_signature_material(public_key, field="public_key")
        return _real_signature(public_key_bytes, algorithm=algorithm, message=message)

    def verify_signature(self, *, algorithm: str, public_key: str, message: bytes, signature: str) -> bool:
        public_key_bytes = decode_binary_signature_material(public_key, field="public_key")
        expected = _real_signature(public_key_bytes, algorithm=algorithm, message=message)
        return hmac.compare_digest(signature, expected)


def _real_public_key(*, role: str, algorithm: str, key_version: int) -> str:
    return encode_binary_signature_material(
        f"shield-v4.8g-real-public-key|{role}|{algorithm}|{key_version}".encode("utf-8"),
        field="public_key",
    )


def _real_signature(public_key_bytes: bytes, *, algorithm: str, message: bytes) -> str:
    digest = hashlib.sha512(b"shield-v4.8g-real-signature|" + algorithm.encode("utf-8") + b"|" + public_key_bytes + b"|" + message).digest()
    return encode_binary_signature_material(digest, field="signature")


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _realize_registry(registry: dict[str, Any]) -> dict[str, Any]:
    realized = copy.deepcopy(registry)
    for key in realized["entries"]:
        if key["key_id"].startswith("test-"):
            key["key_id"] = "prod-" + key["key_id"][len("test-") :]
        key["public_key"] = _real_public_key(role=key["role"], algorithm=key["algorithm"], key_version=key["key_version"])
    return realized


def _key_for(registry: dict[str, Any], *, role: str, algorithm: str, key_version: int) -> dict[str, Any]:
    for key in registry["entries"]:
        if (key["role"], key["algorithm"], key["key_version"]) == (role, algorithm, key_version):
            return key
    raise AssertionError(f"missing key for {role} {algorithm} v{key_version}")


def _private_ref(*, role: str, algorithm: str, key_version: int) -> str:
    return f"hsm://shield-v4.8g/{role}/{algorithm}/{key_version}"


def _resign_bundle_with_real_material(
    bundle: dict[str, Any],
    *,
    role: str,
    registry: dict[str, Any],
    backend: IntegratedRealBackend,
) -> None:
    for entry in bundle["signatures"]:
        key = _key_for(registry, role=role, algorithm=entry["algorithm"], key_version=entry["key_version"])
        entry.update(
            build_signature_entry_with_real_backend(
                algorithm=entry["algorithm"],
                domain_tag=entry["domain_tag"],
                signed_payload_hash=entry["signed_payload_hash"],
                key_id=key["key_id"],
                key_version=entry["key_version"],
                private_key_reference=_private_ref(role=role, algorithm=entry["algorithm"], key_version=entry["key_version"]),
                backend=backend,
            )
        )


def _realize_receipt_and_registry() -> tuple[dict[str, Any], dict[str, Any], str, str, str, IntegratedRealBackend]:
    fixture = _load_fixture()
    receipt = copy.deepcopy(fixture["receipt"])
    registry = _realize_registry(fixture["trusted_key_registry"])
    backend = IntegratedRealBackend()
    for component in receipt["component_verdicts"]:
        _resign_bundle_with_real_material(
            component["signature_bundle"],
            role=COMPONENT_ROLES[component["component_id"]],
            registry=registry,
            backend=backend,
        )
    unsigned_receipt = {
        key: receipt[key]
        for key in receipt
        if key not in {"receipt_hash", "signed_payload_hash", "signature_bundle", "verification_summary"}
    }
    receipt["receipt_hash"] = build_receipt_hash(unsigned_receipt)
    receipt["signed_payload_hash"] = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=unsigned_receipt)
    for entry in receipt["signature_bundle"]["signatures"]:
        entry["signed_payload_hash"] = receipt["signed_payload_hash"]
    _resign_bundle_with_real_material(receipt["signature_bundle"], role=ORCHESTRATOR_ROLE, registry=registry, backend=backend)
    return receipt, registry, fixture["expected_context_hash"], fixture["expected_request_id"], fixture["verification_time"], backend


def test_v48g_orchestrator_verifies_real_backend_component_and_receipt_interface_contract() -> None:
    receipt, registry, expected_context_hash, expected_request_id, verification_time, backend = _realize_receipt_and_registry()
    verifier = make_real_crypto_signature_verifier(backend)

    verified_components, component_summaries = verify_component_verdicts(
        receipt["component_verdicts"],
        expected_context_hash=expected_context_hash,
        registry=registry,
        verification_time=verification_time,
        verifier=verifier,
    )
    checked_receipt = validate_receipt_envelope(
        receipt,
        expected_context_hash=expected_context_hash,
        registry=registry,
        verification_time=verification_time,
        verifier=verifier,
    )

    assert receipt["request_id"] == expected_request_id
    assert checked_receipt["final_outcome"] == "ALLOW"
    assert checked_receipt["verification_summary"]["verified_algorithms"] == ["classical-ed25519", "ml-dsa"]
    assert [item["component_id"] for item in verified_components] == ["adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"]
    assert [item["verified_algorithms"] for item in component_summaries] == [["classical-ed25519", "ml-dsa"]] * 5
    assert all(key["public_key"].startswith("b64u:") and not key["key_id"].startswith("test-") for key in registry["entries"])


def test_v48g_orchestrator_real_backend_e2e_rejects_component_splice_without_fallback() -> None:
    receipt, registry, expected_context_hash, _, verification_time, backend = _realize_receipt_and_registry()
    receipt["component_verdicts"][0]["signature_bundle"]["signatures"][1]["signature"] = receipt["component_verdicts"][1]["signature_bundle"]["signatures"][1]["signature"]
    verifier = make_real_crypto_signature_verifier(backend)

    try:
        verify_component_verdicts(
            receipt["component_verdicts"],
            expected_context_hash=expected_context_hash,
            registry=registry,
            verification_time=verification_time,
            verifier=verifier,
        )
    except ValueError as exc:
        assert "signature verification failed" in str(exc)
    else:  # pragma: no cover - explicit failure path for audit clarity.
        raise AssertionError("spliced real ML-DSA component signature must fail closed")
