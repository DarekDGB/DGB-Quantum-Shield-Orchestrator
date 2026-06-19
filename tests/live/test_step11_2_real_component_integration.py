from __future__ import annotations

import os
from typing import Any, Mapping

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("ADAMANTINEOS_LIVE_SHIELD_INTEGRATION") != "1",
    reason="requires all Shield component packages and AdamantineOS to be co-installed",
)

NOW = 1_706_990_400
REQUEST_ID = "step11-2-live-req"


def _symbols() -> dict[str, Any]:
    # Import inside the live test so normal package CI can collect this module
    # without requiring the five component repos or AdamantineOS to be installed.
    from adamantine.v1.contracts.policy_pack import PolicyPack
    from adamantine.v1.contracts.reason_ids import ReasonId
    from adamantine.v1.contracts.shield import ExternalReasonMap, ExternalReasonMapEntry
    from adamantine.v1.enforcement.nonce_store import InMemoryNonceStore
    from adamantine.v1.eqc.context_hash import compute_context_hash
    from adamantine.v1.execution.executor import RecordingExecutor
    from adamantine.v1.execution.orchestrator_v2 import orchestrate_execution_v2
    from adamantine.v1.integrations.qid_adapter import compute_qid_shape_a_proof_hash
    from adamantine.v1.integrations.shield_orchestrator_receipt_verifier import (
        ShieldReceiptVerificationState,
        verify_shield_orchestrator_receipt,
    )
    from adamantine.v1.policy.risk_policy import RiskPolicy, ShieldRuntimeBoundary
    from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
    from shield_orchestrator.v3.orchestrate import orchestrate

    # These imports intentionally prove the workflow co-installed the real engines.
    pytest.importorskip("sentinel_ai_v2.v3")
    pytest.importorskip("adn_v3")
    pytest.importorskip("dqsnetwork.v3_api")
    pytest.importorskip("dgb_wallet_guardian")
    pytest.importorskip("qwg")

    return {
        "ExternalReasonMap": ExternalReasonMap,
        "ExternalReasonMapEntry": ExternalReasonMapEntry,
        "InMemoryNonceStore": InMemoryNonceStore,
        "OrchestratorV3Request": OrchestratorV3Request,
        "PolicyPack": PolicyPack,
        "ReasonId": ReasonId,
        "RecordingExecutor": RecordingExecutor,
        "RiskPolicy": RiskPolicy,
        "ShieldReceiptVerificationState": ShieldReceiptVerificationState,
        "ShieldRuntimeBoundary": ShieldRuntimeBoundary,
        "compute_context_hash": compute_context_hash,
        "compute_qid_shape_a_proof_hash": compute_qid_shape_a_proof_hash,
        "orchestrate": orchestrate,
        "orchestrate_execution_v2": orchestrate_execution_v2,
        "verify_shield_orchestrator_receipt": verify_shield_orchestrator_receipt,
    }


def _context_hash(symbols: Mapping[str, Any]) -> str:
    return symbols["compute_context_hash"](
        wallet_id="w1",
        action="send",
        fields={"asset": "DGB", "amount": "1", "ui_confirmed": "true"},
    )


def _component_inputs(*, deny: bool) -> dict[str, Any]:
    qwg_context = {
        "sentinel_level": "critical" if deny else "normal",
        "dqs_network_score": 0.95 if deny else 0.0,
        "adn_level": "normal",
        "wallet_balance": 100.0,
        "tx_amount": 95.0 if deny else 1.0,
        "address_age_days": 1 if deny else 100,
        "behaviour_score": 5.0 if deny else 1.0,
        "trusted_device": False if deny else True,
    }
    return {
        "sentinel_ai": {
            "telemetry": {
                "entropy": {"score": 0.0, "drop": 0.0},
                "mempool": {"score": 0.0, "anomaly": 0.0},
                "reorg": {"score": 0.0, "depth": 0},
            }
        },
        "dqsn": {"signals": []},
        "adn": {"events": []},
        "guardian_wallet": {
            "mode": "qid_auth",
            "auth_ctx": {
                "qid_verified": True,
                "service_id": "svc",
                "callback_url": "https://example.com/callback",
                "nonce": "qid-nonce",
                "address": "DTestAddress",
                "pubkey": "pubkey",
                "binding_verified": True,
                "require": "legacy",
            },
        },
        "qwg": {"risk_context": qwg_context},
    }


def _run_real_shield(symbols: Mapping[str, Any], *, context_hash: str, deny: bool) -> Any:
    request = symbols["OrchestratorV3Request"](
        contract_version=3,
        wallet_id="w1",
        action="send",
        nonce="nonce-deny" if deny else "nonce-allow",
        ttl_seconds=60,
        payload={
            "request_id": REQUEST_ID,
            "context_hash": context_hash,
            "component_inputs": _component_inputs(deny=deny),
        },
    )
    return symbols["orchestrate"](request)


def _assert_real_engine_metadata(receipt: Mapping[str, Any]) -> None:
    verdicts = receipt["component_verdicts"]
    assert {v["component_id"] for v in verdicts} == {
        "adn",
        "dqsn",
        "guardian_wallet",
        "qwg",
        "sentinel_ai",
    }
    for verdict in verdicts:
        metadata = verdict["metadata"]
        assert metadata["bridge_source"] == "real_component_engine"
        assert "bridge_error" not in metadata
        assert isinstance(metadata.get("engine_component"), str)


def _qid_payload(symbols: Mapping[str, Any], *, context_hash: str) -> dict[str, Any]:
    payload = {
        "qid_iface_version": "qid-session-v0",
        "subject": "did:example:123",
        "issued_at": NOW - 10,
        "expires_at": NOW + 10,
        "proof_hash": "placeholder",
        "context_hash": context_hash,
        "device_binding": "device-1",
        "issuer_version": "qid-v0",
    }
    payload["proof_hash"] = symbols["compute_qid_shape_a_proof_hash"](
        qid_iface_version=payload["qid_iface_version"],
        subject=payload["subject"],
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        context_hash=payload["context_hash"],
        device_binding=payload["device_binding"],
        issuer_version=payload["issuer_version"],
    )
    return payload


def _oracle_payload(*, context_hash: str) -> dict[str, Any]:
    return {
        "ac_iface_version": "adaptive_core_oracle_v3",
        "context_hash": context_hash,
        "issued_at": NOW - 5,
        "expires_at": NOW + 5,
        "generated_at": NOW - 1,
        "overall_score": 99,
        "signals": [{"source": "ac_model", "severity": 10, "reason_ids": ["AC_OK"]}],
        "oracle_version": "adaptive-core/3.0.0",
        "external_source_id": "ac-prod-1",
    }


def _policy(symbols: Mapping[str, Any]) -> Any:
    reason_id = symbols["ReasonId"]
    reason_map = symbols["ExternalReasonMap"](
        entries=(
            symbols["ExternalReasonMapEntry"](
                external_id="ok",
                internal_reason_id=reason_id.EVIDENCE_OK.value,
            ),
            symbols["ExternalReasonMapEntry"](
                external_id="AC_OK",
                internal_reason_id=reason_id.EVIDENCE_OK.value,
            ),
            symbols["ExternalReasonMapEntry"](
                external_id="OK",
                internal_reason_id=reason_id.EVIDENCE_OK.value,
            ),
            symbols["ExternalReasonMapEntry"](
                external_id="BLOCK",
                internal_reason_id=reason_id.DENY_POLICY.value,
            ),
        )
    )
    pack = symbols["PolicyPack"](
        min_overall_score=85,
        allowed_external_reason_ids=("ok", "AC_OK", "OK", "BLOCK"),
        external_reason_map=reason_map,
    )
    return symbols["RiskPolicy"](
        min_overall_score=85,
        policy_pack=pack,
        shield_runtime_boundary=symbols["ShieldRuntimeBoundary"].ORCHESTRATOR_RECEIPT_V3_2,
        require_authenticated_external_evidence=True,
    )


def _adamantine_request(
    symbols: Mapping[str, Any],
    *,
    context_hash: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "v": "execution_request_v2",
        "request_id": REQUEST_ID,
        "intent": "authorize",
        "context": {
            "wallet_id": "w1",
            "device_id": "d1",
            "app_id": "app",
            "session_id": "s1",
            "action": "send",
            "fields": {"asset": "DGB", "amount": "1", "ui_confirmed": "true"},
        },
        "authority": {
            "class": "user",
            "scope": {"policy_pack": "default"},
            "proofs": {
                "wsqk": {
                    "wallet_id": "w1",
                    "action": "send",
                    "context_hash": context_hash,
                    "issued_at": NOW,
                    "expires_at": NOW + 60,
                    "nonce": "n1",
                }
            },
        },
        "timebox": {
            "issued_at": "2024-02-03T20:00:00Z",
            "expires_at": "2024-02-03T20:01:00Z",
        },
        "nonce": {"value": "n1", "store": "tva", "mode": "single_use"},
        "payload": {
            "evidence": {
                "qid": _qid_payload(symbols, context_hash=context_hash),
                "oracle": _oracle_payload(context_hash=context_hash),
                "shield": dict(receipt),
            },
            "body": {"ui_confirmed": True},
        },
    }


def _qid_verifier(_payload: Mapping[str, Any]) -> None:
    return None


def _shield_verifier(payload: Mapping[str, Any], expected_context_hash: str) -> None:
    if payload.get("context_hash") != expected_context_hash:
        raise ValueError("shield context mismatch")
    if payload.get("schema_version") != "shield.receipt.v1":
        raise ValueError("shield schema mismatch")


def _oracle_verifier(payload: Mapping[str, Any], expected_context_hash: str) -> None:
    if payload.get("context_hash") != expected_context_hash:
        raise ValueError("oracle context mismatch")
    if payload.get("external_source_id") != "ac-prod-1":
        raise ValueError("oracle signer mismatch")


def test_real_components_produce_allow_receipt_and_final_adamantineos_allow() -> None:
    symbols = _symbols()
    context_hash = _context_hash(symbols)
    shield_response = _run_real_shield(symbols, context_hash=context_hash, deny=False)

    assert shield_response.outcome == "ALLOW"
    assert shield_response.receipt is not None
    assert shield_response.receipt["final_outcome"] == "ALLOW"
    _assert_real_engine_metadata(shield_response.receipt)

    receipt_result = symbols["verify_shield_orchestrator_receipt"](
        shield_response.receipt,
        expected_context_hash=context_hash,
        expected_request_id=REQUEST_ID,
    )
    assert receipt_result.state is symbols["ShieldReceiptVerificationState"].VERIFIED_ALLOW_EVIDENCE_CONTINUE_CHECKS
    assert receipt_result.accepted_as_evidence is True
    assert receipt_result.final_approval is False

    executor = symbols["RecordingExecutor"]()
    response = symbols["orchestrate_execution_v2"](
        payload=_adamantine_request(symbols, context_hash=context_hash, receipt=shield_response.receipt),
        now=NOW,
        executor=executor,
        nonce_store=symbols["InMemoryNonceStore"](),
        policy=_policy(symbols),
        qid_verifier=_qid_verifier,
        shield_receipt_verifier=_shield_verifier,
        oracle_verifier=_oracle_verifier,
    )

    assert response["status"] == "allow"
    assert response["artifacts"]["shield_runtime_boundary"]["verified"] is True
    assert response["artifacts"]["shield_runtime_boundary"]["accepted_as_evidence"] is True
    assert response["artifacts"]["shield_runtime_boundary"]["final_approval"] is False
    assert executor.called is True


def test_real_component_deny_dominates_and_adamantineos_denies() -> None:
    symbols = _symbols()
    context_hash = _context_hash(symbols)
    shield_response = _run_real_shield(symbols, context_hash=context_hash, deny=True)

    assert shield_response.outcome == "DENY"
    assert shield_response.receipt is not None
    assert shield_response.receipt["final_outcome"] == "DENY"
    assert "ORCH_DENY_DOMINATES" in shield_response.receipt["dominant_reason_ids"]
    _assert_real_engine_metadata(shield_response.receipt)
    qwg = next(
        verdict for verdict in shield_response.receipt["component_verdicts"] if verdict["component_id"] == "qwg"
    )
    assert qwg["decision"] == "DENY"

    receipt_result = symbols["verify_shield_orchestrator_receipt"](
        shield_response.receipt,
        expected_context_hash=context_hash,
        expected_request_id=REQUEST_ID,
    )
    assert receipt_result.state is symbols["ShieldReceiptVerificationState"].VERIFIED_DENY_DOMINATES
    assert receipt_result.accepted_as_evidence is True
    assert receipt_result.final_outcome == "DENY"

    executor = symbols["RecordingExecutor"]()
    response = symbols["orchestrate_execution_v2"](
        payload=_adamantine_request(symbols, context_hash=context_hash, receipt=shield_response.receipt),
        now=NOW,
        executor=executor,
        nonce_store=symbols["InMemoryNonceStore"](),
        policy=_policy(symbols),
        qid_verifier=_qid_verifier,
        shield_receipt_verifier=_shield_verifier,
        oracle_verifier=_oracle_verifier,
    )

    assert response["status"] == "deny"
    assert response["decision"]["evidence"]["shield"]["valid"] is False
    assert executor.called is False
