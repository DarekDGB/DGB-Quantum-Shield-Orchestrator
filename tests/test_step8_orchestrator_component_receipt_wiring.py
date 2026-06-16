from __future__ import annotations

from typing import Any

import pytest

from shield_orchestrator.bridges.adn_bridge import ADNBridge
from shield_orchestrator.bridges.dqsn_bridge import DQSNBridge
from shield_orchestrator.bridges.guardian_wallet_bridge import GuardianWalletBridge
from shield_orchestrator.bridges.qwg_bridge import QWGBridge
from shield_orchestrator.bridges.sentinel_bridge import SentinelBridge
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.contracts.v3_2_receipt import validate_receipt
from shield_orchestrator.v3.orchestrate import orchestrate

CTX = "a" * 64
REQ = "req-step8-3"


def _request() -> OrchestratorV3Request:
    return OrchestratorV3Request(
        contract_version=3,
        wallet_id="wallet-1",
        action="SEND",
        nonce="nonce-1",
        ttl_seconds=60,
        payload={
            "request_id": REQ,
            "context_hash": CTX,
            "component_inputs": {
                "sentinel_ai": {"telemetry": {}},
                "dqsn": {"signals": []},
                "adn": {"events": []},
                "guardian_wallet": {"wallet_ctx": {}, "tx_ctx": {}, "extra_signals": {}},
                "qwg": {"risk_context": {}},
            },
        },
    )


def _response(component: str, outcome: str, *, authority: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "contract_version": 3,
        "component": component,
        "request_id": REQ,
        "context_hash": "b" * 64,
        "risk": {"score": 0.0, "tier": "LOW"},
        "reason_codes": [f"{component.upper()}_INTERNAL"],
        "evidence": {},
        "meta": {"fail_closed": True},
    }
    if component == "guardian_wallet":
        body["outcome"] = outcome.lower()
    else:
        body["decision"] = outcome
    if authority:
        body["final_approval"] = True
    return body


def _patch_all(monkeypatch: pytest.MonkeyPatch, *, qwg_outcome: str = "ALLOW", authority: bool = False) -> None:
    monkeypatch.setattr(
        SentinelBridge,
        "_evaluate_engine",
        lambda self, payload, *, request_id: _response("sentinel", "ALLOW"),
    )
    monkeypatch.setattr(
        DQSNBridge,
        "_evaluate_engine",
        lambda self, payload, *, request_id: _response("dqsn", "ALLOW"),
    )
    monkeypatch.setattr(
        ADNBridge,
        "_evaluate_engine",
        lambda self, payload, *, request_id: _response("adn", "ALLOW"),
    )
    monkeypatch.setattr(
        GuardianWalletBridge,
        "_evaluate_engine",
        lambda self, payload, *, request_id: _response("guardian_wallet", "allow"),
    )
    monkeypatch.setattr(
        QWGBridge,
        "_evaluate_engine",
        lambda self, payload, *, request_id: _response("qwg", qwg_outcome, authority=authority),
    )


def test_step8_3_real_component_outputs_build_v3_2_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_all(monkeypatch)

    resp = orchestrate(_request())

    assert resp.outcome == "ALLOW"
    assert resp.reason_ids == ("ORCH_OK_ALL_COMPONENTS_ALLOW",)
    assert resp.receipt is not None
    assert validate_receipt(resp.receipt, expected_context_hash=CTX) == resp.receipt
    assert [item["component_id"] for item in resp.receipt["component_verdicts"]] == [
        "adn",
        "dqsn",
        "guardian_wallet",
        "qwg",
        "sentinel_ai",
    ]
    assert {item["decision"] for item in resp.receipt["component_verdicts"]} == {"ALLOW"}
    assert all("phase3_bridge_stub" not in str(entry.notes) for entry in resp.trace)


def test_step8_3_component_deny_dominates_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_all(monkeypatch, qwg_outcome="BLOCK")

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == ("ORCH_DENY_DOMINATES",)
    assert resp.receipt is not None
    qwg = next(item for item in resp.receipt["component_verdicts"] if item["component_id"] == "qwg")
    assert qwg["decision"] == "DENY"
    assert qwg["reason_ids"] == ["QWG_DENY_KEY_RISK"]


def test_step8_3_component_internal_reason_codes_are_translated(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_all(monkeypatch)

    resp = orchestrate(_request())

    assert resp.receipt is not None
    all_reason_ids = [
        reason_id
        for component in resp.receipt["component_verdicts"]
        for reason_id in component["reason_ids"]
    ]
    assert "QWG_INTERNAL" not in all_reason_ids
    assert "QWG_OK_POSTURE_ALLOW" in all_reason_ids
    assert "SNTL_OK_TELEMETRY_ALLOW" in all_reason_ids


def test_step8_3_component_authority_bypass_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_all(monkeypatch, authority=True)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == ("ORCH_ERROR_INVALID_COMPONENT_VERDICT",)
    assert resp.receipt is not None
    qwg = next(item for item in resp.receipt["component_verdicts"] if item["component_id"] == "qwg")
    assert qwg["decision"] == "ERROR"
    assert qwg["reason_ids"] == ["QWG_ERROR_INVALID_VERDICT"]


def test_step8_3_missing_component_input_fails_closed_not_allow_stub() -> None:
    req = OrchestratorV3Request(
        contract_version=3,
        wallet_id="wallet-1",
        action="SEND",
        nonce="nonce-1",
        ttl_seconds=60,
        payload={"request_id": REQ, "context_hash": CTX},
    )

    resp = orchestrate(req)

    assert resp.outcome == "DENY"
    assert resp.reason_ids == ("ORCH_ERROR_INVALID_COMPONENT_VERDICT",)
    assert resp.receipt is not None
    assert {item["decision"] for item in resp.receipt["component_verdicts"]} == {"ERROR"}
    assert all(item["metadata"]["bridge_error"] == "missing_component_input" for item in resp.receipt["component_verdicts"])
