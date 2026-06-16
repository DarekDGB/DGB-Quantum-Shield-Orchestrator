from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from enum import Enum
from typing import Any

import pytest

from shield_orchestrator.bridges.adn_bridge import ADNBridge
from shield_orchestrator.bridges.dqsn_bridge import DQSNBridge
from shield_orchestrator.bridges.guardian_wallet_bridge import GuardianWalletBridge
from shield_orchestrator.bridges.qwg_bridge import QWGBridge
from shield_orchestrator.bridges.sentinel_bridge import SentinelBridge
import shield_orchestrator.bridges.component_verdicts as verdicts
import shield_orchestrator.v3.orchestrate as orchestrate_module
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, TraceEntry
from shield_orchestrator.v3.contracts.reason_ids import ReasonId
from shield_orchestrator.v3.orchestrate import orchestrate

CTX = "a" * 64
REQ = "req-coverage-lock"


def _request(payload: dict[str, Any] | None = None) -> OrchestratorV3Request:
    return OrchestratorV3Request(
        contract_version=3,
        wallet_id="wallet-1",
        action="SEND",
        nonce="nonce-1",
        ttl_seconds=60,
        payload=payload or {"request_id": REQ, "context_hash": CTX},
    )


def _component_payload(component_id: str) -> dict[str, Any]:
    if component_id == "sentinel_ai":
        return {"telemetry": {"status": "green"}}
    if component_id == "dqsn":
        return {"signals": [{"status": "ok"}], "constraints": {"strict": True}}
    if component_id == "adn":
        return {"events": [{"status": "normal"}]}
    if component_id == "guardian_wallet":
        return {
            "mode": "tx",
            "wallet_ctx": {"balance": 1},
            "tx_ctx": {"amount": 1},
            "auth_ctx": {"qid": True},
            "extra_signals": {"trusted": True},
        }
    if component_id == "qwg":
        return {
            "risk_context": {
                "sentinel_level": "normal",
                "dqs_network_score": 0.1,
                "adn_level": "normal",
                "wallet_balance": 100.0,
                "tx_amount": 1.0,
                "address_age_days": 10,
                "behaviour_score": 1.0,
                "device_id": "device-1",
                "trusted_device": True,
            }
        }
    raise AssertionError(component_id)


@pytest.mark.parametrize(
    "bridge_cls, component_id",
    [
        (SentinelBridge, "sentinel_ai"),
        (DQSNBridge, "dqsn"),
        (ADNBridge, "adn"),
        (GuardianWalletBridge, "guardian_wallet"),
        (QWGBridge, "qwg"),
    ],
)
def test_component_bridge_engine_exception_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    bridge_cls: type[Any],
    component_id: str,
) -> None:
    def boom(self: Any, payload: Any, *, request_id: str) -> dict[str, Any]:
        raise RuntimeError("engine offline")

    monkeypatch.setattr(bridge_cls, "_evaluate_engine", boom)

    req = _request(
        {
            "request_id": REQ,
            "context_hash": CTX,
            "component_inputs": {component_id: _component_payload(component_id)},
        }
    )

    result = bridge_cls().evaluate_v3(req)

    assert result.verdict["decision"] == "ERROR"
    assert result.verdict["metadata"]["bridge_error"] == "component_engine_unavailable_or_failed"
    assert result.trace.status == "ERROR"


def test_adn_engine_request_and_real_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class FakeADNv3:
        def evaluate(self, req: dict[str, Any]) -> dict[str, Any]:
            seen.update(req)
            return {"decision": "ALLOW", "component": req["component"], "request_id": req["request_id"]}

    monkeypatch.setitem(sys.modules, "adn_v3", types.SimpleNamespace(ADNv3=FakeADNv3))
    bridge = ADNBridge()

    assert bridge._engine_request({"contract_version": 99, "events": ["kept"]}, request_id=REQ) == {
        "contract_version": 3,
        "events": ["kept"],
        "component": "adn",
        "request_id": REQ,
    }
    assert bridge._engine_request({"events": ["event"], "ignored": object()}, request_id=REQ) == {
        "contract_version": 3,
        "component": "adn",
        "request_id": REQ,
        "events": ["event"],
    }

    assert bridge._evaluate_engine({"events": ["event"]}, request_id=REQ)["decision"] == "ALLOW"
    assert seen["component"] == "adn"


def test_dqsn_engine_request_and_real_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_evaluate_v3(req: dict[str, Any]) -> dict[str, Any]:
        seen.update(req)
        return {"decision": "ALLOW", "component": req["component"], "request_id": req["request_id"]}

    package = types.ModuleType("dqsnetwork")
    api = types.ModuleType("dqsnetwork.v3_api")
    api.evaluate_v3 = fake_evaluate_v3  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dqsnetwork", package)
    monkeypatch.setitem(sys.modules, "dqsnetwork.v3_api", api)
    bridge = DQSNBridge()

    assert bridge._engine_request({"contract_version": 99, "signals": ["kept"]}, request_id=REQ) == {
        "contract_version": 3,
        "signals": ["kept"],
        "component": "dqsn",
        "request_id": REQ,
    }
    assert bridge._engine_request({"signals": ["sig"], "constraints": "bad"}, request_id=REQ) == {
        "contract_version": 3,
        "component": "dqsn",
        "request_id": REQ,
        "signals": ["sig"],
        "constraints": {},
    }

    assert bridge._evaluate_engine({"signals": ["sig"]}, request_id=REQ)["decision"] == "ALLOW"
    assert seen["component"] == "dqsn"


def test_guardian_wallet_engine_request_and_real_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class FakeGuardianWalletV3:
        def evaluate(self, req: dict[str, Any]) -> dict[str, Any]:
            seen.update(req)
            return {"outcome": "allow", "component": req["component"], "request_id": req["request_id"]}

    monkeypatch.setitem(
        sys.modules,
        "dgb_wallet_guardian",
        types.SimpleNamespace(GuardianWalletV3=FakeGuardianWalletV3),
    )
    bridge = GuardianWalletBridge()

    assert bridge._engine_request({"contract_version": 99, "mode": "kept"}, request_id=REQ) == {
        "contract_version": 3,
        "mode": "kept",
        "component": "guardian_wallet",
        "request_id": REQ,
    }
    assert bridge._engine_request(
        {
            "mode": "recover",
            "wallet_ctx": "bad",
            "tx_ctx": {"amount": 1},
            "auth_ctx": "bad",
            "extra_signals": {"trusted": True},
        },
        request_id=REQ,
    ) == {
        "contract_version": 3,
        "component": "guardian_wallet",
        "request_id": REQ,
        "mode": "recover",
        "wallet_ctx": {},
        "tx_ctx": {"amount": 1},
        "auth_ctx": {},
        "extra_signals": {"trusted": True},
    }

    assert bridge._evaluate_engine({"wallet_ctx": {}}, request_id=REQ)["outcome"] == "allow"
    assert seen["component"] == "guardian_wallet"


def test_qwg_engine_request_risk_level_and_real_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class FakeRiskLevel(str):
        pass

    class FakeRiskContext:
        def __init__(self, **kwargs: Any) -> None:
            seen.update(kwargs)

    class FakeDecisionEngine:
        def evaluate_transaction_v3(self, ctx: FakeRiskContext) -> dict[str, Any]:
            return {"decision": "ALLOW", "component": "qwg", "request_id": REQ}

    monkeypatch.setitem(
        sys.modules,
        "qwg",
        types.SimpleNamespace(
            DecisionEngine=FakeDecisionEngine,
            RiskContext=FakeRiskContext,
            RiskLevel=FakeRiskLevel,
        ),
    )

    bridge = QWGBridge()
    response = bridge._evaluate_engine(_component_payload("qwg"), request_id=REQ)

    assert response["decision"] == "ALLOW"
    assert seen["sentinel_level"] == "normal"
    assert seen["trusted_device"] is True

    seen.clear()
    assert bridge._evaluate_engine({"risk_context": "bad"}, request_id=REQ)["decision"] == "ALLOW"
    assert seen["sentinel_level"] == "normal"
    assert seen["trusted_device"] is True

    assert bridge._risk_level(" NORMAL ", FakeRiskLevel) == "normal"
    assert bridge._risk_level(123, FakeRiskLevel) == "123"


def test_sentinel_engine_request_and_real_import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class FakeThresholds:
        pass

    class FakeSentinelV3:
        def __init__(self, *, thresholds: FakeThresholds) -> None:
            self.thresholds = thresholds

        def evaluate(self, req: dict[str, Any]) -> dict[str, Any]:
            seen.update(req)
            return {"decision": "ALLOW", "component": req["component"], "request_id": req["request_id"]}

    config = types.ModuleType("sentinel_ai_v2.config")
    config.CircuitBreakerThresholds = FakeThresholds  # type: ignore[attr-defined]
    v3 = types.ModuleType("sentinel_ai_v2.v3")
    v3.SentinelV3 = FakeSentinelV3  # type: ignore[attr-defined]
    package = types.ModuleType("sentinel_ai_v2")
    monkeypatch.setitem(sys.modules, "sentinel_ai_v2", package)
    monkeypatch.setitem(sys.modules, "sentinel_ai_v2.config", config)
    monkeypatch.setitem(sys.modules, "sentinel_ai_v2.v3", v3)
    bridge = SentinelBridge()

    assert bridge._engine_request({"contract_version": 99, "telemetry": {"kept": True}}, request_id=REQ) == {
        "contract_version": 3,
        "telemetry": {"kept": True},
        "component": "sentinel",
        "request_id": REQ,
    }
    assert bridge._engine_request({"telemetry": {"ok": True}, "constraints": "bad"}, request_id=REQ) == {
        "contract_version": 3,
        "component": "sentinel",
        "request_id": REQ,
        "telemetry": {"ok": True},
        "constraints": {},
    }

    assert bridge._evaluate_engine({"telemetry": {"ok": True}}, request_id=REQ)["decision"] == "ALLOW"
    assert seen["component"] == "sentinel"


def test_component_input_accepts_top_level_alias() -> None:
    req = _request({"sentinel": {"telemetry": {"ok": True}}})

    assert verdicts.component_input(req, "sentinel_ai") == {"telemetry": {"ok": True}}


def test_non_object_engine_response_fails_closed() -> None:
    result = verdicts.build_component_result_from_response(
        component_id="qwg",
        request_id=REQ,
        context_hash=CTX,
        engine_response=["not", "an", "object"],
    )

    assert result.verdict["decision"] == "ERROR"
    assert result.verdict["metadata"]["bridge_error"] == "component_engine_returned_non_object"


def test_json_like_enum_dataclass_tuple_and_decision_branches() -> None:
    class Decision(Enum):
        WARN = "warn"

    @dataclass(frozen=True)
    class EngineResponse:
        decision: Decision
        component: str
        context_hash: str
        reason_codes: tuple[str, ...]

    result = verdicts.build_component_result_from_response(
        component_id="qwg",
        request_id=REQ,
        context_hash=CTX,
        engine_response=EngineResponse(
            decision=Decision.WARN,
            component="qwg",
            context_hash="b" * 64,
            reason_codes=("internal_warn",),
        ),
    )

    assert result.verdict["decision"] == "ESCALATE"
    assert result.verdict["metadata"]["engine_reason_codes"] == ["internal_warn"]
    assert verdicts._normalized_decision({"decision": Decision.WARN}) == "ESCALATE"
    assert verdicts._normalized_decision({"decision": "mystery"}) == "ERROR"
    assert verdicts._json_like((Decision.WARN, {"nested": (1, 2)})) == ["warn", {"nested": [1, 2]}]


def test_component_helper_validation_error_branches() -> None:
    assert verdicts._safe_engine_context_hash("z" * 64) is None
    assert verdicts._safe_engine_context_hash(123) is None
    assert verdicts._safe_str_list("not-list") == []

    with pytest.raises(ValueError, match="must not be empty"):
        verdicts._require_supported([], allowed=("A",), field="field")
    with pytest.raises(ValueError, match="contains invalid value"):
        verdicts._require_supported([""], allowed=("A",), field="field")
    with pytest.raises(ValueError, match="contains unknown value"):
        verdicts._require_supported(["B"], allowed=("A",), field="field")
    with pytest.raises(ValueError, match="contains duplicate value"):
        verdicts._require_supported(["A", "A"], allowed=("A",), field="field")

    with pytest.raises(ValueError, match="64-character"):
        verdicts._require_lower_sha256("abc", field="hash")
    with pytest.raises(ValueError, match="sha256 hex"):
        verdicts._require_lower_sha256("z" * 64, field="hash")
    with pytest.raises(ValueError, match="lowercase"):
        verdicts._require_lower_sha256("A" * 64, field="hash")


def test_orchestrate_invalid_context_hash_maps_to_invalid_request() -> None:
    resp = orchestrate(_request({"request_id": REQ, "context_hash": "A" * 64}))

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.INVALID_REQUEST.value,)


def test_orchestrate_bridge_type_error_maps_to_hashing_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self: Any, request: OrchestratorV3Request) -> Any:
        raise TypeError("bridge hashing failed")

    monkeypatch.setattr(orchestrate_module.SentinelBridge, "evaluate_v3", boom)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.HASHING_FAILED.value,)


def test_normalize_legacy_trace_without_verdict_and_unknown_bridge() -> None:
    legacy_trace = TraceEntry(stage="legacy", component="qwg", status="OK")

    result = orchestrate_module._normalize_bridge_result(
        legacy_trace,
        bridge_component="qwg",
        request_id=REQ,
        context_hash=CTX,
    )

    assert result.verdict["decision"] == "ERROR"
    assert result.verdict["metadata"]["bridge_error"] == "bridge_returned_trace_without_verdict"

    with pytest.raises(ValueError, match="ComponentBridgeResult"):
        orchestrate_module._normalize_bridge_result(
            legacy_trace,
            bridge_component="unknown",
            request_id=REQ,
            context_hash=CTX,
        )


def test_response_from_receipt_maps_human_review_to_escalate() -> None:
    outcome, reason_ids = orchestrate_module._response_from_receipt(
        {
            "final_outcome": "HUMAN_REVIEW_REQUIRED",
            "dominant_reason_ids": ["ORCH_ESCALATE_HUMAN_REVIEW_REQUIRED"],
        }
    )

    assert outcome == "ESCALATE"
    assert reason_ids == ("ORCH_ESCALATE_HUMAN_REVIEW_REQUIRED",)
