from __future__ import annotations

from shield_orchestrator.config import ShieldConfig
from shield_orchestrator.context import ShieldContext
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, OrchestratorV3Response, TraceEntry
from shield_orchestrator.v3.contracts.reason_ids import ReasonId
from shield_orchestrator.v3.orchestrate import orchestrate
import shield_orchestrator.v3.orchestrate as orchestrate_module


def _request() -> OrchestratorV3Request:
    return OrchestratorV3Request(
        contract_version=3,
        wallet_id="wallet-1",
        action="SEND",
        nonce="nonce-1",
        ttl_seconds=60,
        payload={"amount": 1},
    )


def test_context_log_is_silent_when_logging_disabled(capsys) -> None:
    cfg = ShieldConfig()
    cfg.enable_logging = False
    ctx = ShieldContext(cfg)

    ctx.log("hidden")

    assert capsys.readouterr().out == ""


def test_response_deny_factory_sets_contract_locked_fields() -> None:
    trace = (
        TraceEntry(
            stage="fail_closed",
            component="orchestrator",
            status="DENY",
            reason_ids=(ReasonId.INVALID_REQUEST.value,),
        ),
    )

    resp = OrchestratorV3Response.deny(
        context_hash="abc123",
        reason_ids=(ReasonId.INVALID_REQUEST.value,),
        trace=trace,
    )

    assert resp.contract_version == 3
    assert resp.context_hash == "abc123"
    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.INVALID_REQUEST.value,)
    assert resp.trace == trace


def test_component_exception_maps_to_component_error(monkeypatch) -> None:
    def boom(self, request):
        raise RuntimeError("component exploded")

    monkeypatch.setattr(orchestrate_module.SentinelBridge, "evaluate_v3", boom)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.COMPONENT_ERROR.value,)
    assert resp.trace[0].stage == "fail_closed"


def test_adaptive_core_sink_failure_does_not_change_outcome(monkeypatch) -> None:
    def boom(self, request, *, outcome, reason_ids):
        raise RuntimeError("sink unavailable")

    monkeypatch.setattr(orchestrate_module.AdaptiveCoreBridge, "report_v3", boom)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.DENY_BY_POLICY.value,)
    assert resp.trace[-1].stage == "adaptive_core"
    assert resp.trace[-1].status == "ERROR"
    assert resp.trace[-1].reason_ids == (ReasonId.COMPONENT_ERROR.value,)
    assert resp.trace[-1].notes == "phase3_sink_failed"


def test_final_context_hash_type_error_maps_to_hashing_failed(monkeypatch) -> None:
    calls = {"count": 0}

    def fail_final_hash_once(material):
        calls["count"] += 1
        if calls["count"] == 1:
            raise TypeError("final hash failed")
        return "0" * 64

    monkeypatch.setattr(orchestrate_module, "compute_context_hash", fail_final_hash_once)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.HASHING_FAILED.value,)
    assert resp.trace[0].stage == "fail_closed"


def test_unexpected_internal_error_fails_closed(monkeypatch) -> None:
    def invalid_validator(request):
        raise ValueError("unexpected validator defect")

    monkeypatch.setattr(orchestrate_module, "_validate_request", invalid_validator)

    resp = orchestrate(_request())

    assert resp.outcome == "DENY"
    assert resp.reason_ids == (ReasonId.INTERNAL_ERROR.value,)
    assert resp.trace[0].stage == "internal_error"
    assert resp.trace[0].status == "DENY"
