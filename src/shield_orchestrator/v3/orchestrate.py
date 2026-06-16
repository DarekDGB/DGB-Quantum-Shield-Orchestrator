from __future__ import annotations

from dataclasses import asdict
from typing import Any

from shield_orchestrator.bridges.adaptive_core_bridge import AdaptiveCoreBridge
from shield_orchestrator.bridges.adn_bridge import ADNBridge
from shield_orchestrator.bridges.component_verdicts import (
    ComponentBridgeResult,
    error_component_result,
    receipt_context_hash,
    receipt_request_id,
)
from shield_orchestrator.bridges.dqsn_bridge import DQSNBridge
from shield_orchestrator.bridges.guardian_wallet_bridge import GuardianWalletBridge
from shield_orchestrator.bridges.qwg_bridge import QWGBridge
from shield_orchestrator.bridges.sentinel_bridge import SentinelBridge
from shield_orchestrator.errors import TVAError

from .context_hash import compute_context_hash
from .contracts.envelope import OrchestratorV3Request, OrchestratorV3Response, TraceEntry
from .contracts.reason_ids import ReasonId
from .contracts.v3_2_receipt import build_receipt
from .contracts.version import CONTRACT_VERSION


def orchestrate(request: OrchestratorV3Request) -> OrchestratorV3Response:
    """
    Orchestrator v3 public entrypoint.

    Step 8.3 behavior:
    - strict request validation + contract_version gate
    - deterministic bridge calls in fixed order:
        Sentinel -> DQSN -> ADN -> Guardian Wallet -> QWG
    - every bridge must return a Shield v3.2 component verdict
    - component verdicts are assembled into the v3.2 receipt AdamantineOS consumes
    - DENY / ERROR dominates, ESCALATE maps to human review
    - missing component input or unavailable component package yields ERROR verdict,
      not an all-ALLOW stub
    - Adaptive Core remains a read-only sink and must not affect outcome
    """
    try:
        _validate_request(request)
        try:
            request_id = receipt_request_id(request)
            context_hash = receipt_context_hash(request)
        except TypeError as e:
            raise TVAError(ReasonId.HASHING_FAILED.value, "hashing failed") from e
        except ValueError as e:
            raise TVAError(ReasonId.INVALID_REQUEST.value, "invalid request context") from e

        trace: list[TraceEntry] = [
            TraceEntry(stage="input_validation", component="orchestrator", status="OK")
        ]
        component_verdicts: list[dict[str, Any]] = []

        try:
            for bridge in (
                SentinelBridge(),
                DQSNBridge(),
                ADNBridge(),
                GuardianWalletBridge(),
                QWGBridge(),
            ):
                result = bridge.evaluate_v3(request)
                normalized = _normalize_bridge_result(
                    result,
                    bridge_component=str(getattr(bridge, "COMPONENT", "unknown")),
                    request_id=request_id,
                    context_hash=context_hash,
                )
                trace.append(normalized.trace)
                component_verdicts.append(normalized.verdict)
        except TypeError as e:
            raise TVAError(ReasonId.HASHING_FAILED.value, "hashing failed") from e
        except Exception as e:
            raise TVAError(ReasonId.COMPONENT_ERROR.value, "component error") from e

        receipt = build_receipt(
            request_id=request_id,
            context_hash=context_hash,
            component_verdicts=component_verdicts,
        )
        outcome, reason_ids = _response_from_receipt(receipt)

        trace.append(
            TraceEntry(
                stage="receipt_synthesis",
                component="shield_orchestrator",
                status="OK" if outcome != "DENY" else "DENY",
                reason_ids=reason_ids,
                component_context_hash=str(receipt["receipt_hash"]),
                notes="v3_2_receipt_built_from_component_verdicts",
            )
        )

        # Adaptive Core sink (must not influence outcome)
        try:
            sink_entry = AdaptiveCoreBridge().report_v3(
                request, outcome=outcome, reason_ids=reason_ids
            )
        except Exception:
            sink_entry = TraceEntry(
                stage="adaptive_core",
                component="adaptive_core",
                status="ERROR",
                reason_ids=(ReasonId.COMPONENT_ERROR.value,),
                notes="phase3_sink_failed",
            )

        full_trace = tuple(trace + [sink_entry])

        try:
            compute_context_hash(
                {
                    "receipt_hash": receipt["receipt_hash"],
                    "outcome": outcome,
                    "reason_ids": list(reason_ids),
                    "trace": [asdict(t) for t in full_trace],
                }
            )
        except TypeError as e:
            raise TVAError(ReasonId.HASHING_FAILED.value, "hashing failed") from e

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome=outcome,
            context_hash=context_hash,
            reason_ids=reason_ids,
            trace=full_trace,
            receipt=receipt,
        )

    except TVAError as e:
        # Build a deterministic DENY response without ever re-hashing the payload.
        trace = (
            TraceEntry(
                stage="fail_closed",
                component="orchestrator",
                status="DENY",
                reason_ids=(e.reason_id,),
                notes="tva_error",
            ),
        )

        # Always omit payload in failure hashing to avoid recursive serialization errors.
        hash_material = {
            "request": _request_for_hash(request, include_payload=False),
            "outcome": "DENY",
            "reason_ids": [e.reason_id],
            "trace": [asdict(t) for t in trace],
        }
        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome="DENY",
            context_hash=context_hash,
            reason_ids=(e.reason_id,),
            trace=trace,
        )

    except Exception:
        trace = (
            TraceEntry(
                stage="internal_error",
                component="orchestrator",
                status="DENY",
                reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            ),
        )

        hash_material = {
            "request": _request_for_hash(request, include_payload=False),
            "outcome": "DENY",
            "reason_ids": [ReasonId.INTERNAL_ERROR.value],
            "trace": [asdict(t) for t in trace],
        }
        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome="DENY",
            context_hash=context_hash,
            reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            trace=trace,
        )


def _normalize_bridge_result(
    result: Any,
    *,
    bridge_component: str,
    request_id: str,
    context_hash: str,
) -> ComponentBridgeResult:
    if isinstance(result, ComponentBridgeResult):
        return result
    if isinstance(result, TraceEntry):
        # Legacy or monkeypatched bridge returned a trace but no component verdict.
        # That is no longer sufficient for receipt synthesis, so convert to an
        # explicit ERROR component verdict instead of silently accepting OK.
        if bridge_component in {"adn", "dqsn", "guardian_wallet", "qwg", "sentinel_ai"}:
            return error_component_result(
                component_id=bridge_component,
                request_id=request_id,
                context_hash=context_hash,
                note="bridge_returned_trace_without_verdict",
            )
    raise ValueError("component bridge must return ComponentBridgeResult")


def _response_from_receipt(receipt: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    final_outcome = str(receipt["final_outcome"])
    reason_ids = tuple(str(item) for item in receipt["dominant_reason_ids"])
    if final_outcome == "ALLOW":
        return "ALLOW", reason_ids
    if final_outcome == "HUMAN_REVIEW_REQUIRED":
        return "ESCALATE", reason_ids
    return "DENY", reason_ids


def _request_for_hash(request: OrchestratorV3Request, *, include_payload: bool) -> dict[str, Any]:
    """
    Deterministic request material for hashing.

    include_payload=True is the normal path.
    include_payload=False is used for fail-closed responses to avoid
    non-serializable payload causing recursive hashing failures.
    """
    d = asdict(request)
    if not include_payload:
        d = dict(d)
        d["payload"] = None
    return d


def _validate_request(request: OrchestratorV3Request) -> None:
    if request.contract_version != CONTRACT_VERSION:
        raise TVAError(ReasonId.INVALID_CONTRACT_VERSION.value, "contract_version must be 3")

    if not isinstance(request.wallet_id, str) or not request.wallet_id:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "wallet_id must be a non-empty string")

    if not isinstance(request.action, str) or not request.action:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "action must be a non-empty string")

    if not isinstance(request.nonce, str) or not request.nonce:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "nonce must be a non-empty string")

    if not isinstance(request.ttl_seconds, int) or request.ttl_seconds <= 0:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "ttl_seconds must be a positive integer")
