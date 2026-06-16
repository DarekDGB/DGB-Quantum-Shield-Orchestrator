from __future__ import annotations

from typing import Any, Mapping

from .base_layer import BaseLayer
from .component_verdicts import (
    ComponentBridgeResult,
    build_component_result_from_response,
    component_input,
    error_component_result,
    receipt_context_hash,
    receipt_request_id,
)
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request


class QWGBridge(BaseLayer):
    """QWG bridge for Shield v3.2 receipt synthesis."""

    COMPONENT = "qwg"

    def evaluate_v3(self, request: OrchestratorV3Request) -> ComponentBridgeResult:
        request_id = receipt_request_id(request)
        context_hash = receipt_context_hash(request)
        payload = component_input(request, self.COMPONENT)
        if payload is None:
            return error_component_result(
                component_id=self.COMPONENT,
                request_id=request_id,
                context_hash=context_hash,
                note="missing_component_input",
            )
        try:
            response = self._evaluate_engine(payload, request_id=request_id)
        except Exception:
            return error_component_result(
                component_id=self.COMPONENT,
                request_id=request_id,
                context_hash=context_hash,
                note="component_engine_unavailable_or_failed",
            )
        return build_component_result_from_response(
            component_id=self.COMPONENT,
            request_id=request_id,
            context_hash=context_hash,
            engine_response=response,
        )

    def _evaluate_engine(self, payload: Mapping[str, Any], *, request_id: str) -> Any:
        from qwg import DecisionEngine, RiskContext, RiskLevel

        ctx_payload = payload.get("risk_context", payload)
        if not isinstance(ctx_payload, Mapping):
            ctx_payload = {}
        ctx = RiskContext(
            sentinel_level=self._risk_level(ctx_payload.get("sentinel_level", "normal"), RiskLevel),
            dqs_network_score=float(ctx_payload.get("dqs_network_score", 0.0)),
            adn_level=self._risk_level(ctx_payload.get("adn_level", "normal"), RiskLevel),
            wallet_balance=float(ctx_payload.get("wallet_balance", 0.0)),
            tx_amount=float(ctx_payload.get("tx_amount", 0.0)),
            address_age_days=ctx_payload.get("address_age_days"),
            behaviour_score=float(ctx_payload.get("behaviour_score", 1.0)),
            device_id=ctx_payload.get("device_id"),
            trusted_device=bool(ctx_payload.get("trusted_device", True)),
        )
        return DecisionEngine().evaluate_transaction_v3(ctx)

    @staticmethod
    def _risk_level(value: Any, risk_level_cls: Any) -> Any:
        clean = str(value).lower().strip()
        return risk_level_cls(clean)
