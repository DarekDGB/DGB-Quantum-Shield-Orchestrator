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


class ADNBridge(BaseLayer):
    """ADN bridge for Shield v3.2 receipt synthesis."""

    COMPONENT = "adn"

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

    def _evaluate_engine(self, payload: Mapping[str, Any], *, request_id: str) -> Mapping[str, Any]:
        from adn_v3 import ADNv3

        return ADNv3().evaluate(self._engine_request(payload, request_id=request_id))

    def _engine_request(self, payload: Mapping[str, Any], *, request_id: str) -> dict[str, Any]:
        if "contract_version" in payload:
            req = dict(payload)
        else:
            events = payload.get("events", [])
            req = {
                "contract_version": 3,
                "component": self.COMPONENT,
                "request_id": request_id,
                "events": list(events) if isinstance(events, list) else [],
            }
        req["contract_version"] = 3
        req["component"] = self.COMPONENT
        req["request_id"] = request_id
        return req
