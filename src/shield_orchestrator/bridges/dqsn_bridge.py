# src/shield_orchestrator/bridges/dqsn_bridge.py

from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class DQSNBridge(BaseLayerBridge):
    name = "dqsn"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        base = float(event.get("network_risk", 0.15))
        score = max(0.0, min(1.0, base))
        return LayerResult(self.name, score, {"source": "dqsn", "raw": base})
