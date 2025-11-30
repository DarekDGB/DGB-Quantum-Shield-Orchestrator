# src/shield_orchestrator/bridges/sentinel_bridge.py

from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayerBridge, LayerResult
from ..context import ShieldContext


class SentinelBridge(BaseLayerBridge):
    name = "sentinel"

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        base = float(event.get("sentinel_risk", 0.10))
        score = max(0.0, min(1.0, base))
        return LayerResult(self.name, score, {"source": "sentinel", "raw": base})
