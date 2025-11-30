from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class ADNBridge(ShieldLayer):
    """
    Bridge for ADN v2.

    Uses 'node_stress' (0–1) to simulate local node stress / lockdown risk.
    """

    def __init__(self) -> None:
        super().__init__(name="adn_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        payload: Dict[str, Any] = event.payload
        node_stress = float(payload.get("node_stress", 0.0))

        severity = max(0.0, min(node_stress, 1.0))
        level = "LOW"
        if severity > 0.85:
            level = "CRITICAL"
        elif severity > 0.6:
            level = "HIGH"
        elif severity > 0.35:
            level = "ELEVATED"

        return LayerResult(
            layer=self.name,
            severity=severity,
            level=level,
            notes="Simulated ADN local node stress / lockdown tendency.",
            metadata={"node_stress": node_stress},
        )
