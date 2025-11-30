from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class DQSNBridge(ShieldLayer):
    """
    Bridge for DQSN v2.

    For now, treats 'network_cluster_risk' from the payload as a 0–1 score.
    """

    def __init__(self) -> None:
        super().__init__(name="dqsn_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        payload: Dict[str, Any] = event.payload
        cluster_risk = float(payload.get("network_cluster_risk", 0.0))

        severity = max(0.0, min(cluster_risk, 1.0))
        level = "LOW"
        if severity > 0.8:
            level = "CRITICAL"
        elif severity > 0.6:
            level = "HIGH"
        elif severity > 0.3:
            level = "ELEVATED"

        return LayerResult(
            layer=self.name,
            severity=severity,
            level=level,
            notes="Simulated DQSN network cluster risk.",
            metadata={"network_cluster_risk": cluster_risk},
        )
