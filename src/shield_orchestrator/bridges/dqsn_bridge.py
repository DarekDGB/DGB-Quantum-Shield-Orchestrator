from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class DQSNLayer(BaseLayer):
    """
    Lightweight bridge for DigiByte Quantum Shield Network (DQSN v2).

    It interprets network-wide confirmation / cluster risk.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("dqsn_v2")
        self.weight = weight

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        cluster_risk = float(event.get("cluster_risk", 0.0))
        global_alerts = int(event.get("global_alerts", 0))

        base_score = max(0.0, min(1.0, cluster_risk + 0.1 * global_alerts))
        score = max(0.0, min(1.0, base_score * self.weight))

        context.log(f"[DQSN] cluster_risk={cluster_risk}, global_alerts={global_alerts}, "
                    f"score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "cluster_risk": cluster_risk,
                "global_alerts": global_alerts,
            },
        )
