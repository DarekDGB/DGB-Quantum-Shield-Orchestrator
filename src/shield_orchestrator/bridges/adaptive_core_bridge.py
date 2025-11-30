from __future__ import annotations

from typing import Any, Dict, List

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class AdaptiveCoreLayer(BaseLayer):
    """
    Bridge for the Adaptive Core v2.

    It receives the *previous layer results* and produces a final immune score.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("adaptive_core_v2")
        self.weight = weight

    def process(
        self,
        event: Dict[str, Any],
        context: ShieldContext,
        previous_results: List[LayerResult],
    ) -> LayerResult:
        if not previous_results:
            score = 0.0
        else:
            avg_prev = sum(r.risk_score for r in previous_results) / len(previous_results)
            # Adaptive core amplifies persistent high risk, dampens noise.
            score = max(0.0, min(1.0, avg_prev * 1.1 * self.weight))

        context.log(f"[AdaptiveCore] previous_avg={avg_prev if previous_results else 0.0:.3f}, "
                    f"immune_score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "previous_layers": [r.name for r in previous_results],
            },
        )
