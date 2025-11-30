from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .config import ShieldConfig
from .context import ShieldContext
from .bridges.base_layer import LayerResult
from .bridges.sentinel_bridge import SentinelLayer
from .bridges.dqsn_bridge import DQSNLayer
from .bridges.adn_bridge import ADNLayer
from .bridges.guardian_wallet_bridge import GuardianWalletLayer
from .bridges.qwg_bridge import QWGLayer
from .bridges.adaptive_core_bridge import AdaptiveCoreLayer


@dataclass
class ShieldResult:
    """Final aggregate result from the full shield pipeline."""
    final_score: float
    final_level: str
    layer_results: List[LayerResult]
    logs: List[str]


class FullShieldPipeline:
    """
    Minimal but real 6-layer orchestration.

    This does not import the separate layer repos – it models their behaviour
    with deterministic scoring so CI can run fully in this repository.
    """

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self.config = config or ShieldConfig()
        self.context = ShieldContext(config={"weights": self.config.__dict__})

        # Instantiate the 5 “front” layers.
        self.sentinel = SentinelLayer(weight=self.config.sentinel_weight)
        self.dqsn = DQSNLayer(weight=self.config.dqsn_weight)
        self.adn = ADNLayer(weight=self.config.adn_weight)
        self.guardian = GuardianWalletLayer(weight=self.config.guardian_weight)
        self.qwg = QWGLayer(weight=self.config.qwg_weight)
        self.adaptive_core = AdaptiveCoreLayer(weight=self.config.adaptive_weight)

    @classmethod
    def from_default_config(cls) -> "FullShieldPipeline":
        return cls()

    def _risk_level(self, score: float) -> str:
        if score >= 0.80:
            return "CRITICAL"
        if score >= 0.60:
            return "HIGH"
        if score >= 0.35:
            return "ELEVATED"
        return "LOW"

    def process_event(self, event: Dict[str, Any]) -> ShieldResult:
        """
        Run the event through all 6 layers and return an aggregate view.
        """
        results: List[LayerResult] = []

        # 1–5: individual layers
        for layer in (self.sentinel, self.dqsn, self.adn, self.guardian, self.qwg):
            res = layer.process(event, self.context)
            results.append(res)

        # 6: Adaptive Core sees all previous results.
        adaptive_result = self.adaptive_core.process(event, self.context, results)
        results.append(adaptive_result)

        # Aggregate
        final_score = (
            sum(r.risk_score for r in results) / len(results) if results else 0.0
        )
        level = self._risk_level(final_score)

        return ShieldResult(
            final_score=final_score,
            final_level=level,
            layer_results=results,
            logs=list(self.context.logs),
        )
