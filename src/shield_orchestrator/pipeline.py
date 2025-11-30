# src/shield_orchestrator/pipeline.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from .context import ShieldContext
from .bridges.base_layer import LayerResult
from .bridges.sentinel_bridge import SentinelBridge
from .bridges.dqsn_bridge import DQSNBridge
from .bridges.adn_bridge import ADNBridge
from .bridges.guardian_wallet_bridge import GuardianWalletBridge
from .bridges.qwg_bridge import QWGBridge
from .bridges.adaptive_core_bridge import AdaptiveCoreBridge


@dataclass
class FullShieldResult:
    context: ShieldContext
    layer_results: List[LayerResult]

    @property
    def final_risk_score(self) -> float:
        if not self.layer_results:
            return 0.0
        return max(r.risk_score for r in self.layer_results)

    @property
    def final_risk_level(self) -> str:
        score = self.final_risk_score
        if score >= 0.8:
            return "CRITICAL"
        if score >= 0.5:
            return "HIGH"
        if score >= 0.3:
            return "ELEVATED"
        return "LOW"


class FullShieldPipeline:
    """Self-contained 6-layer pipeline used for CI & demos.

    This does *not* call real Sentinel/DQSN/ADN/etc.  It only simulates
    the data flow so the architecture can be tested cleanly.
    """

    def __init__(
        self,
        *,
        sentinel: SentinelBridge | None = None,
        dqsn: DQSNBridge | None = None,
        adn: ADNBridge | None = None,
        guardian_wallet: GuardianWalletBridge | None = None,
        qwg: QWGBridge | None = None,
        adaptive_core: AdaptiveCoreBridge | None = None,
        context: ShieldContext | None = None,
    ) -> None:
        self.context = context or ShieldContext.default()
        self.sentinel = sentinel or SentinelBridge()
        self.dqsn = dqsn or DQSNBridge()
        self.adn = adn or ADNBridge()
        self.guardian_wallet = guardian_wallet or GuardianWalletBridge()
        self.qwg = qwg or QWGBridge()
        self.adaptive_core = adaptive_core or AdaptiveCoreBridge()

    @classmethod
    def from_default_config(cls) -> "FullShieldPipeline":
        return cls()

    def _iter_layers(self) -> Iterable:
        return (
            self.sentinel,
            self.dqsn,
            self.adn,
            self.guardian_wallet,
            self.qwg,
            self.adaptive_core,
        )

    def process_event(self, event: Dict[str, Any]) -> FullShieldResult:
        """Run one event through all 6 layers in sequence."""
        current_event: Dict[str, Any] = dict(event)
        results: List[LayerResult] = []

        for bridge in self._iter_layers():
            result = bridge.process(current_event, self.context)
            results.append(result)

            # Enrich event with this layer's risk for later stages.
            current_event[f"{bridge.name}_risk"] = result.risk_score

        return FullShieldResult(context=self.context, layer_results=results)
