from __future__ import annotations

from typing import Any, Dict

from .base_layer import BaseLayer, LayerResult
from ..context import ShieldContext


class GuardianWalletLayer(BaseLayer):
    """
    Bridge for Guardian Wallet v2.

    It looks at withdrawal size and recent activity bursts.
    """

    def __init__(self, weight: float = 1.0) -> None:
        super().__init__("guardian_wallet_v2")
        self.weight = weight

    def process(self, event: Dict[str, Any], context: ShieldContext) -> LayerResult:
        amount_dgb = float(event.get("amount_dgb", 0.0))
        recent_txs = int(event.get("recent_txs", 0))

        # Simple heuristic: big withdrawal or sudden activity burst.
        amount_score = min(1.0, amount_dgb / 250_000.0)
        burst_score = min(1.0, recent_txs / 10.0)

        base_score = max(amount_score, burst_score)
        score = max(0.0, min(1.0, base_score * self.weight))

        context.log(f"[GuardianWallet] amount_dgb={amount_dgb}, recent_txs={recent_txs}, "
                    f"score={score:.3f}")

        return LayerResult(
            name=self.name,
            risk_score=score,
            details={
                "amount_dgb": amount_dgb,
                "recent_txs": recent_txs,
            },
        )
