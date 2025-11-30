from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class GuardianWalletBridge(ShieldLayer):
    """
    Bridge for Guardian Wallet v2.

    Looks at:
    - withdrawal_amount_dgb
    - full_balance_wipe (bool)
    - destination_score (0–1 suspiciousness)
    """

    def __init__(self) -> None:
        super().__init__(name="guardian_wallet_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        p: Dict[str, Any] = event.payload

        amount = float(p.get("withdrawal_amount_dgb", 0.0))
        full_wipe = bool(p.get("full_balance_wipe", False))
        dest_score = float(p.get("destination_score", 0.0))

        severity = 0.0
        if amount > 0:
            severity += min(amount / 250_000.0, 1.0)
        if full_wipe:
            severity = max(severity, 0.9)
        severity = max(severity, dest_score)
        severity = max(0.0, min(severity, 1.0))

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
            notes="Simulated Guardian Wallet withdrawal behaviour.",
            metadata={
                "withdrawal_amount_dgb": amount,
                "full_balance_wipe": full_wipe,
                "destination_score": dest_score,
            },
        )
