from __future__ import annotations

from typing import Any, Dict

from .base_layer import ShieldLayer, ShieldEvent, LayerResult
from ..context import ShieldContext


class QWGBridge(ShieldLayer):
    """
    Bridge for Quantum Wallet Guard v2.

    Uses 'qrs' (Quantum-style Risk Score) between 0–100.
    """

    def __init__(self) -> None:
        super().__init__(name="qwg_v2")

    def process(self, event: ShieldEvent, ctx: ShieldContext) -> LayerResult:
        p: Dict[str, Any] = event.payload
        qrs = float(p.get("qrs", 0.0))

        severity = max(0.0, min(qrs / 100.0, 1.0))
        level = "LOW"
        if severity > 0.85:
            level = "CRITICAL"
        elif severity > 0.65:
            level = "HIGH"
        elif severity > 0.4:
            level = "ELEVATED"

        return LayerResult(
            layer=self.name,
            severity=severity,
            level=level,
            notes="Simulated QWG quantum-style risk score.",
            metadata={"qrs": qrs},
        )
