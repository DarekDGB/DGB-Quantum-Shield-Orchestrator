from __future__ import annotations

from dataclasses import asdict

from .base_layer import BaseLayer
from shield_orchestrator.v3.context_hash import compute_context_hash
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, TraceEntry


class AdaptiveCoreBridge(BaseLayer):
    """
    Adaptive Core bridge (read-only sink).

    - MUST NOT influence orchestrator outcome.
    - Emits a deterministic TraceEntry indicating a report was produced.
    """

    COMPONENT = "adaptive_core"
    STAGE = "adaptive_core"

    def report_v3(self, request: OrchestratorV3Request, *, outcome: str, reason_ids: tuple[str, ...]) -> TraceEntry:
        """
        Produce a deterministic sink trace entry.

        IMPORTANT:
        This is a sink only. It does not change outcome/reason_ids.
        """
        component_context_hash = compute_context_hash(
            {
                "component": self.COMPONENT,
                "request": asdict(request),
                "outcome": outcome,
                "reason_ids": list(reason_ids),
            }
        )

        return TraceEntry(
            stage=self.STAGE,
            component=self.COMPONENT,
            status="OK",
            reason_ids=(),
            component_context_hash=component_context_hash,
            notes="phase3_sink_stub",
        )
