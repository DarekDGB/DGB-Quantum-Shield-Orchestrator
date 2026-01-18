from __future__ import annotations

from dataclasses import asdict

from .base_layer import BaseLayer
from shield_orchestrator.v3.context_hash import compute_context_hash
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, OrchestratorV3Response, TraceEntry


class AdaptiveCoreBridge(BaseLayer):
    """
    Adaptive Core bridge (read-only sink).

    Adaptive Core v3 is an oracle/reporting layer:
    - it MUST NOT grant runtime authority
    - it MUST NOT change the orchestrator decision
    - it MAY ingest the final v3 envelope and produce a report later

    Phase 3: we emit a deterministic TraceEntry that records that a report
    was (conceptually) produced from the orchestrator outcome.
    """

    COMPONENT = "adaptive_core"
    STAGE = "adaptive_core"

    def report_v3(self, request: OrchestratorV3Request, final: OrchestratorV3Response) -> TraceEntry:
        """
        Produce a deterministic report trace entry from the final orchestrator response.

        This does not affect ALLOW/ESCALATE/DENY.
        """
        component_context_hash = compute_context_hash(
            {
                "component": self.COMPONENT,
                "request": asdict(request),
                "final": asdict(final),
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
