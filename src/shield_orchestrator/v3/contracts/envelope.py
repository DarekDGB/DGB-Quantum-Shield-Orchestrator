from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .version import CONTRACT_VERSION


Outcome = Literal["ALLOW", "ESCALATE", "DENY"]
TraceStatus = Literal["OK", "DENY", "ERROR", "SKIPPED"]


@dataclass(frozen=True)
class TraceEntry:
    """
    Deterministic pipeline trace entry.
    """
    stage: str
    component: str
    status: TraceStatus
    reason_ids: tuple[str, ...] = ()
    component_context_hash: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class OrchestratorV3Request:
    """
    Public v3 request envelope.
    """
    contract_version: int
    wallet_id: str
    action: str
    nonce: str
    ttl_seconds: int

    # Optional opaque payload (treated strictly as data, no semantics here)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OrchestratorV3Response:
    """
    Public v3 response envelope.
    """
    contract_version: int
    context_hash: str
    outcome: Outcome
    reason_ids: tuple[str, ...]
    trace: tuple[TraceEntry, ...]

    @staticmethod
    def deny(
        *,
        context_hash: str,
        reason_ids: tuple[str, ...],
        trace: tuple[TraceEntry, ...],
    ) -> "OrchestratorV3Response":
        """
        Construct a deterministic DENY response.
        """
        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            context_hash=context_hash,
            outcome="DENY",
            reason_ids=reason_ids,
            trace=trace,
        )
