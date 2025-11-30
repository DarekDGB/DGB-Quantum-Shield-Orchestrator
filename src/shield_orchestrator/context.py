from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict
import uuid


@dataclass
class ShieldContext:
    """
    Shared runtime context for one Quantum Immune Shield evaluation.

    Keeps:
    - request_id for tracing
    - created_at timestamp
    - arbitrary metadata (e.g. testnet, node id, wallet id)
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def with_metadata(self, **extra: Any) -> "ShieldContext":
        """Return a shallow copy with additional metadata merged in."""
        merged = {**self.metadata, **extra}
        return ShieldContext(
            request_id=self.request_id,
            created_at=self.created_at,
            metadata=merged,
        )
