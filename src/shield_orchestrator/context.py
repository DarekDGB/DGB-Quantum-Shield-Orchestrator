# src/shield_orchestrator/context.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict
import uuid


@dataclass
class ShieldContext:
    """Simple shared context for a full-shield run."""

    run_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "ShieldContext":
        return cls(run_id=str(uuid.uuid4()))
