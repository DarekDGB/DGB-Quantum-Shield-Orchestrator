from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ShieldContext:
    """
    Shared runtime context for the full shield pipeline.
    Keeps simple config, network label and a log buffer.
    """

    network: str = "dgb-regtest"
    config: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)

    def log(self, message: str) -> None:
        """Append a message to the in-memory log buffer."""
        self.logs.append(message)
