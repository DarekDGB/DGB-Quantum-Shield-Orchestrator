from __future__ import annotations

from .bridges.base_layer import LEGACY_PROCESS_DISABLED_MESSAGE
from .config import ShieldConfig
from .context import ShieldContext


class FullShieldPipeline:
    """
    Deprecated legacy pipeline shell.

    This class is retained only so older imports fail loudly instead of falling
    back to a fake all-pass Shield path. The live Shield handoff API is the
    v3.2 receipt entrypoint: shield_orchestrator.v3.orchestrate.orchestrate().
    """

    def __init__(self, config=None):
        self.config = config or ShieldConfig()
        self.ctx = ShieldContext(self.config)

    @staticmethod
    def from_default_config():
        return FullShieldPipeline()

    def process_event(self, event: dict) -> dict:
        """
        Disabled legacy v2-style entrypoint.

        FullShieldPipeline previously called BaseLayer.process(), which could
        return unconditional all-pass data. That path is intentionally closed.
        """
        raise RuntimeError(LEGACY_PROCESS_DISABLED_MESSAGE)
