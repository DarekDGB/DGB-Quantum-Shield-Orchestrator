from __future__ import annotations


LEGACY_PROCESS_DISABLED_MESSAGE = (
    "Legacy BaseLayer.process() is disabled because it is not a live Shield "
    "v3.2 receipt path. Use shield_orchestrator.v3.orchestrate.orchestrate() "
    "with explicit component_inputs to produce a fail-closed v3.2 receipt."
)


class BaseLayer:
    def process(self, event: dict) -> dict:
        """
        Disabled legacy v2-style process path.

        The v3.2 Orchestrator must not expose any unconditional all-pass layer
        path. Integrators must use the fail-closed v3.2 receipt entrypoint:
        shield_orchestrator.v3.orchestrate.orchestrate().
        """
        raise RuntimeError(LEGACY_PROCESS_DISABLED_MESSAGE)
