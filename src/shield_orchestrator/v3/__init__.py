from __future__ import annotations

"""
shield_orchestrator.v3

IMPORTANT:
Do not import orchestrate() at module import time.
Bridges import v3 submodules (e.g. context_hash), and importing orchestrate
here creates a circular import during test collection.

Consumers should import directly:
    from shield_orchestrator.v3.orchestrate import orchestrate
"""

__all__ = []
