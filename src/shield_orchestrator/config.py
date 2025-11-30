from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ShieldConfig:
    """
    High-level weight configuration for the 6 layers.

    These weights are used to compute the final aggregate risk score.
    They do NOT have to be perfect – they just keep the demo deterministic.
    """

    sentinel_weight: float = 0.15
    dqsn_weight: float = 0.20
    adn_weight: float = 0.20
    guardian_weight: float = 0.15
    qwg_weight: float = 0.15
    adaptive_weight: float = 0.15
