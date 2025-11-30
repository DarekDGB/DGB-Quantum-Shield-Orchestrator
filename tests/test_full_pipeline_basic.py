# tests/test_full_pipeline_basic.py

from __future__ import annotations

from shield_orchestrator.pipeline import FullShieldPipeline


def test_full_pipeline_runs_low_risk() -> None:
    """Pipeline should run end-to-end and produce a LOW or higher level."""
    shield = FullShieldPipeline.from_default_config()

    event = {
        "type": "tx",
        "amount_dgb": 1000,
    }

    result = shield.process_event(event)

    assert len(result.layer_results) == 6
    assert result.final_risk_level in {"LOW", "ELEVATED", "HIGH", "CRITICAL"}


def test_full_pipeline_detects_high_risk() -> None:
    """If all layers see strong risk, final score should be high."""
    shield = FullShieldPipeline.from_default_config()

    event = {
        "type": "tx",
        "amount_dgb": 1_000_000,
        "sentinel_risk": 0.6,
        "network_risk": 0.7,
        "node_risk": 0.8,
        "wallet_risk": 0.85,
        "quantum_risk": 0.9,
        "immune_risk": 0.95,
        "quantum_flag": True,
    }

    result = shield.process_event(event)

    assert result.final_risk_score >= 0.5
    assert result.final_risk_level in {"HIGH", "CRITICAL"}
