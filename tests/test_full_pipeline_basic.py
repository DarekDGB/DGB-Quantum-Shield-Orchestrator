from shield_orchestrator import FullShieldPipeline, ShieldContext


def test_full_pipeline_low_risk():
    pipeline = FullShieldPipeline.from_default_config()

    payload = {
        "entropy_drop": 0.05,
        "network_cluster_risk": 0.1,
        "node_stress": 0.05,
        "withdrawal_amount_dgb": 1000,
        "full_balance_wipe": False,
        "destination_score": 0.1,
        "qrs": 5.0,
        "network_immune_score": 0.05,
    }

    outcome = pipeline.process_event(payload)

    assert outcome.final_risk_level == "LOW"
    assert len(outcome.trace) == 6
    assert 0.0 <= outcome.max_severity <= 0.35


def test_full_pipeline_high_risk():
    pipeline = FullShieldPipeline.from_default_config()

    payload = {
        "entropy_drop": 0.8,
        "network_cluster_risk": 0.9,
        "node_stress": 0.7,
        "withdrawal_amount_dgb": 600_000,
        "full_balance_wipe": True,
        "destination_score": 0.9,
        "qrs": 92.0,
        "network_immune_score": 0.88,
    }

    outcome = pipeline.process_event(payload)

    assert outcome.final_risk_level in ("HIGH", "CRITICAL")
    assert len(outcome.trace) == 6
    assert outcome.max_severity > 0.65

    # Ensure each named layer appears exactly once
    layer_names = [r.layer for r in outcome.trace]
    assert set(layer_names) == {
        "sentinel_v2",
        "dqsn_v2",
        "adn_v2",
        "guardian_wallet_v2",
        "qwg_v2",
        "adaptive_core_v2",
    }
