from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.orchestrate import orchestrate


def test_v3_fail_closed_when_components_unwired():
    req = OrchestratorV3Request(
        contract_version=3,
        wallet_id="w1",
        action="SEND",
        nonce="n1",
        ttl_seconds=60,
        payload={},
    )

    resp = orchestrate(req)

    assert resp.outcome == "DENY"
    assert "COMPONENT_MISSING" in resp.reason_ids
    # deterministic trace includes final_synthesis
    assert any(t.stage == "final_synthesis" for t in resp.trace)
