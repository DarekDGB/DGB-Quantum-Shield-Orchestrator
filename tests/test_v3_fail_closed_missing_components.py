from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.orchestrate import orchestrate


def test_v3_denies_by_default_when_wired_phase3() -> None:
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
    assert "POLICY_DENY_BY_DEFAULT" in resp.reason_ids
