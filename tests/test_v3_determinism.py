from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.orchestrate import orchestrate


def test_v3_deterministic_context_hash_same_input_same_output():
    req = OrchestratorV3Request(
        contract_version=3,
        wallet_id="w1",
        action="SEND",
        nonce="n1",
        ttl_seconds=60,
        payload={"x": 1, "y": ["a", "b"]},
    )

    a = orchestrate(req)
    b = orchestrate(req)

    assert a.context_hash == b.context_hash
    assert a.outcome == b.outcome
    assert a.reason_ids == b.reason_ids
    assert a.trace == b.trace
