import pytest

from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request
from shield_orchestrator.v3.orchestrate import orchestrate


@pytest.mark.parametrize(
    "wallet_id, action, nonce, ttl_seconds",
    [
        ("", "SEND", "n1", 60),
        ("w1", "", "n1", 60),
        ("w1", "SEND", "", 60),
        ("w1", "SEND", "n1", 0),
    ],
)
def test_v3_invalid_request_fields_fail_closed(wallet_id, action, nonce, ttl_seconds) -> None:
    req = OrchestratorV3Request(
        contract_version=3,
        wallet_id=wallet_id,
        action=action,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
        payload={},
    )
    resp = orchestrate(req)
    assert resp.outcome == "DENY"
    assert "INVALID_REQUEST" in resp.reason_ids


def test_v3_hashing_failure_maps_to_hashing_failed() -> None:
    req = OrchestratorV3Request(
        contract_version=3,
        wallet_id="w1",
        action="SEND",
        nonce="n1",
        ttl_seconds=60,
        payload={"bad": object()},  # not JSON serializable -> hashing failure
    )
    resp = orchestrate(req)
    assert resp.outcome == "DENY"
    assert "HASHING_FAILED" in resp.reason_ids
