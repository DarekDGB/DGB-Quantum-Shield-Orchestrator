from __future__ import annotations

import pytest

from shield_orchestrator.v4.canonical_json import (
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
    canonicalization_manifest,
    domain_separated_payload_bytes,
    parse_json_no_duplicate_keys,
    signed_payload_hash,
    to_canonical_json,
)


def test_v4_canonical_json_normalizes_unicode_and_orders_keys():
    payload = {"z": "e\u0301", "a": [2, 1], "set_like": ["b", "a"]}
    assert to_canonical_json(payload) == '{"a":[2,1],"set_like":["b","a"],"z":"é"}'


def test_v4_canonical_json_rejects_ambiguous_values():
    for payload in ({"n": None}, {"f": 1.1}, {1: "bad"}, {"bad": object()}):
        with pytest.raises(ValueError):
            to_canonical_json(payload)  # type: ignore[arg-type]


def test_v4_parse_json_rejects_duplicate_keys_and_non_object_root():
    with pytest.raises(ValueError, match="duplicate key"):
        parse_json_no_duplicate_keys('{"a":1,"a":2}')
    with pytest.raises(ValueError, match="root"):
        parse_json_no_duplicate_keys('[1,2]')
    assert parse_json_no_duplicate_keys('{"b":2,"a":1}') == {"b": 2, "a": 1}


def test_v4_domain_separated_hashes_are_distinct_and_stable():
    payload = {"request_id": "req-v4", "context_hash": "a" * 64}
    component_hash = signed_payload_hash(domain_tag=COMPONENT_VERDICT_DOMAIN, payload=payload)
    receipt_hash = signed_payload_hash(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=payload)
    assert component_hash == "0b4a611a7e15d977b09c22521690a29b68a51b4ff7d4bb323b93c86446989335"
    assert receipt_hash == "cf31adbbbd373578f3ececee9f9b8cfb76cc73b63a08bbfd0b87bfb8545522c4"
    assert component_hash != receipt_hash
    assert domain_separated_payload_bytes(domain_tag=ORCHESTRATOR_RECEIPT_DOMAIN, payload=payload).startswith(
        b"DGB-SHIELD-V4-SIGNED-PAYLOAD\nDGB-SHIELD-V4-ORCH-RECEIPT"
    )
    with pytest.raises(ValueError, match="domain"):
        signed_payload_hash(domain_tag="bad", payload=payload)


def test_v4_canonicalization_manifest_declares_frozen_profile():
    manifest = canonicalization_manifest()
    assert manifest["canonicalization_profile"] == "shield-v4-canon.v1"
    assert manifest["component_verdict_domain"] == COMPONENT_VERDICT_DOMAIN
    assert manifest["orchestrator_receipt_domain"] == ORCHESTRATOR_RECEIPT_DOMAIN


def test_v4_canonical_json_covers_tuple_non_dict_and_normalized_duplicate_key():
    assert to_canonical_json({"tuple": ("b", "a")}) == '{"tuple":["b","a"]}'
    with pytest.raises(ValueError, match="payload must be dict"):
        to_canonical_json(["bad"])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="duplicate key"):
        to_canonical_json({"é": 1, "e\u0301": 2})
