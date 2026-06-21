# Shield v4 Canonicalization Spec

Author attribution: DarekDGB

## Status

This document freezes the first Shield v4 canonicalization profile before production signing code exists.

Profile: `shield-v4-canon.v1`

This is a contract-level specification. It does not grant transaction-signing authority, broadcast authority, DigiByte consensus authority, wallet custody authority, or AdamantineOS override authority.

## Purpose

Every Shield v4 signature must be produced over one deterministic byte sequence.

If two implementations disagree about the bytes, signatures become unsafe or unverifiable. Therefore, canonicalization is frozen before Shield v4 component signing and Orchestrator signing are wired.

## Canonical JSON Rules

`shield-v4-canon.v1` requires:

- UTF-8 encoding only.
- Unicode strings normalized to NFC before serialization.
- JSON object keys sorted lexicographically by Unicode code point.
- Compact JSON separators: comma and colon only, with no insignificant whitespace.
- Deterministic JSON escaping only.
- `allow_nan=false` behavior.
- Floats are rejected in signed fields.
- NaN and Infinity are rejected.
- Integers are encoded as exact JSON integers.
- Boolean values are allowed as JSON booleans.
- Absent optional fields are omitted.
- `null` is rejected inside signed payloads.
- Arrays preserve schema-defined order.
- Set-valued fields must be emitted by producers as sorted unique lists before signing.
- Duplicate keys are rejected before canonicalization, including duplicate keys created by Unicode normalization.
- `signature_bundle` is excluded from the payload it signs.
- `signed_payload_hash` is excluded from the payload it signs.

## Domain-Separated Hash Input

Shield v4 signed-payload hashing uses this exact byte layout:

```text
DGB-SHIELD-V4-SIGNED-PAYLOAD\n<domain_tag>\n<canonical_json_bytes>
```

The SHA-256 digest of that byte sequence is the `signed_payload_hash`.

The newline separators are part of the frozen format.

## Frozen Domain Tags

Component verdict domain:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Orchestrator receipt domain:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

A signature produced for one domain must never verify in the other domain.

## Receipt Hash

`receipt_hash` is the SHA-256 hash of the canonical unsigned receipt payload.

`receipt_hash` is evidence integrity. It is not a transaction signature and not final execution authority.

## Known-Answer Tests

The frozen V4.3 test vector lives at:

```text
tests/fixtures/v4/orchestrator_receipt_policy_v1_kat.json
```

Every later implementation that claims compatibility with this profile must reproduce the same canonical JSON, domain-separated payload bytes, `receipt_hash`, and `signed_payload_hash` for the same input.

## Fail-Closed Rules

A verifier must reject:

- unsupported domain tags
- non-canonical JSON input
- duplicate keys
- Unicode-normalization key collisions
- floats, NaN, or Infinity
- `null` values inside signed payloads
- changed signed fields after signing
- mismatched `signed_payload_hash`
- mismatched `receipt_hash`
- use of component-verdict signatures as Orchestrator-receipt signatures
- use of Orchestrator-receipt signatures as component-verdict signatures
