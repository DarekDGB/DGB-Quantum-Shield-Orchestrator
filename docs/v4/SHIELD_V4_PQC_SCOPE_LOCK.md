# Shield v4 PQC Scope Lock

Author attribution: DarekDGB

## Status

This document is a pre-implementation scope lock for Shield v4 PQC work.

Baseline tag: `ecosystem-pre-v4-audit-lock`

This is not a Shield v4 release. It does not add signing code, verification code, key material, or a new release claim.

## Purpose

Shield v3 is the deterministic fail-closed skeleton.

Shield v4 adds cryptographically verifiable armor around that skeleton.

Shield v4 must be built as a parallel v4 contract surface. It must not weaken, replace, or silently reinterpret the audited v3 boundary.

## Non-Negotiable Authority Locks

Shield v4 does not sign transactions.

Shield v4 does not broadcast transactions.

Shield v4 does not hold, derive, export, or request wallet private keys, seed material, recovery phrases, or transaction-signing authority.

Shield v4 does not change DigiByte consensus.

Shield v4 does not approve final execution.

Shield v4 produces cryptographically verifiable decision evidence only.

AdamantineOS remains the final execution boundary.

A Shield v4 `ALLOW` is evidence for AdamantineOS. It is not final wallet approval, not broadcast permission, and not autonomous execution authority.

## Scope Boundary

In scope for Shield v4:

- signed Shield component verdict evidence
- signed Shield Orchestrator receipt evidence
- deterministic canonical signed payloads
- domain-separated signature payloads
- verifier-authoritative signature policy checks
- key role separation
- key registry validity and revocation checks
- anti-replay and freshness fields covered by signatures
- negative tests for tampering, replay, downgrade, wrong key, wrong algorithm, context mismatch, and authority injection
- external verification contract documents and frozen Known-Answer Test vectors before future external verifier integrations

Out of scope for Shield v4:

- transaction signing
- transaction broadcasting
- DigiByte consensus modification
- wallet custody
- wallet seed handling
- private-key management for transaction keys
- AI-generated final approvals
- raw component output as AdamantineOS input
- any upstream override of AdamantineOS final policy

## PQC Naming Lock

Use accurate post-quantum signature names.

- ML-DSA, formerly CRYSTALS-Dilithium
- FN-DSA, based on Falcon

ML-DSA and FN-DSA are separate signature directions. FN-DSA / Falcon must never be described as ML-DSA.

Any existing legacy algorithm identifier from another repository must be treated as an implementation compatibility question for the later Q-ID alignment step. Shield v4 documentation must keep the underlying algorithm meaning clear.

## v4 Contract Shape

Shield v4 must keep v3 intact and add parallel v4 schemas.

Planned v4 schema names:

- `shield.verdict.v2`
- `shield.receipt.v2`
- `shield.signature_bundle.v1`
- `shield.key_registry.v1`

Existing v3 schemas remain unchanged:

- `shield.verdict.v1`
- `shield.receipt.v1`

No v4 code may silently accept a v3 receipt where v4 is required.

## First-Signing Design Locks

Anything signed in v4 becomes expensive to change. The following locks must exist before first signing code.

### Canonicalization

The v4 canonicalization profile is `shield-v4-canon.v1`.

The exact canonicalization rules are normative in `SHIELD_V4_CONTRACT_INVARIANTS.md`.

No v4 signature code may be added until canonical payload bytes and signed field sets are locked by tests and Known-Answer Test vectors.

### Domain Separation

Every signed component verdict must bind this domain tag into the signed bytes:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Every signed Orchestrator receipt must bind this domain tag into the signed bytes:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

A signature produced under one domain tag must never verify under another.

### Signed Freshness / Anti-Replay

Freshness is part of the signed payload, not an unsigned side check.

Every signed verdict and signed receipt must bind:

- `request_id`
- `freshness_nonce`
- `not_before`
- `not_after`

A verifier must reject stale receipts, future receipts, duplicate `request_id` / `freshness_nonce` pairs inside the active freshness window, and any receipt whose freshness fields were changed after signing.

### Key Lifecycle

Every signature entry must include:

- `key_id`
- `key_version`
- `algorithm`

Every trust-registry entry must include:

- `role`
- `key_id`
- `key_version`
- `algorithm`
- `not_before`
- `not_after`
- `status`

Supported key status values are:

- `active`
- `revoked`

Revoked keys fail closed. Expired keys fail closed. Unknown keys fail closed. Registry rollback that re-activates a revoked key fails closed.

### Versioned Signature Policy

The first Shield v4 policy version is `policy.v1`.

`policy.v1` requires:

- one approved classical signature path
- one approved ML-DSA signature path

`policy.v1` may allow FN-DSA as supplemental evidence.

FN-DSA must never override failure of a required classical or ML-DSA path.

The embedded `signature_policy` is signed evidence. The verifier's required policy is authoritative. If embedded policy is weaker than verifier-required policy, verification fails closed.

### Hybrid Bundle Binding

All required signatures in a bundle must sign the same domain-separated `signed_payload_hash`.

No first-valid-wins behavior is allowed.

All required algorithms must be evaluated.

Duplicate algorithm entries fail closed.

Unknown or unsupported algorithm entries fail closed.

Cross-receipt signature splicing fails closed.

### External / Wallet Verifier Boundary

The wallet is not the Shield v4 final authority.

The wallet must not treat an unverified Shield receipt as verified.

The wallet must display or act on AdamantineOS final outcome only.

AdamantineOS remains the verification and execution boundary unless a future external verifier contract is explicitly documented, tested, and frozen.

### Frozen Known-Answer Test Vectors

Before v4 code is called locked, test-only vectors must freeze:

- input payload
- canonical bytes
- domain tag
- signed payload hash
- signature bundle shape
- expected verifier result

The vectors must use clearly marked TEST-ONLY keys and must never contain production secrets.

### Dual-Stack Governance / Rollback

A `v4-required` mode must not be controlled by untrusted upstream input.

A downgrade from `v4-required` to `v3-allowed` is a security event and must fail closed unless a future versioned governance contract explicitly permits it.

Rollback must never silently re-open a v3 bypass.

### Verification Observability / Audit Trail

Verification should produce a non-secret audit trail containing:

- `request_id`
- `context_hash`
- `key_id`
- `key_version`
- `algorithm`
- `policy_version`
- pass / fail result
- fail-closed reason identifier

Private keys, seed material, signatures secrets, and sensitive payload secrets must never be logged.

### Performance / DoS Envelope

Verification must reject malformed input before expensive cryptographic verification.

Validation order must be:

1. structural schema checks
2. required field checks
3. canonicalization checks
4. hash checks
5. key-registry checks
6. signature verification

A bounded per-request verification work budget must be defined before release.

## Build Order Lock

Shield v4 build order:

1. scope lock documents
2. Q-ID crypto alignment without key reuse
3. Orchestrator v4 crypto contract primitives
4. QWG pilot component
5. remaining component ports
6. Orchestrator verification of signed component verdicts
7. AdamantineOS Shield v4 verifier
8. full multi-repo v4 integration harness
9. Adaptive Core / AI Gateway compatibility notes
10. final proof pack and release gate

No crypto code should be written before these scope locks are accepted.

## Final Scope Statement

Cryptography proves Shield evidence.

Cryptography does not grant execution authority.

AdamantineOS remains the final boundary.
