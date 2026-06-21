# Shield v4 / Q-ID Crypto Alignment

Author attribution: DarekDGB

## Status

This document is a pre-implementation alignment lock for Shield v4 PQC work.

Baseline tag: `ecosystem-pre-v4-audit-lock`

This is not a Shield v4 release. It does not add signing code, verification code, key material, wallet authority, or DigiByte consensus changes.

## Purpose

Shield v4 may align with Q-ID's algorithm naming direction, but it must not reuse Q-ID keys, Q-ID trust roles, Q-ID login authority, or Q-ID identity proofs as Shield decision authority.

Q-ID proves identity / authentication evidence.

Shield v4 proves Shield component verdict evidence and Shield Orchestrator receipt evidence.

AdamantineOS remains the final execution boundary.

## Non-Negotiable Boundary

Shield v4 does not sign transactions.

Shield v4 does not broadcast transactions.

Shield v4 does not change DigiByte consensus.

Shield v4 does not hold, derive, export, request, or route wallet private keys, seed material, recovery phrases, or transaction-signing authority.

Shield v4 produces cryptographically verifiable decision evidence only.

A Shield v4 signature proves that a Shield role signed a specific Shield evidence payload under a specific domain tag, policy version, key version, registry version, freshness rule, and canonicalization profile.

A Shield v4 signature never grants final execution authority.

## Algorithm Naming Alignment

Shield v4 may use the same public algorithm identifier direction as Q-ID where the meaning is compatible:

| Shield v4 meaning | Compatible identifier direction | Accurate algorithm wording |
|---|---|---|
| Development-only deterministic test path | `dev-hmac-sha256` | CI/test-only scaffold, not production cryptography |
| ML-DSA signature path | `pqc-ml-dsa` | ML-DSA, formerly CRYSTALS-Dilithium |
| FN-DSA / Falcon signature path | `pqc-falcon` | FN-DSA, based on Falcon |
| Hybrid signature bundle | `pqc-hybrid-ml-dsa-falcon` | ML-DSA plus FN-DSA/Falcon with strict AND semantics |

ML-DSA and FN-DSA/Falcon are separate signature directions.

FN-DSA/Falcon must never be described as ML-DSA.

A valid optional FN-DSA/Falcon path must never override failure of a required ML-DSA path or any other verifier-required signature path.

## Q-ID Reference Files

Q-ID currently contains the ecosystem crypto direction in these files:

- `qid/algorithms.py`
- `qid/crypto.py`
- `qid/pqc_backends.py`
- `qid/pqc_sign.py`
- `qid/pqc_verify.py`
- `docs/CONTRACTS/PQC_MODEL.md`
- `docs/CONTRACTS/CANONICAL_JSON_PROFILES.md`

These files are reference material for naming and failure philosophy only.

They are not Shield v4 key material, not Shield v4 trust registry entries, not Shield v4 authority, and not a substitute for Shield v4's own contracts and tests.

## Key Separation Lock

Shield v4 must not reuse Q-ID keys.

Q-ID key roles and Shield key roles are separate trust domains.

Required Shield v4 key roles are:

- `shield_component_adn`
- `shield_component_dqsn`
- `shield_component_guardian_wallet`
- `shield_component_qwg`
- `shield_component_sentinel_ai`
- `shield_orchestrator`

Each Shield role must have its own key identity, key version, algorithm binding, validity window, and trust-registry entry.

A Q-ID identity key must not be accepted as any Shield component key.

A Q-ID identity key must not be accepted as the Shield Orchestrator key.

A Shield component key must not be accepted as the Shield Orchestrator key.

A Shield key must not be accepted as a Q-ID identity key.

## Trust Role Separation

| Domain | What it proves | What it must not prove |
|---|---|---|
| Q-ID | Identity / authentication evidence | Shield component verdict authority |
| Shield component | Component verdict evidence | Orchestrator aggregation authority |
| Shield Orchestrator | Verified Shield aggregation receipt evidence | AdamantineOS final execution authority |
| AdamantineOS | Final policy decision boundary | DigiByte consensus mutation or wallet private-key authority |

No domain may inherit authority from another domain through field names, metadata, algorithm labels, or shared key material.

## Canonicalization Alignment Rule

Shield v4 has its own frozen canonicalization profile:

- `shield-v4-canon.v1`

Q-ID has its own canonicalization profiles.

Shield v4 may study Q-ID canonicalization design, but Shield v4 signed bytes must be defined by the Shield v4 canonicalization specification and frozen Known-Answer Test vectors.

A Q-ID canonical profile must not be silently substituted for `shield-v4-canon.v1`.

A future bridge between Q-ID and Shield must compare explicit profile names and fail closed on mismatch.

## Domain Separation Rule

Shield v4 signatures must include Shield-specific domain separation tags in the signed bytes.

Planned Shield v4 tags:

- `DGB-SHIELD-V4-COMPONENT-VERDICT:<schema_version>:<policy_version>`
- `DGB-SHIELD-V4-ORCH-RECEIPT:<schema_version>:<policy_version>`

Q-ID login or identity signatures must never verify under Shield v4 domain tags.

Shield v4 component verdict signatures must never verify under Q-ID login or identity tags.

Shield v4 component verdict signatures must never verify as Shield Orchestrator receipt signatures.

## Signature Policy Alignment

Hybrid means strict AND, not OR.

If the verifier-required policy requires classical plus ML-DSA, both must pass.

If the verifier-required policy later requires classical plus ML-DSA plus FN-DSA/Falcon, all required paths must pass.

No `first valid signature wins` behavior is allowed.

The verifier's required policy is authoritative.

The embedded `signature_policy` is signed evidence, not a verifier override.

A weaker embedded policy than the verifier-required policy must fail closed.

## Registry Alignment

Shield v4 must use a Shield trust registry, not a Q-ID trust registry.

A Shield registry entry must bind at minimum:

- role
- key id
- key version
- algorithm
- validity window
- status: `active` or `revoked`
- registry version

A revoked Shield key must fail closed.

A Q-ID registry entry, Q-ID binding, Q-ID login proof, or Q-ID public key container must not be accepted as a Shield registry entry.

## External / Wallet Boundary

The wallet is not the Shield v4 cryptographic authority in the first v4 design.

The wallet must treat Shield v4 artifacts as untrusted unless AdamantineOS has verified them and produced the final outcome.

Future wallet-side or external verification must use a published Shield v4 external verifier contract, frozen canonicalization spec, frozen KAT vectors, signature bundle rules, and trust registry rules.

This alignment document prevents wallet integration from being redesigned around Q-ID keys or Q-ID authority when Shield v4 arrives.

## Fail-Closed Requirements

A Shield v4 verifier must fail closed if it sees:

- a Q-ID key used for a Shield role
- a Shield key used for a Q-ID role
- an unknown algorithm
- an unsupported algorithm
- a legacy algorithm label without explicit compatibility rules
- a missing Shield domain tag
- a Q-ID domain tag where a Shield domain tag is required
- a canonicalization profile mismatch
- a weaker signature policy than the verifier-required policy
- missing required algorithm paths
- optional FN-DSA/Falcon success while a required path fails
- revoked key material
- stale or rollback key registry version

## V4.2 Exit Criteria

This step is complete only when:

- Shield v4 naming is aligned with Q-ID without key reuse.
- Q-ID has a matching document stating the same boundary from the Q-ID side.
- No crypto implementation is added in V4.2.
- No transaction-signing, broadcasting, consensus, custody, or AdamantineOS override path is introduced.
- Later V4.3 code can build Shield-specific canonicalization, signature bundle, and key registry modules without importing Q-ID authority as Shield authority.
