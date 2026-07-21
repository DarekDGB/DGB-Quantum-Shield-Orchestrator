# Shield v4 / Q-ID Crypto Alignment

Author attribution: DarekDGB

## Status

This document is the post-V4.8H crypto-alignment lock between the implemented
Shield v4 policy surface and the current Q-ID crypto surface.

It is a documentation and regression-lock step. It does not add or change
cryptographic runtime code, keys, dependencies, workflows, transaction signing,
transaction broadcasting, wallet custody, or DigiByte consensus.

## Evidence Basis

The Shield side is grounded in the implemented Orchestrator sources:

- `src/shield_orchestrator/v4/crypto_algorithms.py`
- `src/shield_orchestrator/v4/signature_bundle.py`
- `src/shield_orchestrator/v4/key_registry.py`
- `src/shield_orchestrator/v4/oqs_mldsa_backend.py`
- `src/shield_orchestrator/v4/oqs_falcon_backend.py`
- `src/shield_orchestrator/v4/canonical_json.py`

The Q-ID side was checked against the current Q-ID sources:

- `qid/algorithms.py`
- `qid/crypto.py`
- `qid/pqc_backends.py`
- `qid/pqc/pqc_ml_dsa.py`
- `qid/pqc/pqc_falcon.py`
- `qid/canonical_profiles.py`

Naming similarity between those repositories is descriptive only. It does not
create interoperability, trust, or authority.

## Implemented Algorithm and Profile Matrix

### Q-ID identity domain

Q-ID currently exposes these Q-ID-owned public algorithm identifiers:

| Q-ID identifier | Current default runtime mapping | Q-ID meaning |
|---|---|---|
| `dev-hmac-sha256` | deterministic development scaffold | development and CI only |
| `pqc-ml-dsa` | `ML-DSA-44` | Q-ID ML-DSA identity evidence |
| `pqc-falcon` | `Falcon-512` | Q-ID Falcon identity evidence |
| `pqc-hybrid-ml-dsa-falcon` | `ML-DSA-44` plus `Falcon-512` | Q-ID hybrid identity evidence with strict AND semantics |

The legacy Q-ID identifier `hybrid-dev-ml-dsa` is a Q-ID compatibility alias.
It is not a Shield identifier.

Q-ID key-generation helpers may recognize additional liboqs parameter sets.
That crypto-agility does not change the current Q-ID default mappings above and
does not authorize a Q-ID key or signature for any Shield role.

### Shield decision-evidence domain

Shield v4 policy `policy.v1` uses these Shield-owned identifiers and profiles:

| Shield identifier | Policy position | Locked profile and mechanism |
|---|---|---|
| `classical-ed25519` | required | `rfc8032-ed25519-v1`; `Ed25519` |
| `ml-dsa` | required | `fips204-ml-dsa-65-v1`; `ML-DSA-65` |
| `fn-dsa` | optional evidence | `fips206-draft-falcon1024-v1`; `Falcon-1024` |

ML-DSA was formerly called CRYSTALS-Dilithium.

FN-DSA is based on Falcon. It is a separate signature direction from ML-DSA.
The Shield `fn-dsa` path is draft FN-DSA/Falcon-1024 evidence.
It must not be described as final FIPS 206 proof.

## Identifier and Parameter-Set Separation

Q-ID and Shield intentionally do not share algorithm identifiers:

- Q-ID `pqc-ml-dsa` is not Shield `ml-dsa`.
- Q-ID `pqc-falcon` is not Shield `fn-dsa`.
- Q-ID `pqc-hybrid-ml-dsa-falcon` is not a Shield signature bundle policy.

Their current parameter sets also differ:

- Q-ID defaults to `ML-DSA-44`; Shield requires `ML-DSA-65`.
- Q-ID defaults to `Falcon-512`; Shield optional evidence uses `Falcon-1024`.

Parameter-set difference is not the only boundary. Even if a future version
uses the same primitive or parameter set in both repositories, the key role,
key identity, registry, canonical bytes, domain tag, policy, and verifier
authority must still remain separate.

Naming similarity does not authorize key, role, registry, canonicalization,
profile, parameter-set, signature, or authority reuse.

## Key and Trust-Role Separation

Q-ID keys prove Q-ID identity or authentication evidence.

Shield keys prove Shield component verdict evidence or Shield Orchestrator
receipt evidence.

The Shield roles are:

- `shield_component_adn`
- `shield_component_dqsn`
- `shield_component_guardian_wallet`
- `shield_component_qwg`
- `shield_component_sentinel_ai`
- `shield_orchestrator`

A Q-ID identity key must never satisfy a Shield key role.

A Shield key must never satisfy Q-ID identity authority.

A Shield component key must never satisfy the Shield Orchestrator role, and a
Shield Orchestrator key must never satisfy a component role.

No Q-ID key ID, public key container, binding, login proof, identity
attestation, trust-registry entry, or algorithm label is a Shield trust entry.

## Canonicalization Separation

Q-ID owns these named canonical JSON profiles:

- `qid-canonical-json-v1`
- `adamantine-qid-canonical-json-v1`

Shield owns the separate profile:

- `shield-v4-canon.v1`

Q-ID canonical bytes must not be accepted as Shield canonical bytes merely
because both surfaces use deterministic JSON. A profile name, serializer, or
hash match is not key authority and is not signature authority.

Any future bridge must name both sides of a conversion explicitly, validate a
versioned closed contract, and fail closed on profile substitution or mismatch.

## Domain Separation

Shield component verdict evidence uses:

```text
DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1
```

Shield Orchestrator receipt evidence uses:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

Q-ID login, binding, authentication, and identity-attestation signatures are
Q-ID-domain evidence. They must never verify as either Shield evidence type.

A Shield component signature must never verify as an Orchestrator receipt
signature, a Q-ID signature, a transaction signature, or final approval.

## Policy Separation and No-Rescue Rule

Shield `policy.v1` requires both:

- `classical-ed25519`
- `ml-dsa`

Shield `fn-dsa` is optional evidence only. A valid optional signature must
never replace, rescue, downgrade, or override a missing or failed required
signature.

If optional `fn-dsa` evidence is present, it must itself verify under
`fips206-draft-falcon1024-v1`. Malformed, unknown-profile, wrong-role, or invalid
optional evidence fails closed.

Q-ID hybrid strict-AND behavior remains a Q-ID policy. It does not define the
Shield signature policy and cannot satisfy any Shield-required algorithm path.

The verifier-controlled Shield policy is authoritative. Embedded policy data
is signed evidence and cannot weaken that policy.

## Authority Boundary

Shield v4:

- does not sign transactions;
- does not broadcast transactions;
- does not change DigiByte consensus; and
- produces cryptographically verifiable decision evidence only.

Q-ID evidence does not make Shield decisions or grant Shield execution
authority.

Shield evidence does not grant Q-ID identity authority.

AdamantineOS remains the final fail-closed policy and execution boundary. A
Shield signature that verifies against the verifier-controlled Shield registry
proves evidence integrity and the registered Shield role binding; it does not
grant final execution authority.

## Fail-Closed Compatibility Rules

A verifier or future bridge must reject:

- a Q-ID key used for a Shield role;
- a Shield key used for a Q-ID role;
- a Q-ID signature presented as a Shield signature;
- a Shield signature presented as a Q-ID signature;
- implicit translation between Q-ID and Shield algorithm identifiers;
- parameter-set substitution;
- standard-profile substitution;
- canonicalization-profile substitution;
- domain-tag substitution;
- unknown, duplicate, or reordered algorithm entries where order is governed;
- a weaker embedded policy than the verifier-controlled policy;
- missing required Shield algorithm paths;
- optional evidence attempting to rescue a required failure;
- a Q-ID outcome presented as AdamantineOS final approval; and
- a Shield outcome presented as transaction-signing or broadcast authority.

## Proof Boundary

This alignment lock proves that the Orchestrator documentation agrees with the
checked Shield and Q-ID contracts and that the two trust domains remain
explicitly separate.

It does not prove cross-repository runtime interoperability, remote
attestation, producer authenticity, final FIPS 206 conformance, transaction
signing, transaction broadcast, a DigiByte consensus change, or final execution
authority.

Standard CI does not prove live liboqs execution. When green, the Orchestrator's
dedicated `shield-v4-real-oqs.yml` workflow separately proves its guarded
`ML-DSA-65` and `Falcon-1024` test nodes with zero skips, failures, and errors.
This alignment step makes no Q-ID live-liboqs execution claim.
