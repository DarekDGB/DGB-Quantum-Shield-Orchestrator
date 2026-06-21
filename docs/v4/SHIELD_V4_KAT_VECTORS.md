# Shield v4 Known-Answer Test Vectors

Author attribution: DarekDGB

## Status

This document records the first frozen Shield v4 Orchestrator Known-Answer Test vector created during V4.3.

The vector is TEST-ONLY. It does not contain production private keys. It does not claim production ML-DSA or FN-DSA cryptography. It freezes the Shield v4 contract envelope, canonical bytes, hash binding, key-role binding, policy binding, and fail-closed verification shape.

## Vector Location

```text
tests/fixtures/v4/orchestrator_receipt_policy_v1_kat.json
```

## Frozen Values

Receipt hash:

```text
4dcf7fc66317e8f06fbd24edf8c839a7ddf0d38b88b70af321cc7732d0ab46f5
```

Signed payload hash:

```text
d4e4c277f99e9320a27a3502e3b26196638c1e4d8bdf5dcee0ad533559240ca3
```

Domain tag:

```text
DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1
```

Canonicalization profile:

```text
shield-v4-canon.v1
```

Signature policy:

```text
policy.v1
```

Required algorithm paths:

```text
classical-ed25519
ml-dsa
```

Optional evidence path:

```text
fn-dsa
```

## Important Algorithm Wording

ML-DSA means ML-DSA, formerly CRYSTALS-Dilithium.

FN-DSA means FN-DSA, based on Falcon.

FN-DSA is not ML-DSA and cannot satisfy the ML-DSA requirement.

## Authority Boundary

Passing this KAT proves only that an implementation agrees with the Shield v4 test vector.

It does not grant transaction-signing authority.

It does not grant broadcast authority.

It does not change DigiByte consensus.

It does not bypass AdamantineOS.

AdamantineOS remains the final execution boundary.
