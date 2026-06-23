# Shield v4 Real Crypto Backend Contract

Author attribution: DarekDGB

## Status

This document locks the Shield v4 real-crypto backend boundary for the Orchestrator.
It is the bridge between the already-tested Shield v4 deterministic contract envelope
and deployment-controlled production cryptographic implementations.

This is not a Shield v4 release gate by itself. It is the adapter contract that must
exist before replacing TEST-ONLY deterministic signatures with real signature
implementations.

## Non-authority lock

Shield v4 cryptography proves Shield decision evidence only.

The Orchestrator still must not:

- sign DigiByte transactions;
- broadcast transactions;
- change DigiByte consensus;
- grant final execution approval;
- bypass AdamantineOS.

AdamantineOS remains the final execution boundary.

## Algorithm lock

Shield v4 policy `policy.v1` uses these names:

- `classical-ed25519` — required classical signature path;
- `ml-dsa` — required PQC path; ML-DSA was formerly CRYSTALS-Dilithium;
- `fn-dsa` — optional evidence path based on Falcon.

`fn-dsa` is not ML-DSA. It must never override failure of the required
`classical-ed25519` or `ml-dsa` paths.

## Backend model

The Orchestrator exposes a backend-neutral adapter contract in:

```text
src/shield_orchestrator/v4/real_crypto_backend.py
```

The adapter does not vendor or import a specific PQC library. Real deployments may
connect liboqs, an HSM, a FIPS-validated module, or another reviewed backend through
the same interface.

This keeps CI deterministic and prevents local machine state from silently changing
Shield v4 verification results.

## Frozen real-signature input

Every real signature signs the exact byte string:

```text
DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT
<domain_tag>
<signed_payload_hash>
<algorithm>
<key_id>
<key_version>
```

Rules:

- UTF-8 encoding only;
- line separator is LF (`\n`);
- no trailing newline;
- `signed_payload_hash` must be lowercase SHA-256 hex;
- `domain_tag` must be one of the frozen Shield v4 signing domains;
- `algorithm`, `key_id`, and `key_version` must match the trust registry entry.

The `signed_payload_hash` is already computed over the domain-separated canonical
payload. The real-signature input binds that hash to the concrete signature entry so
signatures cannot be spliced across algorithms, keys, or bundles.

## Test-only material rejection

The real-crypto adapter must reject deterministic test material before calling a
production backend.

Rejected examples include:

- key ids beginning with `test-`;
- public keys containing `TEST-ONLY`;
- private key references containing `test-only` or beginning with `test-`.

There is no automatic fallback from real backend mode to TEST-ONLY deterministic
HMAC signatures.

## Signing and verification boundary

The Orchestrator may use the real backend to:

- verify signed component verdict evidence;
- sign the final Shield v4 Orchestrator receipt evidence.

The Orchestrator still cannot sign transactions or broadcast. The final receipt is
cryptographically verifiable evidence for AdamantineOS, not final execution approval.

## Third-party attribution

When a real backend is selected, repository-level attribution belongs in:

```text
THIRD_PARTY_NOTICES.md
```

The notice must identify the backend family, clarify that no third-party PQC source is
vendored unless explicitly stated, and keep author attribution as DarekDGB.
