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

The neutral adapter does not require a specific PQC library. Real deployments may
connect liboqs, an HSM, a FIPS-validated module, or another reviewed backend through
the same interface.

The optional OQS ML-DSA backend lives in:

```text
src/shield_orchestrator/v4/oqs_mldsa_backend.py
```

It lazily imports `oqs` only when used, so normal CI and non-OQS deployments do not
silently depend on local machine crypto state. If OQS is missing, disabled, or lacks
the locked mechanism, the backend fails closed.

## OQS ML-DSA mapping

For Shield v4 `policy.v1`, the optional OQS backend maps:

```text
Shield algorithm: ml-dsa
OQS mechanism:    ML-DSA-65
```

The mechanism is deliberately locked for this backend. A caller cannot silently swap
`ML-DSA-44`, `ML-DSA-87`, Falcon/FN-DSA, or another mechanism behind the Shield
policy name.

## CI proof levels and gated real-liboqs job

Default package CI proves the real-backend adapter interface, binary-material parsing,
fail-closed exception hierarchy, bundle binding, and cross-repo wiring with deterministic
backends. That default CI does not claim to execute live liboqs ML-DSA.

Live liboqs ML-DSA proof is intentionally optional and gated so normal CI does not gain a
hard OQS/liboqs dependency. The dedicated job must set `SHIELD_V4_REAL_OQS=1`, install
`oqs`/liboqs, write a JUnit report, disable default coverage addopts for the focused gated job, and run the not-skipped guard:

```text
SHIELD_V4_REAL_OQS=1 python -m pytest \
  tests/test_v48g_real_oqs_mldsa_backend.py \
  --override-ini addopts='' \
  --junitxml=.artifacts/v48g-real-oqs.xml
python scripts/assert_real_oqs_junit_not_skipped.py .artifacts/v48g-real-oqs.xml
```

The guard fails if the real-OQS job collects zero tests, skips any testcase, or records any
failure/error. A public claim that live liboqs ML-DSA verified through this backend requires
that gated job to pass with `skipped == 0`; release-grade real-backend proof remains a
V4.10 release gate.

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

## Binary encoding lock

Real ML-DSA signatures and public keys are binary. Shield v4 real backend adapters use
explicit unpadded base64url encoding with the prefix:

```text
b64u:<unpadded-base64url-bytes>
```

Rules:

- real binary signatures use `b64u:`;
- real OQS public keys use `b64u:` in the trust registry;
- padding characters (`=`) are rejected;
- malformed base64url is rejected before calling a crypto backend;
- historical 64-character deterministic test digests remain test fixtures only.

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
