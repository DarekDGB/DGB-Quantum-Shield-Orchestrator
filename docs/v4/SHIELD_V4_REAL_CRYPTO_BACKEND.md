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

- `classical-ed25519` - required classical signature path;
- `ml-dsa` - required PQC path; ML-DSA was formerly CRYSTALS-Dilithium;
- `fn-dsa` - optional evidence path based on Falcon.

`fn-dsa` is not ML-DSA. It must never override failure of the required
`classical-ed25519` or `ml-dsa` paths.

V4.8H selects Falcon-1024 for the draft FN-DSA profile:

```text
Shield algorithm: fn-dsa
Standard profile: fips206-draft-falcon1024-v1
Falcon parameter set: Falcon-1024
Security level note: Falcon-1024 is NIST security level 5; ML-DSA-65 remains the required level-3 PQC path.
```

The FN-DSA profile is optional additional evidence only. It is draft-profile
crypto-agility evidence and must not be described as final FIPS 206 production
proof until final FIPS 206 support is separately integrated and tested.

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

## OQS Falcon-1024 mapping

V4.8H-E adds an optional OQS backend for live FN-DSA draft-profile evidence:

```text
src/shield_orchestrator/v4/oqs_falcon_backend.py
tests/test_v48h_e_oqs_falcon_backend.py
tests/test_v48h_e_real_oqs_falcon_backend.py
```

The backend mapping is locked as:

```text
Shield algorithm: fn-dsa
standard_profile: fips206-draft-falcon1024-v1
OQS mechanism:    Falcon-1024
```

This is optional hybrid evidence only. It does not make FN-DSA required, does not rescue failed `classical-ed25519` or `ml-dsa`, does not sign transactions, does not broadcast, and does not change DigiByte consensus. It is draft Falcon-1024 profile evidence only, not a final FIPS 206 production claim.

## CI proof levels and gated real-liboqs job

Default package CI proves the real-backend adapter interface, binary-material parsing,
fail-closed exception hierarchy, bundle binding, and cross-repo wiring with deterministic
backends. That default CI does not claim to execute live liboqs ML-DSA or live Falcon-1024.

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

V4.8H-E extends the dedicated PQC workflow so it sets both `SHIELD_V4_REAL_OQS=1` and `SHIELD_V4_REAL_OQS_FALCON=1`, then runs the ML-DSA proof and the Falcon-1024 proof in the same guarded JUnit report:

```text
python -m pytest --override-ini addopts='' \
  tests/test_v48g_real_oqs_mldsa_backend.py \
  tests/test_v48h_e_real_oqs_falcon_backend.py \
  -q --junitxml=shield-v4-real-oqs-results.xml
python scripts/assert_real_oqs_junit_not_skipped.py shield-v4-real-oqs-results.xml
```

A public live Falcon-1024 Orchestrator claim requires that dedicated workflow to finish green with `skipped == 0`, `failures == 0`, and `errors == 0` for the guarded report.

### V4.10-I1 immutable source and retained-evidence pilot

The Orchestrator pilot pins the matching upstream 0.16.0 release sources by
full commit identity, rather than fetching a moving default branch:

| Dependency | Release label | Immutable source commit |
|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs/commit/5a1a854b0dc9f2141bdc771c555ee60c37950183) | 0.16.0 | `5a1a854b0dc9f2141bdc771c555ee60c37950183` |
| [liboqs-python](https://github.com/open-quantum-safe/liboqs-python/commit/c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061) | 0.16.0 | `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061` |

The workflow checks each fetched HEAD, builds liboqs outside the repository,
and installs into a dedicated temporary prefix. It builds the wrapper wheel
from the pinned source with build isolation disabled, installs that wheel
without index resolution, checks the installed wrapper bytes, and records
the built wheel and loaded shared-library hashes. The expected shared library
must load before the wrapper import; the wrapper must use that same handle.
The job also checks versions and both required mechanisms before collecting
the proof tests. A missing provider cannot silently become an auto-installed
replacement for this proof.

The existing two native test functions and runtime backend bytes are unchanged.
The final report guard now uses this exact allow-list:

```text
python scripts/assert_real_oqs_junit_not_skipped.py artifacts/real-oqs/shield-v4-real-oqs-results.xml \
  --min-tests 2 --exact-tests 2 \
  --require-testcase "tests/test_v48g_real_oqs_mldsa_backend.py::test_v48g_real_oqs_mldsa65_orchestrator_backend_round_trip_and_negatives" \
  --require-testcase "tests/test_v48h_e_real_oqs_falcon_backend.py::test_v48h_e_real_oqs_falcon1024_backend_round_trip_and_negatives"
```

The guard reconciles JUnit counters against actual testcase outcomes. Exact
mode rejects extra, missing, duplicated, ambiguous, or conflicting node
identities. Malformed, nested, missing, oversized, or inconsistent reports
fail closed. Summary counters alone cannot hide a child failure, error, or
skip. Legacy minimum-count invocation remains available, with the same
counter/outcome consistency checks.

Each run retains `shield-v4-real-oqs-<commit>-<attempt>` for 90 days. The artifact
contains JUnit XML, collection output, pytest and guard logs, environment and
source identities, source-archive digests, build/install logs, CMake cache,
the wrapper wheel, the loaded native library digest, and self-excluding SHA256SUMS.
Artifacts from a failed job are diagnostic evidence only. Release evidence
requires the exact commit's entire workflow to succeed, the exact two nodes
to pass with zero skips/failures/errors, and retained artifact/hash review.
Download the artifact before retention expires and preserve it with the final
proof pack; recording a hash alone does not preserve its bytes.

The workflow's three Actions use full commit pins; the runner family is
ubuntu-24.04 and CPython is 3.11.15. Direct Python build/test tool versions are
selected explicitly, while transitive dependencies and operating-system build
packages are recorded rather than fully locked. This is an immutable native
source proof, not a bit-for-bit reproducible operating-system image claim.

I1 remains a prepared pilot until its post-commit workflows, retained native
artifact, and fresh ZIP are verified. The other six repositories require
separate I follow-up. Test keys and this evidence do not prove production
custody, FIPS validation, or final FIPS 206 support.

## Frozen real-signature input

Every real signature signs the exact byte string:

```text
DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT
<domain_tag>
<signed_payload_hash>
<algorithm>
<standard_profile>
<key_id>
<key_version>
```

Rules:

- UTF-8 encoding only;
- line separator is LF (`\n`);
- no trailing newline;
- `signed_payload_hash` must be lowercase SHA-256 hex;
- `domain_tag` must be one of the frozen Shield v4 signing domains;
- `standard_profile` must be allow-listed for the selected algorithm;
- `algorithm`, `key_id`, and `key_version` must match the trust registry entry.

The `signed_payload_hash` is already computed over the domain-separated canonical
payload. The real-signature input binds that hash to the concrete signature entry so
signatures cannot be spliced across algorithms, keys, profiles, or bundles. A
signature over `fn-dsa` profile `fips206-draft-falcon1024-v1` must not be silently
reinterpreted as Falcon-512 or any future final FIPS 206 profile.

## Binary encoding lock

Real ML-DSA and FN-DSA/Falcon signatures and public keys are binary. Shield v4 real
backend adapters use explicit unpadded base64url encoding with the prefix:

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
