# Third-Party Notices

Author attribution: DarekDGB

This repository, **DGB Quantum Shield Orchestrator**, is licensed under the MIT
License.

It may optionally interface with third-party open-source cryptographic libraries for
Shield v4 PQC-ready signature verification and receipt signing. No third-party PQC
source code is vendored into this repository unless explicitly stated.

## Open Quantum Safe / liboqs

Open Quantum Safe / liboqs is an allowed backend family for deployment-controlled
Shield v4 PQC implementations.

Purpose:

- ML-DSA, formerly CRYSTALS-Dilithium;
- FN-DSA, based on Falcon, as optional evidence only.

The Orchestrator repository does not vendor liboqs source code in this step. If an
integrator compiles, links, or deploys liboqs or a wrapper, that integrator must review
and comply with the licenses of the exact backend artifacts used in that environment.

## Classical signature backend

Shield v4 policy `policy.v1` also requires a classical `classical-ed25519` path.
The concrete Ed25519 backend is deployment controlled unless a future repository step
adds a pinned dependency.

## Usage clarification

- This repository defines Shield v4 contracts, canonicalization, trust-registry rules,
  and real-crypto adapter boundaries.
- Cryptographic backends are pluggable and deployment controlled.
- No PQC implementation is embedded directly in this codebase by this notice.
- Test-only deterministic signatures are not production cryptography.

## No endorsement

Reference to third-party projects does not imply endorsement. All trademarks and
project names remain the property of their respective owners.

Copyright (c) 2025
Author: DarekDGB
License: MIT
