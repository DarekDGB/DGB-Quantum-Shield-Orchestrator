# Security Policy — DigiByte Quantum Shield Orchestrator

**Repository:** DGB-Quantum-Shield-Orchestrator  
**Component:** Shield Orchestrator v3.2 — Deterministic Receipt Boundary  
**Maintainer:** DarekDGB  
**License:** MIT

This document defines the security policy and disclosure process for the DigiByte Quantum Shield Orchestrator, with a focus on the **Shield v3.2.0 receipt boundary**.

---

## Supported Versions

Only the current Shield v3 Orchestrator surface is supported and security-maintained for new Shield work.

| Component | Status |
|---|---|
| Orchestrator v3.2.0 | ✅ Supported — current receipt-boundary hardening surface |
| Orchestrator v3.1.0 | ✅ Previous foundation-hardening baseline |
| Older archived behavior | ❌ Unsupported |

Legacy documentation may remain in the repository for historical reference, but it is **non-authoritative** for v3.2.0 security behavior.

---

## Security Model

The Shield Orchestrator is a **deterministic, fail-closed aggregation and receipt boundary**.

Security is enforced through:

- strict component verdict validation
- deterministic aggregation
- stable reason codes
- stable evidence families
- canonical context hashing
- canonical receipt hashing
- fail-closed behavior
- no hidden authority
- tests for receipt construction and validation

The Orchestrator is **consensus-neutral**.

It does not:

- alter DigiByte consensus rules
- sign transactions
- broadcast transactions
- hold, derive, or access private keys
- perform final AdamantineOS execution approval

The Orchestrator produces the Shield receipt only.

AdamantineOS remains responsible for its own final checks and execution rules.

---

## Non-Negotiable Design Invariants

### 1. Fail-Closed by Default

Any invalid, ambiguous, incomplete, unsafe, or malformed input must produce an explicit rejection path.

Expected fail-closed behavior includes:

- deterministic reject outcome
- explicit reason code
- no silent fallback
- no implicit allow
- no authority escalation

### 2. Determinism

The same valid input must always produce the same receipt.

Contract behavior must not depend on:

- timestamps
- randomness
- environment state
- network state
- file-system state
- dictionary iteration order
- runtime-dependent side effects

Canonical hashes must be reproducible.

### 3. Single Receipt Authority

The Orchestrator may:

- consume component verdict evidence
- validate component identity and contract version
- aggregate component evidence
- produce deterministic Shield receipts
- hand one Shield receipt to AdamantineOS

The Orchestrator must never:

- treat raw component output as final execution approval
- allow component-level bypass into AdamantineOS
- execute cryptographic signing
- modify consensus behavior
- override AdamantineOS final checks
- create hidden authority through fallback behavior

### 4. No Silent Fallbacks

All error paths must be explicit, deterministic, and test-covered.

A fallback that changes authority, weakens validation, or allows execution is a security defect.

---

## v3.2.0 Security Boundary

The v3.2.0 boundary locks the Orchestrator into the Shield manifest / verdict / receipt upgrade path.

Component verdicts are **evidence only**.

The Orchestrator receipt is the only valid Shield handoff artifact for AdamantineOS.

AdamantineOS must not consume raw component outputs directly as final signing, execution, or approval authority.

A Shield `ALLOW` result only permits AdamantineOS to continue its own checks.

It is **not** final signing or execution approval.

---

## Fail-Closed Requirements

The following conditions must reject deterministically:

- missing required receipt data
- malformed receipt data
- missing component verdict data
- malformed component verdict data
- unknown component identity
- duplicated component verdicts
- duplicated authority claims
- unknown reason IDs
- unknown evidence families
- mismatched component identity
- mismatched contract version
- mismatched context hash
- unsafe or unserialisable input
- non-canonical verdict data
- non-canonical receipt data
- ambiguity affecting authority, determinism, or auditability

---

## Security Testing

Security guarantees are enforced through tests covering:

- fail-closed behavior
- deterministic orchestration behavior
- unsupported contract versions
- reason-code stability
- evidence-family validation
- component verdict validation
- canonical receipt construction
- canonical receipt hash stability
- malformed receipt rejection
- duplicate component verdict rejection
- AdamantineOS handoff boundary assumptions
- regression protection against behavior drift

Security-sensitive changes must include tests.

Tests define truth.

Documentation must never claim behavior that tests do not enforce.

---

## Release Requirements

No Orchestrator v3.2.0 release should be tagged unless all of the following are true:

- roadmap checklist is complete
- tests pass locally or in CI
- coverage gate remains at 100%
- manifest files are present and aligned
- reason IDs are documented and tested
- evidence families are documented and tested
- receipt boundary tests pass
- AdamantineOS handoff boundary is respected
- final fresh ZIP audit is complete
- Red Team report is complete
- no docs-vs-tests mismatch remains

---

## Reporting a Vulnerability

If you believe you have found a security issue:

1. Do **not** disclose it publicly first.
2. Open a private security advisory through GitHub if available.
3. Alternatively, contact the maintainer through the GitHub profile: **@DarekDGB**.

Please include:

- clear description of the issue
- steps to reproduce, if applicable
- expected behavior
- actual behavior
- affected commit hash or tag
- potential security impact

Coordinated disclosure is strongly encouraged.

---

## In Scope

Security issues in scope include:

- Orchestrator receipt construction behavior
- determinism violations
- fail-closed bypasses
- reason ID ambiguity
- evidence-family ambiguity
- manifest/verdict/receipt mismatch
- context hash mismatch
- component verdict bypass risk
- AdamantineOS raw-output bypass risk
- CI or test coverage gaps affecting security

---

## Out of Scope

The following are out of scope unless they create a direct security defect:

- DigiByte consensus vulnerabilities
- mining-layer issues
- wallet UI preferences
- performance tuning
- cosmetic documentation changes
- non-security refactors
- unsupported archived behavior

---

## Security Updates

Security fixes may:

- tighten validation
- improve fail-closed behavior
- add negative tests
- update documentation
- clarify reason IDs or evidence families
- strengthen receipt validation

Breaking changes to security semantics require:

- documentation updates
- explicit version notes
- regression tests
- coverage proof

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind.

Use at your own risk.

---

## Final Security Rule

Any change that weakens determinism, fail-closed behavior, explicit authority boundaries, component-evidence-only behavior, or the single Orchestrator receipt model must be rejected.

© 2025 DarekDGB
