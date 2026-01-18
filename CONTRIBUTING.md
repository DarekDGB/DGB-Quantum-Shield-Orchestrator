# Contributing to DGB Quantum Shield Orchestrator

The **DigiByte Quantum Shield Orchestrator** is the **v3 coordination layer**
of the DigiByte Quantum Shield.

This repository is responsible for:
- deterministically invoking Shield Contract v3 components
- enforcing strict evaluation order
- synthesizing a single, fail-closed security envelope
- forwarding results to Adaptive Core as a **read-only sink**

It does **not** implement security logic itself.

Contributions must preserve this role:
**orchestration, coordination, and contract enforcement only.**

---

## 🧭 Scope of This Repository

This project coordinates the following **external Shield v3 components**:

- Sentinel (v3) — signal emission
- DQSN (v3) — network aggregation
- ADN (v3) — defensive state signaling
- Guardian Wallet (v3) — wallet-level enforcement
- QWG (v3) — cryptographic / PQC guardrails
- Adaptive Core (v3) — read-only intelligence & reporting

These components live in **their own repositories**.
This project only connects them via **explicit, deterministic bridges**.

---

## ✅ What Contributions Are Welcome

### ✔️ 1. Bridge Improvements
Improvements to adapters under:

```
src/shield_orchestrator/bridges/
```

Examples:
- clearer v3 contract usage
- stricter input validation
- better trace or context propagation
- safer error handling (always fail-closed)

Bridges must:
- never make allow / deny decisions
- never modify global state
- never escalate authority

---

### ✔️ 2. Orchestration & Contract Logic
Enhancements to:

```
src/shield_orchestrator/v3/
```

Examples:
- stricter request validation
- clearer trace semantics
- improved determinism guarantees
- additional fail-closed reason mappings

All changes must respect:
- deny-by-default behavior
- deterministic execution
- contract version discipline

---

### ✔️ 3. Testing & Verification
Improvements to:

```
tests/
```

Examples:
- negative-first tests
- missing-component scenarios
- hashing and serialization failures
- determinism regression tests

Tests are **authoritative**:
if behavior is not test-covered, it is not considered stable.

---

### ✔️ 4. Documentation
Updates to:
- README.md
- SECURITY.md
- docs/ (v3 only)

Docs must describe **what exists today**, not speculative future systems.

Legacy or historical material belongs in `docs/legacy/`.

---

## ❌ What Will NOT Be Accepted

### 🚫 1. Moving Layer Logic Into the Orchestrator
This repository must **never** implement or duplicate:

- Sentinel analytics
- DQSN aggregation logic
- ADN defense logic
- QWG cryptographic checks
- Guardian Wallet UX or policy logic
- Adaptive Core learning or decision-making

Those belong to their respective repositories.

---

### 🚫 2. Policy or Authority Escalation
The orchestrator must **not**:
- introduce implicit allow paths
- override downstream components
- auto-upgrade or self-modify behavior
- make autonomous security decisions

All outcomes must remain **fail-closed** unless explicitly extended by versioned design.

---

### 🚫 3. Consensus or Protocol Changes
This project must **never**:
- alter DigiByte consensus rules
- modify block, mempool, or validation logic
- act as governance or validator software

It is strictly **coordination-layer software**.

---

### 🚫 4. Non-Deterministic Behavior
Rejected changes include:
- time-based logic
- randomness
- order-dependent execution
- hidden configuration toggles

Determinism is a core invariant.

---

## 🧱 Design Principles (Non-Negotiable)

1. **Deny-by-Default**  
   Any ambiguity or failure results in `DENY`.

2. **Deterministic Execution**  
   Same input → same output → same hash.

3. **Explicit Contracts**  
   Interfaces are versioned, documented, and test-locked.

4. **No Hidden Authority**  
   No backdoors, overrides, or escape hatches.

5. **Separation of Concerns**  
   Orchestration here, logic elsewhere.

6. **Auditability**  
   All behavior must be explainable via trace output.

---

## 🔄 Pull Request Expectations

A good PR must:
- clearly describe intent and scope
- reference relevant v3 docs or contracts
- include tests for any behavioral change
- preserve folder structure and contracts
- avoid speculative or future-facing logic

The maintainer (**@DarekDGB**) reviews:
- architectural fit
- security invariants
- contract discipline

CI must be green for review.

---

## 📝 License

By contributing, you agree that your contributions are licensed under the MIT License.

© 2025 **DarekDGB**
