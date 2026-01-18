# DigiByte Quantum Shield Orchestrator (v3)

![CI](https://github.com/DarekDGB/DGB-Quantum-Shield-Orchestrator/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)
![License](https://img.shields.io/github/license/DarekDGB/DGB-Quantum-Shield-Orchestrator)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

**Shield Contract v3 • Deterministic Orchestration • Fail-Closed Security**

The **DigiByte Quantum Shield Orchestrator** is the **v3 coordination layer**
that deterministically connects all DigiByte Quantum Shield components and
forwards the final security envelope to **Adaptive Core v3** as a read-only sink.

It produces a **single deterministic v3 envelope** that downstream callers
(such as **Adamantine Wallet OS**) can treat as the authoritative shield result.

> Orchestrator v3 coordinates and aggregates.  
> It does **not** sign, broadcast, hold keys, or mutate state.

---

## Core Properties

- **Contract v3 only** (any other version → fail-closed)
- **Deterministic & replayable** (same input → same output → same `context_hash`)
- **Fail-closed** (no silent defaults, no best-effort behavior)
- **Strict canonicalization** (stable JSON → stable hashing)
- **No hidden authority** (aggregation only, never escalation)
- **Fully traceable** (component-by-component execution trace)

---

## High-Level Architecture

```
┌─────────────────────┐
│ Adamantine Wallet OS│
└─────────┬───────────┘
          │ OrchestratorV3Request
          ▼
┌────────────────────────────────────┐
│  Quantum Shield Orchestrator (v3)   │
│  - strict validation                │
│  - deterministic ordering           │
│  - deny-by-default synthesis        │
└─────────┬───────────┬──────────────┘
          │           │
          │           │ read-only report
          │           ▼
          │   ┌──────────────────┐
          │   │ Adaptive Core v3 │
          │   │ (no authority)   │
          │   └──────────────────┘
          │
          ▼
┌────────────────────────────────────┐
│ Shield Contract v3 Components       │
│                                    │
│  1. Sentinel AI v3                 │
│  2. DQSN v3                        │
│  3. ADN v3                         │
│  4. Guardian Wallet v3             │
│  5. QWG v3                         │
└────────────────────────────────────┘

Final output:
→ OrchestratorV3Response (single deterministic envelope)
```

---

## Role in the DigiByte Quantum Shield

Adamantine Wallet OS  
→ **Orchestrator v3**  
→ Sentinel AI v3  
→ DQSN v3  
→ ADN v3  
→ Guardian Wallet v3  
→ QWG v3  

Signals are aggregated and returned through the Orchestrator
as a **single Shield Contract v3 envelope**.

**Adaptive Core v3** receives reports only.
It cannot influence outcomes or execution.

---

## What Orchestrator v3 Produces

A single **v3 response envelope** containing:

- `contract_version = 3`
- deterministic `context_hash`
- final `outcome` (`DENY` by default)
- stable `reason_ids`
- full deterministic execution trace
- canonical JSON suitable for audit and replay

---

## What Orchestrator v3 Does NOT Do

- hold private keys or secrets
- sign or broadcast transactions
- modify wallet or node state
- guess missing fields
- auto-upgrade layers
- bypass Guardian / QWG / WSQK / EQC rules
- execute consensus or governance logic

---

## Documentation (v3)

Authoritative documentation lives under:

```
docs/v3/
```

- INDEX.md
- CONTRACT.md
- ARCHITECTURE.md
- API.md
- REASON_IDS.md

Legacy material is preserved under:

```
docs/legacy/
```

If documentation and code diverge, **contracts and tests win**.

---

## Quality & Verification

- CI enforced
- ≥90% test coverage
- deterministic tests only
- negative-first testing
- fail-closed on all errors

---

## License

MIT License © 2025 **DarekDGB**
