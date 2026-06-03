# AdamantineOS Handoff Contract — Shield v3.2.0

Author attribution: DarekDGB

## Non-Negotiable Boundary

AdamantineOS consumes Shield only through one deterministic Orchestrator receipt.

Raw component verdicts are evidence for the Orchestrator only.

Raw component verdicts are not AdamantineOS execution authority.

---

## Handoff Rules

AdamantineOS must reject:

- missing receipt
- malformed receipt
- unknown receipt schema
- unsupported contract version
- context hash mismatch
- receipt hash mismatch
- tampered receipt content
- Shield `DENY` with handoff allowed
- Shield `HUMAN_REVIEW_REQUIRED` with autonomous handoff allowed
- direct `shield.verdict.v1` component payloads
- raw Guardian Wallet outputs as final authority
- raw QWG outputs as final authority
- raw ADN outputs as final authority
- raw DQSN outputs as final authority
- raw Sentinel AI outputs as final authority

Shield `ALLOW` only permits AdamantineOS to continue to its own checks.

Shield `ALLOW` is never automatic final signing or execution authority.

---

## Freshness / Replay Boundary

Shield v3.2.0 receipts bind to exact `context_hash`.

A receipt from one context must not be reused in another context.

Stateful replay protection belongs at the AdamantineOS execution boundary through its nonce / replay protection system.

The Shield Orchestrator does not store mutable replay state.

AdamantineOS must continue to enforce its own replay, nonce, policy, WSQK, and execution checks after validating a Shield receipt.

---

## AI Safety Boundary

AI output is evidence only.

AI cannot:

- sign
- approve
- override DENY
- bypass human review
- create missing Shield evidence silently
- act as final AdamantineOS authority

---

## Governance Boundary

Human approval must bind to the exact execution context.

Shield v3.2.0 does not define an emergency governance override path.

No human approval, AI output, or component verdict may override a Shield DENY unless a future explicit governance contract is documented, tested, and versioned.

---

## Critical Statement

Shield can permit AdamantineOS to continue evaluating.

Shield does not grant final execution authority by itself.
