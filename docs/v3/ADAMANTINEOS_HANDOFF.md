# AdamantineOS Handoff Contract — Shield v3.2.0

Author attribution: DarekDGB

## Non-Negotiable Boundary

AdamantineOS consumes Shield only through one deterministic Orchestrator receipt.

Raw component verdicts are evidence for the Orchestrator only. They are not an AdamantineOS execution authority.

## Handoff Rules

- Missing receipt = reject.
- Malformed receipt = reject.
- Context mismatch = reject.
- Unknown receipt schema = reject.
- Shield `DENY` = reject.
- Shield `HUMAN_REVIEW_REQUIRED` = no autonomous execution.
- Shield `ALLOW` only permits AdamantineOS to continue to its own checks.

Critical statement:

> Shield can permit AdamantineOS to continue evaluating. Shield does not grant final execution authority by itself.
