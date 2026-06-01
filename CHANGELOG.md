# Changelog

## v3.0.0 — Shield Orchestrator Stabilisation

Stabilised Shield Contract v3 orchestrator release.

- Locks package version to `3.0.0`
- Enforces 100% full `shield_orchestrator` package coverage in CI
- Adds v3 full coverage lock tests for fail-closed and error-path behaviour
- Adds packaged typing marker
- Confirms deterministic orchestration behaviour under CI
- Preserves Adaptive Core as a read-only sink with no outcome authority

CI proof:

```text
17 passed
248 statements
0 missed
100% coverage
Required test coverage of 100% reached.
```
