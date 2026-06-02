# Changelog

## v3.1.0 — Shield Orchestrator Foundation Hardening

Shield v3.1.0 foundation-hardening release for the DigiByte Quantum Shield Orchestrator.

- Updates package metadata to `3.1.0`
- Aligns release-facing documentation to the Shield v3.1.0 foundation-hardening track
- Confirms 100% full `shield_orchestrator` package coverage in CI
- Preserves deterministic orchestration and fail-closed behavior
- Preserves Adaptive Core as a read-only sink with no outcome authority
- Clarifies that this release does not introduce a new Shield contract version
- Defers manifest / verdict / receipt / proof-pack hardening to the next Shield roadmap phase

CI proof:

```text
17 passed
248 statements
0 missed
100% coverage
Required test coverage of 100% reached.
```

Boundary:

This release is foundation hardening only. It preserves Shield Contract v3 behavior and does not implement the later manifest / verdict / receipt / proof-pack hardening layer.

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
