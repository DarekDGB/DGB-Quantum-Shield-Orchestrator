# Shield v4.0.0 Orchestrator Release Status

Author attribution: DarekDGB

```text
Status: CONTROLLED PRE-RELEASE
Release decision: NOT YET AUTHORIZED
Distribution version: 4.0.0
Candidate tag: v4.0.0
Tag created: no
```

## Current decision

The Orchestrator distribution metadata is aligned to `4.0.0` so the final
release documents and downstream release pack can be evaluated against one
candidate version. This is not a release announcement and does not authorize
creation or movement of `v4.0.0`.

Only DarekDGB may authorize the final tag action after all V4.10 release gates
are complete.

## Completed controlled stages

- V4.10-A authenticated the all-repository source inventory and public claim
  matrix.
- V4.10-B added the privacy-safe append-only verification audit and exact
  durable acknowledgement boundary.
- V4.10-C added bounded six-bundle verification, callback ceilings, pinned
  performance/DoS evidence, and completed exact-commit standard, live,
  performance, real-OQS, and fresh-ZIP verification.
- V4.10-D was subsequently verified at Orchestrator commit
  `66818bbce884309076a27535f1a02d9696d1054e`.
- V4.10-E through H were verified in living roadmap R2.50. H uses explicit
  equivalent standard-CI reports and separates remote observations from
  local collection/skip reconstruction; it is not native-OQS proof.

The authenticated V4.10-C Orchestrator evidence base is commit
`d4d4f7338b4109d4914bf6861b62a8e9e2dfd0f5` and fresh-ZIP SHA-256
`889ed72fc515e51364af3698921083e51408daa537c38b8e897b5584b6d6d100`.

## V4.10-D candidate scope

V4.10-D aligns the Orchestrator package and public candidate version, adds the
final v4 test matrix and proof pack, historicizes contradictory v3.2.0
pending-tag wording, and aligns README, changelog, security, and contribution
guidance.

V4.10-D's post-commit workflows and fresh-ZIP gate are complete. Its historical
package changed no runtime verifier, protocol, schema, KAT, external package
manifest, workflow, fixture, or cryptographic key material.

The current V4.10-I1 Orchestrator pilot changes the dedicated native workflow,
JUnit guard, guard/workflow regression tests, and related documentation. It
pins both native dependency sources, checks the loaded provider, and retains
proof artifacts. Runtime, native proof tests, protocols, fixture bytes, and
distribution metadata remain unchanged. I1 is prepared, not post-commit
verified; it does not close I for the seven repositories or authorize a tag.

## Frozen algorithm policy

`policy.v1` requires:

```text
classical-ed25519
ml-dsa
```

Optional `fn-dsa` may be absent. If present, it must appear last, use
`fips206-draft-falcon1024-v1`, and verify. It cannot replace or rescue either
required path. The Falcon-1024 profile is draft evidence, not final FIPS 206
proof.

## Authority boundary

The Orchestrator verifies and signs Shield decision evidence. It does not sign
or broadcast transactions, hold wallet private keys, change DigiByte
consensus, grant final approval, or override AdamantineOS.

AdamantineOS remains the final fail-closed policy and execution boundary.

## Remaining V4.10 stages

- V4.10-E: five-component release-pack alignment, verified complete;
- V4.10-F: AdamantineOS final verifier proof pack, verified complete;
- V4.10-G: compatibility-repository release truth, verified complete;
- V4.10-H: final standard-CI evidence matrix, complete for the R2.50 snapshot;
- V4.10-I: final live-OQS evidence matrix, Orchestrator I1 pilot prepared;
- V4.10-J: final negative matrix and adversarial audit;
- V4.10-K: final hashes, attribution, and fresh-ZIP lock; and
- V4.10-L: final release decision.

I-L remain incomplete. An I1 commit requires refreshing the Orchestrator H row;
the other nine H rows remain tied to their unchanged authenticated commits.

## Disclosed residuals

- The other six native workflows still fetch moving liboqs/liboqs-python
  branches; the Orchestrator I1 candidate pins both immutable release commits.
- Standard/live workflows retain mutable major action tags, and live component
  checkouts are not immutable. The I1 native Actions are pinned, but its OS
  build packages and all transitive Python dependencies are not fully locked.
- Standard CI enforces statement coverage rather than branch coverage.
- I1 configures native retention for 90 days. Its successful post-commit
  artifact must still be downloaded and audited; no future artifact hash is
  asserted. Other workflow retention gaps remain visible.
- Native OQS evidence uses test keys and does not prove production-key or HSM
  assurance.
- The pinned structural benchmark excludes provider cryptographic latency.
- FN-DSA/Falcon-1024 remains a draft-profile path.

These residuals must remain visible to the final release decision.

## Tag rule

Do not create or move `v4.0.0` based on this candidate status. The only valid
release authorization is an explicit DarekDGB decision after V4.10-L.
