# Shield Orchestrator — Legacy Design v2 Archive

Author attribution: **DarekDGB**  
License: MIT

---

## Status

This document is an archived v2 design note. It is not the live Shield handoff contract.

The legacy `FullShieldPipeline.process_event()` / `BaseLayer.process()` path is disabled in code because it is not a fail-closed v3.2 receipt path. It must not be used by wallet integrations, AdamantineOS integrations, or production callers.

The only supported live Orchestrator path is the Shield v3.2 receipt entrypoint:

```python
from shield_orchestrator.v3.orchestrate import orchestrate
```

Integrators must provide explicit `payload.component_inputs`. Missing, malformed, or unavailable component input fails closed through the v3.2 receipt path.

---

## Archived v2 idea

The original v2 concept described a `FullShieldPipeline` that routed packets between Shield layers. That model is superseded by the v3.2 receipt boundary.

Do not treat this archived v2 document as current integration guidance.
