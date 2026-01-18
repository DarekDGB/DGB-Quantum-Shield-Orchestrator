from __future__ import annotations

import json
from typing import Any


def to_canonical_json(obj: Any) -> str:
    """
    Deterministic JSON serialization for hashing and audit.

    Rules:
    - UTF-8
    - keys sorted
    - stable separators (no whitespace variance)
    - no reliance on insertion order
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
