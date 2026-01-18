from __future__ import annotations

import hashlib
from typing import Any

from .canonical_json import to_canonical_json


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_context_hash(material: Any) -> str:
    """
    Deterministic context hash computed from canonical JSON.
    """
    canonical = to_canonical_json(material)
    return sha256_hex(canonical)
