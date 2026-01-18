from __future__ import annotations


class TVAError(Exception):
    """
    Deterministic, fail-closed error used at v3 boundaries.

    Orchestrator v3 public APIs must not leak raw exceptions to callers.
    Errors are converted into v3 DENY envelopes with reason ids.
    """

    def __init__(self, reason_id: str, message: str) -> None:
        super().__init__(message)
        self.reason_id = reason_id
        self.message = message

    def __str__(self) -> str:
        return f"{self.reason_id}: {self.message}"
