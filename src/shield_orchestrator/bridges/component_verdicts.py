from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from typing import Any, Mapping

from shield_orchestrator.v3.context_hash import compute_context_hash
from shield_orchestrator.v3.contracts.envelope import OrchestratorV3Request, TraceEntry
from shield_orchestrator.v3.contracts.v3_2_receipt import (
    COMPONENT_EVIDENCE_FAMILIES,
    COMPONENT_REASON_IDS,
    canonical_sha256,
    validate_component_verdict,
)

_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "allow",
        "approved",
        "authority",
        "auto_approve",
        "broadcast",
        "bypass",
        "can_sign",
        "decision_override",
        "execute",
        "final_approval",
        "force_allow",
        "human_approved",
        "override",
        "sign",
        "trusted",
    }
)

_COMPONENT_ERROR_REASON = {
    "adn": "ADN_ERROR_INVALID_VERDICT",
    "dqsn": "DQSN_ERROR_INVALID_VERDICT",
    "guardian_wallet": "GW_ERROR_INVALID_VERDICT",
    "qwg": "QWG_ERROR_INVALID_VERDICT",
    "sentinel_ai": "SNTL_ERROR_AI_OUTPUT_UNTRUSTED",
}

_COMPONENT_REASON_BY_DECISION = {
    "adn": {
        "ALLOW": "ADN_OK_COORDINATION_ALLOW",
        "ESCALATE": "ADN_ESCALATE_POLICY_REVIEW",
        "DENY": "ADN_DENY_DEFENSE_TRIGGERED",
        "ERROR": "ADN_ERROR_INVALID_VERDICT",
    },
    "dqsn": {
        "ALLOW": "DQSN_OK_NETWORK_ALLOW",
        "ESCALATE": "DQSN_ESCALATE_QUANTUM_SIGNAL",
        "DENY": "DQSN_DENY_NETWORK_RISK",
        "ERROR": "DQSN_ERROR_INVALID_VERDICT",
    },
    "guardian_wallet": {
        "ALLOW": "GW_OK_HEALTHY_ALLOW",
        "ESCALATE": "GW_ESCALATE_QID_REQUIRED",
        "DENY": "GW_DENY_POLICY_BLOCKED",
        "ERROR": "GW_ERROR_INVALID_VERDICT",
    },
    "qwg": {
        "ALLOW": "QWG_OK_POSTURE_ALLOW",
        "ESCALATE": "QWG_ESCALATE_QUANTUM_POSTURE",
        "DENY": "QWG_DENY_KEY_RISK",
        "ERROR": "QWG_ERROR_INVALID_VERDICT",
    },
    "sentinel_ai": {
        "ALLOW": "SNTL_OK_TELEMETRY_ALLOW",
        "ESCALATE": "SNTL_ESCALATE_THREAT_REVIEW",
        "DENY": "SNTL_DENY_THREAT_DETECTED",
        "ERROR": "SNTL_ERROR_AI_OUTPUT_UNTRUSTED",
    },
}

_COMPONENT_DEFAULT_FAMILY = {
    "adn": "defense_signal",
    "dqsn": "aggregate_signal",
    "guardian_wallet": "wallet_context",
    "qwg": "wallet_posture",
    "sentinel_ai": "telemetry",
}

_COMPONENT_PAYLOAD_ALIASES = {
    "sentinel_ai": ("sentinel_ai", "sentinel"),
    "dqsn": ("dqsn", "dqs_network"),
    "adn": ("adn",),
    "guardian_wallet": ("guardian_wallet", "guardian"),
    "qwg": ("qwg",),
}


@dataclass(frozen=True)
class ComponentBridgeResult:
    """Bridge output used by Orchestrator v3 receipt synthesis."""

    trace: TraceEntry
    verdict: dict[str, Any]


def receipt_request_id(request: OrchestratorV3Request) -> str:
    """Return the deterministic request_id used by the Shield v3.2 receipt."""

    payload = request.payload if isinstance(request.payload, Mapping) else {}
    candidate = payload.get("request_id")
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()
    return request.nonce


def receipt_context_hash(request: OrchestratorV3Request) -> str:
    """Return caller-bound context_hash or compute a deterministic request context hash.

    AdamantineOS callers SHOULD supply the already-computed AdamantineOS
    context_hash in payload.context_hash, payload.expected_context_hash, or
    payload.adamantine_context_hash. When absent, the Orchestrator computes a
    deterministic local request hash so standalone Orchestrator use remains
    deterministic and fail-closed.
    """

    payload = request.payload if isinstance(request.payload, Mapping) else {}
    for key in ("context_hash", "expected_context_hash", "adamantine_context_hash"):
        value = payload.get(key)
        if isinstance(value, str):
            return _require_lower_sha256(value, field=key)
    return compute_context_hash({"request": asdict(request), "receipt_context": "shield_orchestrator_v3_2"})


def component_input(request: OrchestratorV3Request, component_id: str) -> Mapping[str, Any] | None:
    """Extract explicit component input from the Orchestrator request payload."""

    payload = request.payload if isinstance(request.payload, Mapping) else {}
    nested = payload.get("component_inputs")
    if isinstance(nested, Mapping):
        for key in _COMPONENT_PAYLOAD_ALIASES[component_id]:
            value = nested.get(key)
            if isinstance(value, Mapping):
                return value
    for key in _COMPONENT_PAYLOAD_ALIASES[component_id]:
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
    return None


def build_component_result_from_response(
    *,
    component_id: str,
    request_id: str,
    context_hash: str,
    engine_response: Any,
) -> ComponentBridgeResult:
    """Translate a real component engine response into Shield v3.2 verdict shape."""

    normalized = _json_like(engine_response)
    if not isinstance(normalized, dict):
        return error_component_result(
            component_id=component_id,
            request_id=request_id,
            context_hash=context_hash,
            note="component_engine_returned_non_object",
        )
    if _contains_forbidden_authority(normalized):
        return error_component_result(
            component_id=component_id,
            request_id=request_id,
            context_hash=context_hash,
            note="component_engine_authority_bypass_rejected",
        )

    decision = _normalized_decision(normalized)
    reason_id = _COMPONENT_REASON_BY_DECISION[component_id][decision]
    evidence_hash = canonical_sha256({"component_id": component_id, "engine_response": normalized})
    metadata = {
        "bridge_source": "real_component_engine",
        "engine_component": str(normalized.get("component", component_id)),
        "engine_context_hash": _safe_engine_context_hash(normalized.get("context_hash")),
        "engine_reason_codes": _safe_str_list(normalized.get("reason_codes")),
    }
    verdict = _build_verdict(
        component_id=component_id,
        request_id=request_id,
        context_hash=context_hash,
        decision=decision,
        reason_ids=[reason_id],
        evidence_hash=evidence_hash,
        evidence_families=[_COMPONENT_DEFAULT_FAMILY[component_id]],
        metadata=metadata,
    )
    return ComponentBridgeResult(trace=_trace_from_verdict(verdict, note="real_component_engine"), verdict=verdict)


def error_component_result(
    *,
    component_id: str,
    request_id: str,
    context_hash: str,
    note: str,
) -> ComponentBridgeResult:
    """Build a fail-closed ERROR component verdict for bridge errors/unavailability."""

    evidence_hash = canonical_sha256(
        {
            "component_id": component_id,
            "error": note,
            "request_id": request_id,
            "context_hash": context_hash,
        }
    )
    verdict = _build_verdict(
        component_id=component_id,
        request_id=request_id,
        context_hash=context_hash,
        decision="ERROR",
        reason_ids=[_COMPONENT_ERROR_REASON[component_id]],
        evidence_hash=evidence_hash,
        evidence_families=[_COMPONENT_DEFAULT_FAMILY[component_id]],
        metadata={"bridge_source": "real_component_engine", "bridge_error": note},
    )
    return ComponentBridgeResult(trace=_trace_from_verdict(verdict, note=note), verdict=verdict)


def _build_verdict(
    *,
    component_id: str,
    request_id: str,
    context_hash: str,
    decision: str,
    reason_ids: list[str],
    evidence_hash: str,
    evidence_families: list[str],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    verdict: dict[str, Any] = {
        "component_id": component_id,
        "contract_version": 3,
        "schema_version": "shield.verdict.v1",
        "request_id": request_id,
        "context_hash": _require_lower_sha256(context_hash, field="context_hash"),
        "decision": decision,
        "reason_ids": sorted(_require_supported(reason_ids, allowed=COMPONENT_REASON_IDS[component_id], field="reason_ids")),
        "evidence_hash": _require_lower_sha256(evidence_hash, field="evidence_hash"),
        "evidence_families": sorted(_require_supported(evidence_families, allowed=COMPONENT_EVIDENCE_FAMILIES[component_id], field="evidence_families")),
        "metadata": metadata,
        "fail_closed": True,
    }
    return validate_component_verdict(verdict, expected_context_hash=context_hash)


def _trace_from_verdict(verdict: Mapping[str, Any], *, note: str) -> TraceEntry:
    decision = str(verdict["decision"])
    status = "ERROR" if decision == "ERROR" else "DENY" if decision == "DENY" else "OK"
    return TraceEntry(
        stage=str(verdict["component_id"]),
        component=str(verdict["component_id"]),
        status=status,  # type: ignore[arg-type]
        reason_ids=tuple(str(item) for item in verdict["reason_ids"]),
        component_context_hash=str(verdict["evidence_hash"]),
        notes=note,
    )


def _normalized_decision(response: Mapping[str, Any]) -> str:
    raw = response.get("decision", response.get("outcome", response.get("verdict_type")))
    if isinstance(raw, Enum):
        raw = raw.value
    value = str(raw).upper().strip()
    if value in {"ALLOW", "OK", "SAFE", "GREEN"}:
        return "ALLOW"
    if value in {"WARN", "WARNING", "CAUTION", "YELLOW", "ESCALATE", "DELAY", "REQUIRE_EXTRA_AUTH"}:
        return "ESCALATE"
    if value in {"BLOCK", "DENY", "DENIED"}:
        return "DENY"
    return "ERROR"


def _contains_forbidden_authority(value: Any) -> bool:
    if isinstance(value, Mapping):
        if set(value.keys()) & _FORBIDDEN_AUTHORITY_KEYS:
            return True
        return any(_contains_forbidden_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_authority(item) for item in value)
    return False


def _json_like(value: Any) -> Any:
    if is_dataclass(value):
        return _json_like(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _json_like(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_json_like(v) for v in value]
    if isinstance(value, list):
        return [_json_like(v) for v in value]
    return value


def _safe_engine_context_hash(value: Any) -> str | None:
    if isinstance(value, str) and len(value) == 64:
        try:
            int(value, 16)
        except ValueError:
            return None
        return value.lower()
    return None


def _safe_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _require_supported(values: list[str], *, allowed: tuple[str, ...], field: str) -> list[str]:
    if not values:
        raise ValueError(f"{field} must not be empty")
    allowed_set = set(allowed)
    clean: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} contains invalid value")
        item = value.strip()
        if item not in allowed_set:
            raise ValueError(f"{field} contains unknown value")
        clean.append(item)
    if len(set(clean)) != len(clean):
        raise ValueError(f"{field} contains duplicate value")
    return clean


def _require_lower_sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be 64-character sha256 hex")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be sha256 hex") from exc
    if value != value.lower():
        raise ValueError(f"{field} must be lowercase sha256 hex")
    return value
