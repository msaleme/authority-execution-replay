"""Synthetic, test-controlled observation source for the reference profile.

This module performs no external action.  A caller supplies a fixture marker
that represents a directly observed outcome, and this module turns that marker
into the only receipt shape accepted by the profile validator.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from event_bundle import bundle_for


OBSERVABLE_MARKERS = frozenset({"FIXTURE_EXECUTED", "FIXTURE_DENIED"})
EXPECTED_EXECUTOR_ID = "synthetic-fixture-executor"
FIXTURE_MARKERS = {
    "authority-profile-fixture-v1": OBSERVABLE_MARKERS,
}
AUTHORIZATION_KEYS = frozenset({"decision_id", "action_digest", "expires_at", "fixture_id"})
DECISION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
FIXTURE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_decision_id(value: Any) -> bool:
    return isinstance(value, str) and DECISION_ID_PATTERN.fullmatch(value) is not None and value not in {".", ".."}


def _is_fixture_id(value: Any) -> bool:
    return isinstance(value, str) and FIXTURE_ID_PATTERN.fullmatch(value) is not None and value not in {".", ".."}


def _parse_aware_iso8601(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _is_utc_iso8601(value: Any) -> bool:
    parsed = _parse_aware_iso8601(value)
    return parsed is not None and parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def observation_for(
    authorization: dict[str, Any], marker: str, *, executor_id: str = EXPECTED_EXECUTOR_ID
) -> dict[str, str]:
    """Return a receipt-grade observation only for a recognized fixture marker."""
    if not isinstance(authorization, dict):
        raise ValueError("authorization must be an object")
    if unsupported := set(authorization) - AUTHORIZATION_KEYS:
        raise ValueError(f"authorization contains unsupported fields: {', '.join(sorted(unsupported))}")
    if executor_id != EXPECTED_EXECUTOR_ID:
        raise ValueError("executor id is not the synthetic fixture executor")
    if not isinstance(marker, str) or not marker:
        raise ValueError("marker must be a non-empty string")
    if marker not in OBSERVABLE_MARKERS:
        raise ValueError("marker is not a directly observable fixture outcome")
    decision_id = authorization.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id:
        raise ValueError("authorization must contain a decision id")
    if not _is_decision_id(decision_id):
        raise ValueError("authorization decision id must be a canonical identifier")
    action_digest = authorization.get("action_digest")
    if not isinstance(action_digest, str) or not action_digest:
        raise ValueError("authorization must contain an action digest")
    if not _is_sha256(action_digest):
        raise ValueError("authorization action digest must be a SHA-256 hex digest")
    expires_at = _parse_aware_iso8601(authorization.get("expires_at"))
    if expires_at is None:
        raise ValueError("authorization expiry must be timezone-aware ISO-8601")
    if not _is_utc_iso8601(authorization.get("expires_at")):
        raise ValueError("authorization expiry must be UTC ISO-8601")
    fixture_id = authorization.get("fixture_id")
    if not isinstance(fixture_id, str) or not fixture_id:
        raise ValueError("authorization must contain a fixture id")
    if not _is_fixture_id(fixture_id):
        raise ValueError("authorization fixture id must be a canonical identifier")
    if fixture_id not in FIXTURE_MARKERS:
        raise ValueError("authorization must name a declared owned fixture")
    if marker not in FIXTURE_MARKERS[fixture_id]:
        raise ValueError("marker is not declared by the authorized fixture")
    observed_state = "EXECUTED" if marker == "FIXTURE_EXECUTED" else "DENIED_BEFORE_EXECUTION"
    observed_at = "2026-08-07T02:00:00Z"
    if datetime.fromisoformat(observed_at.replace("Z", "+00:00")) >= expires_at:
        raise ValueError("authorization expiry must be after the fixture observation time")
    event = {
        "marker_id": marker,
        "fixture_id": fixture_id,
        "executor_id": executor_id,
        "decision_id": decision_id,
        "action_digest": action_digest,
        "observed_state": observed_state,
        "observed_at": observed_at,
    }
    bundle = bundle_for(event)
    return event | {"evidence_sha256": bundle["event_sha256"], "bundle_sha256": bundle["bundle_sha256"]}


def cross_profile_receipt(authorization: dict[str, Any], marker: str) -> dict[str, Any]:
    """Create a synthetic cross-profile receipt after direct fixture observation.

    The denial path is an outcome receipt, not an execution-occurrence claim.
    """
    observation = observation_for(authorization, marker)
    state = observation["observed_state"]
    event = {
        key: observation[key]
        for key in (
            "marker_id",
            "fixture_id",
            "executor_id",
            "decision_id",
            "action_digest",
            "observed_state",
            "observed_at",
        )
    }
    execution: dict[str, Any] = {"state": state, "observation": observation, "bundle": bundle_for(event)}
    if state == "EXECUTED":
        execution["receipt"] = {
            "executor_id": observation["executor_id"],
            "decision_id": observation["decision_id"],
            "action_digest": observation["action_digest"],
            "occurred_at": observation["observed_at"],
            "evidence_sha256": observation["evidence_sha256"],
            "bundle_sha256": observation["bundle_sha256"],
        }
    return execution
