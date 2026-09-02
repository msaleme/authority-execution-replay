"""Fail-closed validator for synthetic authority-to-execution records."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from event_bundle import valid as valid_bundle


ALLOWED_STATES = frozenset({"NOT_ATTEMPTED", "DENIED_BEFORE_EXECUTION", "EXECUTED"})
OBSERVABLE_STATES = frozenset({"DENIED_BEFORE_EXECUTION", "EXECUTED"})
EXECUTION_KEYS = frozenset({"state", "receipt", "observation", "bundle"})
EXPECTED_EXECUTOR_ID = "synthetic-fixture-executor"
DECLARED_FIXTURE_IDS = frozenset({"authority-profile-fixture-v1"})
DECISION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
FIXTURE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MARKER_STATES = {
    "FIXTURE_EXECUTED": "EXECUTED",
    "FIXTURE_DENIED": "DENIED_BEFORE_EXECUTION",
}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_decision_id(value: Any) -> bool:
    return isinstance(value, str) and DECISION_ID_PATTERN.fullmatch(value) is not None and value not in {".", ".."}


def _is_fixture_id(value: Any) -> bool:
    return isinstance(value, str) and FIXTURE_ID_PATTERN.fullmatch(value) is not None and value not in {".", ".."}


def _is_aware_iso8601(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _is_utc_iso8601(value: Any) -> bool:
    parsed = _parse_aware_iso8601(value)
    return parsed is not None and parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


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


def validate(record: dict[str, Any], now: datetime | None = None) -> list[str]:
    """Return every unsupported claim in a profile record.

    A valid record may show that execution did not occur. It may never turn a
    static finding or an authorization decision into an execution claim.
    """
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record must be an object"]
    required = {"schema_version", "subject", "authorization", "execution", "claim"}
    missing = required - record.keys()
    if missing:
        return [f"missing top-level fields: {', '.join(sorted(missing))}"]
    unsupported_record_fields = set(record) - required
    if unsupported_record_fields:
        errors.append(f"record contains unsupported fields: {', '.join(sorted(unsupported_record_fields))}")
    if record["schema_version"] != "0.1-internal":
        errors.append("unsupported schema version")

    subject = record["subject"]
    if not isinstance(subject, dict) or not isinstance(subject.get("artifact_sha256"), str):
        errors.append("subject requires an artifact SHA-256")
    else:
        unsupported_subject_fields = set(subject) - {"artifact_sha256"}
        if unsupported_subject_fields:
            errors.append(f"subject contains unsupported fields: {', '.join(sorted(unsupported_subject_fields))}")
        if not _is_sha256(subject["artifact_sha256"]):
            errors.append("subject artifact SHA-256 must be 64 hex characters")

    authorization = record["authorization"]
    authorization_expiry: datetime | None = None
    if not isinstance(authorization, dict):
        errors.append("authorization must be an object")
    else:
        unsupported_authorization_fields = set(authorization) - {"decision_id", "action_digest", "expires_at", "fixture_id"}
        if unsupported_authorization_fields:
            errors.append(
                f"authorization contains unsupported fields: {', '.join(sorted(unsupported_authorization_fields))}"
            )
        for key in ("decision_id", "action_digest", "expires_at", "fixture_id"):
            if not isinstance(authorization.get(key), str) or not authorization[key]:
                errors.append(f"authorization requires {key}")
        if "decision_id" in authorization and not _is_decision_id(authorization.get("decision_id")):
            errors.append("authorization decision id must be a canonical identifier")
        if "fixture_id" in authorization and not _is_fixture_id(authorization.get("fixture_id")):
            errors.append("authorization fixture id must be a canonical identifier")
        if isinstance(authorization.get("fixture_id"), str) and authorization["fixture_id"] not in DECLARED_FIXTURE_IDS:
            errors.append("authorization fixture is not a declared owned fixture")
        if "action_digest" in authorization and not _is_sha256(authorization.get("action_digest")):
            errors.append("authorization action digest must be a 64-character SHA-256 hex digest")
        expires_at = authorization.get("expires_at")
        if isinstance(expires_at, str):
            expiry = _parse_aware_iso8601(expires_at)
            if expiry is None:
                errors.append("authorization expiry is invalid")
            else:
                if not _is_utc_iso8601(expires_at):
                    errors.append("authorization expiry must be UTC ISO-8601")
                authorization_expiry = expiry
                if now is not None and expiry.astimezone(UTC) <= now.astimezone(UTC):
                    errors.append("authorization is expired")

    execution = record["execution"]
    if not isinstance(execution, dict) or execution.get("state") not in ALLOWED_STATES:
        return errors + ["execution requires a recognized state"]
    unsupported_execution_fields = set(execution) - EXECUTION_KEYS
    if unsupported_execution_fields:
        errors.append(f"execution contains unsupported fields: {', '.join(sorted(unsupported_execution_fields))}")
    state = execution["state"]
    receipt = execution.get("receipt")
    if state == "EXECUTED":
        if not isinstance(receipt, dict):
            errors.append("executed state requires an execution receipt")
        else:
            unsupported_receipt_fields = set(receipt) - {
                "executor_id",
                "decision_id",
                "action_digest",
                "occurred_at",
                "evidence_sha256",
                "bundle_sha256",
            }
            if unsupported_receipt_fields:
                errors.append(f"execution receipt contains unsupported fields: {', '.join(sorted(unsupported_receipt_fields))}")
            for key in ("executor_id", "decision_id", "action_digest", "occurred_at", "evidence_sha256", "bundle_sha256"):
                if not isinstance(receipt.get(key), str) or not receipt[key]:
                    errors.append(f"execution receipt requires {key}")
            for key in ("action_digest", "evidence_sha256", "bundle_sha256"):
                if key in receipt and not _is_sha256(receipt.get(key)):
                    errors.append(f"execution receipt {key} must be a 64-character SHA-256 hex digest")
            if "decision_id" in receipt and not _is_decision_id(receipt.get("decision_id")):
                errors.append("execution receipt decision id must be a canonical identifier")
            if "occurred_at" in receipt and not _is_utc_iso8601(receipt.get("occurred_at")):
                errors.append("execution receipt timestamp must be UTC ISO-8601")
            occurred_at = _parse_aware_iso8601(receipt.get("occurred_at"))
            if (
                occurred_at is not None
                and authorization_expiry is not None
                and occurred_at.astimezone(UTC) >= authorization_expiry.astimezone(UTC)
            ):
                errors.append("execution receipt timestamp is outside authorization window")
            if isinstance(authorization, dict) and receipt.get("action_digest") != authorization.get("action_digest"):
                errors.append("execution receipt action digest is not bound to authorization")
            if isinstance(authorization, dict) and receipt.get("decision_id") != authorization.get("decision_id"):
                errors.append("execution receipt decision id is not bound to authorization")
    elif receipt is not None:
        errors.append("non-executed states must not carry an execution receipt")

    observation = execution.get("observation")
    if state in OBSERVABLE_STATES:
        bundle = execution.get("bundle")
        if not valid_bundle(bundle):
            errors.append("observable execution state requires an intact fixture event bundle")
        if not isinstance(observation, dict):
            errors.append("observable execution state requires a controlled observation")
        else:
            unsupported_observation_fields = set(observation) - {
                "marker_id",
                "fixture_id",
                "executor_id",
                "decision_id",
                "action_digest",
                "observed_state",
                "observed_at",
                "evidence_sha256",
                "bundle_sha256",
            }
            if unsupported_observation_fields:
                errors.append(
                    f"controlled observation contains unsupported fields: {', '.join(sorted(unsupported_observation_fields))}"
                )
            for key in (
                "marker_id",
                "fixture_id",
                "executor_id",
                "decision_id",
                "action_digest",
                "observed_state",
                "observed_at",
                "evidence_sha256",
                "bundle_sha256",
            ):
                if not isinstance(observation.get(key), str) or not observation[key]:
                    errors.append(f"controlled observation requires {key}")
            for key in ("action_digest", "evidence_sha256", "bundle_sha256"):
                if key in observation and not _is_sha256(observation.get(key)):
                    errors.append(f"controlled observation {key} must be a 64-character SHA-256 hex digest")
            if "decision_id" in observation and not _is_decision_id(observation.get("decision_id")):
                errors.append("controlled observation decision id must be a canonical identifier")
            if "fixture_id" in observation and not _is_fixture_id(observation.get("fixture_id")):
                errors.append("controlled observation fixture id must be a canonical identifier")
            if "observed_at" in observation and not _is_utc_iso8601(observation.get("observed_at")):
                errors.append("controlled observation timestamp must be UTC ISO-8601")
            observed_at = _parse_aware_iso8601(observation.get("observed_at"))
            if (
                observed_at is not None
                and authorization_expiry is not None
                and observed_at.astimezone(UTC) >= authorization_expiry.astimezone(UTC)
            ):
                errors.append("controlled observation timestamp is outside authorization window")
            if observation.get("observed_state") != state:
                errors.append("controlled observation state conflicts with execution state")
            marker_id = observation.get("marker_id")
            if marker_id not in MARKER_STATES:
                errors.append("controlled observation marker is not recognized")
            elif MARKER_STATES[marker_id] != state:
                errors.append("controlled observation marker conflicts with execution state")
            if observation.get("executor_id") != EXPECTED_EXECUTOR_ID:
                errors.append("controlled observation executor is not the synthetic fixture executor")
            if isinstance(authorization, dict) and observation.get("action_digest") != authorization.get("action_digest"):
                errors.append("controlled observation action digest is not bound to authorization")
            if isinstance(authorization, dict) and observation.get("decision_id") != authorization.get("decision_id"):
                errors.append("controlled observation decision id is not bound to authorization")
            if isinstance(authorization, dict) and observation.get("fixture_id") != authorization.get("fixture_id"):
                errors.append("controlled observation fixture is not bound to authorization")
            if isinstance(bundle, dict) and observation.get("evidence_sha256") != bundle.get("event_sha256"):
                errors.append("controlled observation is not bound to fixture event bundle")
            if isinstance(bundle, dict) and observation.get("bundle_sha256") != bundle.get("bundle_sha256"):
                errors.append("controlled observation bundle digest is not bound to fixture event bundle")
            if isinstance(bundle, dict) and isinstance(bundle.get("events"), list) and bundle["events"]:
                expected_event = {
                    key: observation.get(key)
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
                if bundle["events"][0] != expected_event:
                    errors.append("fixture event bundle does not match controlled observation")
            if state == "EXECUTED" and isinstance(receipt, dict):
                if receipt.get("executor_id") != observation.get("executor_id"):
                    errors.append("execution receipt executor is not bound to controlled observation")
                if receipt.get("evidence_sha256") != observation.get("evidence_sha256"):
                    errors.append("execution receipt is not bound to controlled observation")
                if receipt.get("bundle_sha256") != observation.get("bundle_sha256"):
                    errors.append("execution receipt bundle digest is not bound to controlled observation")
                if receipt.get("occurred_at") != observation.get("observed_at"):
                    errors.append("execution receipt timestamp is not bound to controlled observation")
    elif observation is not None:
        errors.append("unattempted state must not carry a controlled observation")
    elif execution.get("bundle") is not None:
        errors.append("unattempted state must not carry a fixture event bundle")

    claim = record["claim"]
    if not isinstance(claim, dict) or claim.get("occurred") not in {True, False}:
        errors.append("claim must explicitly state whether execution occurred")
    else:
        unsupported_claim_fields = set(claim) - {"occurred"}
        if unsupported_claim_fields:
            errors.append(f"claim contains unsupported fields: {', '.join(sorted(unsupported_claim_fields))}")
        if claim["occurred"] != (state == "EXECUTED"):
            errors.append("claim occurrence conflicts with execution state")
    return errors
