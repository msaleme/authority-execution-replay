"""Canonical, local-only integrity bundle for fixture observations."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any


BUNDLE_KEYS = frozenset({"bundle_version", "events", "event_sha256", "bundle_sha256"})
EVENT_KEYS = frozenset(
    {
        "marker_id",
        "fixture_id",
        "executor_id",
        "decision_id",
        "action_digest",
        "observed_state",
        "observed_at",
    }
)
CANONICAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _is_canonical_id(value: Any) -> bool:
    return isinstance(value, str) and CANONICAL_ID_PATTERN.fullmatch(value) is not None and value not in {".", ".."}


def canonical_bytes(value: dict[str, Any]) -> bytes:
    """Return the one serialization used for bundle hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def bundle_for(event: dict[str, str]) -> dict[str, Any]:
    """Bind one declared synthetic observation to a deterministic digest."""
    if missing := EVENT_KEYS - event.keys():
        raise ValueError(f"event is missing fields: {', '.join(sorted(missing))}")
    if unsupported := set(event) - EVENT_KEYS:
        raise ValueError(f"event contains unsupported fields: {', '.join(sorted(unsupported))}")
    if non_string := {key for key in EVENT_KEYS if not isinstance(event.get(key), str)}:
        raise ValueError(f"event fields must be strings: {', '.join(sorted(non_string))}")
    if empty := {key for key in EVENT_KEYS if isinstance(event.get(key), str) and not event.get(key)}:
        raise ValueError(f"event fields must be non-empty strings: {', '.join(sorted(empty))}")
    if noncanonical := {key for key in ("decision_id", "fixture_id") if not _is_canonical_id(event.get(key))}:
        raise ValueError(f"event fields must use canonical identifiers: {', '.join(sorted(noncanonical))}")
    event_sha256 = sha256(canonical_bytes(event)).hexdigest()
    bundle = {"bundle_version": "0.1-internal", "events": [event], "event_sha256": event_sha256}
    bundle["bundle_sha256"] = sha256(canonical_bytes(bundle)).hexdigest()
    return bundle


def valid(bundle: Any) -> bool:
    """Verify the local bundle shape and canonical event and bundle digests."""
    if not isinstance(bundle, dict) or bundle.get("bundle_version") != "0.1-internal":
        return False
    if set(bundle) != BUNDLE_KEYS:
        return False
    events = bundle.get("events")
    if not isinstance(events, list) or len(events) != 1 or not isinstance(events[0], dict):
        return False
    event = events[0]
    if set(event) != EVENT_KEYS:
        return False
    if any(not isinstance(event.get(key), str) or not event.get(key) for key in EVENT_KEYS):
        return False
    if any(not _is_canonical_id(event.get(key)) for key in ("decision_id", "fixture_id")):
        return False
    event_sha256 = bundle.get("event_sha256")
    if event_sha256 != sha256(canonical_bytes(event)).hexdigest():
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    return bundle.get("bundle_sha256") == sha256(canonical_bytes(unsigned)).hexdigest()
