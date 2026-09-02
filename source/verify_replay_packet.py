#!/usr/bin/env python3
"""Offline verifier for a synthetic authority-to-execution replay packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from profile import validate


ROOT = Path(__file__).resolve().parent
SOURCE_FILES = ("profile.py", "executor.py", "event_bundle.py")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def verify(packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if packet.get("schema_version") != "0.1-internal-replay":
        return ["unsupported packet schema"]
    source = packet.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("files"), dict):
        return ["packet lacks source file digests"]
    for name in SOURCE_FILES:
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if source["files"].get(name) != actual:
            errors.append(f"source digest mismatch: {name}")
    scenarios = packet.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 3:
        return errors + ["packet must contain exactly three scenarios"]
    expected = {
        "allow-exact-action": ("ALLOW_EXACT_ACTION", True, False),
        "deny-wrong-target": ("DENY_WRONG_TARGET", False, False),
        "deny-post-approval-mutation": ("DENY_POST_APPROVAL_MUTATION", False, True),
    }
    for item in scenarios:
        if not isinstance(item, dict) or item.get("id") not in expected:
            errors.append("unknown scenario")
            continue
        decision, should_occur, must_differ = expected[item["id"]]
        if item.get("policy_decision") != decision:
            errors.append(f"{item['id']}: wrong policy decision")
        sponsor = item.get("human_sponsorship")
        if not isinstance(sponsor, dict) or sponsor.get("scope") != "owned-fixture-only":
            errors.append(f"{item['id']}: invalid sponsorship boundary")
        attempted = item.get("attempted_action")
        if item.get("attempted_action_sha256") != sha256(attempted):
            errors.append(f"{item['id']}: attempted-action digest mismatch")
        authority = item.get("delegated_authority")
        if not isinstance(authority, dict) or not isinstance(attempted, dict):
            errors.append(f"{item['id']}: missing authority or attempted action")
            continue
        differs = authority.get("action_digest") != item.get("attempted_action_sha256")
        if differs != must_differ:
            errors.append(f"{item['id']}: approval-binding expectation failed")
        record = item.get("profile_record")
        if not isinstance(record, dict):
            errors.append(f"{item['id']}: missing profile record")
            continue
        errors.extend(f"{item['id']}: {error}" for error in validate(record))
        if record.get("claim", {}).get("occurred") != should_occur:
            errors.append(f"{item['id']}: occurrence claim does not match expected outcome")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    packet = json.loads(args.packet.read_text())
    errors = verify(packet)
    if errors:
        print("FAIL")
        print("\n".join(errors))
        return 1
    print("PASS: 3 synthetic scenarios verified: exact allow, wrong-target deny, post-approval-mutation deny")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
