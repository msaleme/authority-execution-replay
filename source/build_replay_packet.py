#!/usr/bin/env python3
"""Build a self-contained, synthetic authority-to-execution replay packet.

The packet is deliberately small: an allowed exact action plus two negative
controls.  It is not a live API test, an attestation, or an identity system.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from executor import cross_profile_receipt


ROOT = Path(__file__).resolve().parent
SOURCE_FILES = ("profile.py", "executor.py", "event_bundle.py")
SCHEMA_VERSION = "0.1-internal-replay"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()


def action(target: str, *, mode: str = "read") -> dict[str, str]:
    return {
        "operation": "read_synthetic_sensitive_record",
        "target": target,
        "mode": mode,
        "payload_class": "synthetic-restricted",
    }


def authorization(decision_id: str, action_digest: str) -> dict[str, str]:
    return {
        "decision_id": decision_id,
        "action_digest": action_digest,
        "expires_at": "2026-09-03T00:00:00Z",
        "fixture_id": "authority-profile-fixture-v1",
    }


def profile_record(auth: dict[str, str], marker: str, occurred: bool) -> dict[str, Any]:
    execution = cross_profile_receipt(auth, marker)
    return {
        "schema_version": "0.1-internal",
        "subject": {"artifact_sha256": sha256({"fixture": "authority-execution-replay-v1"})},
        "authorization": auth,
        "execution": execution,
        "claim": {"occurred": occurred},
    }


def scenario(name: str, authorized: dict[str, str], attempted: dict[str, str], decision: str,
             marker: str, occurred: bool) -> dict[str, Any]:
    return {
        "id": name,
        "human_sponsorship": {
            "sponsor_id": "synthetic-human-sponsor-v1",
            "sponsorship_ref": "fixture-sponsorship-v1",
            "scope": "owned-fixture-only",
        },
        "delegated_authority": authorized,
        "policy_decision": decision,
        "authorized_action": authorized["action_digest"],
        "attempted_action": attempted,
        "attempted_action_sha256": sha256(attempted),
        "profile_record": profile_record(authorized, marker, occurred),
        "expected": {"occurred": occurred},
    }


def build() -> dict[str, Any]:
    allowed = action("fixture://sensitive/customer-001")
    wrong_target = action("fixture://sensitive/customer-002")
    mutated = action("fixture://sensitive/customer-001", mode="export")
    allowed_digest = sha256(allowed)
    wrong_digest = sha256(wrong_target)
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "synthetic, owned-fixture, networkless replay only",
        "claim_boundary": (
            "This packet demonstrates a local data-contract verifier over owned fixtures. "
            "It does not establish a real MCP/API action, production enforcement, external identity, "
            "or independent validation."
        ),
        "source": {
            "files": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES},
            "replay_command": "PYTHONDONTWRITEBYTECODE=1 python3 verify_replay_packet.py <packet.json>",
        },
        "scenarios": [
            scenario(
                "allow-exact-action", authorization("allow-exact-action", allowed_digest), allowed,
                "ALLOW_EXACT_ACTION", "FIXTURE_EXECUTED", True,
            ),
            scenario(
                "deny-wrong-target", authorization("deny-wrong-target", wrong_digest), wrong_target,
                "DENY_WRONG_TARGET", "FIXTURE_DENIED", False,
            ),
            scenario(
                "deny-post-approval-mutation", authorization("deny-post-approval-mutation", allowed_digest), mutated,
                "DENY_POST_APPROVAL_MUTATION", "FIXTURE_DENIED", False,
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packet = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(packet) + b"\n")
    print(f"wrote {args.output} sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
