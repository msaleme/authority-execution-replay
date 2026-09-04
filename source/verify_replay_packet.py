#!/usr/bin/env python3
"""Offline verifier for a synthetic authority-to-execution replay packet.

Hardened 2026-09-04 after an independent cross-evaluation (VrtxOmega, harness #304)
found that the previous verifier reported PASS for several parsed-packet mutations.
Root cause: it checked that ``scenarios`` had length three but never that the three
were the distinct required controls, never verified the packet's own SHA-256 against
the manifest, and never checked several fields at all (``authorized_action``, the
top-level ``expected.occurred``, ``delegated_authority`` beyond its action digest, and
the packet-level ``scope`` / ``claim_boundary``). Three copies of the allow control
therefore passed with a success message claiming all three were verified.

The verifier now gates on two independent layers:

* file-to-manifest consistency -- the packet file's SHA-256 must equal
  ``manifest.packet_sha256`` (``main`` only, since it needs the bytes on disk). With the
  manifest held fixed (a pinned commit, a verified signature anchored to a trusted key, or a release digest as the external
  trust anchor), any packet-byte change fails before semantic verification. This is a
  consistency check, not integrity on its own: an attacker who can rewrite both the
  packet and its adjacent manifest defeats it, which is why the semantic layer stands
  independently below;
* inner semantics   -- the exact required-control set, the pinned synthetic ``scope``
  and ``claim_boundary``, and per-scenario internal-consistency invariants; these
  catch a mutation even in a re-hashed packet, and catch parsed-dict mutations that
  never touch the file.

A verifier that cannot fail is not evidence, so ``tests/test_replay_packet.py`` seeds
one mutation per class and asserts each is rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from profile import validate


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
SOURCE_FILES = ("profile.py", "executor.py", "event_bundle.py")

# Pinned v1 contract text. These are fixed for the frozen fixture; a substitution
# (for example widening scope to include production, or replacing the synthetic-only
# claim boundary) must fail even if the packet is otherwise re-hashed consistently.
EXPECTED_SCOPE = "synthetic, owned-fixture, networkless replay only"
EXPECTED_CLAIM_BOUNDARY = (
    "This packet demonstrates a local data-contract verifier over owned fixtures. "
    "It does not establish a real MCP/API action, production enforcement, external "
    "identity, or independent validation."
)

# (policy_decision, expected.occurred, delegated-authority-digest-differs-from-attempted)
EXPECTED_CONTROLS = {
    "allow-exact-action": ("ALLOW_EXACT_ACTION", True, False),
    "deny-wrong-target": ("DENY_WRONG_TARGET", False, False),
    "deny-post-approval-mutation": ("DENY_POST_APPROVAL_MUTATION", False, True),
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def verify(packet: dict[str, Any]) -> list[str]:
    """Semantic verification of a parsed packet. The file-to-manifest consistency check
    (the packet's own SHA-256 against the manifest) runs separately in ``main`` because it
    needs the bytes on disk; this function is what protects a parsed dict."""
    errors: list[str] = []
    if packet.get("schema_version") != "0.1-internal-replay":
        return ["unsupported packet schema"]

    if packet.get("scope") != EXPECTED_SCOPE:
        errors.append("packet scope does not match the pinned synthetic-only scope")
    if packet.get("claim_boundary") != EXPECTED_CLAIM_BOUNDARY:
        errors.append("packet claim_boundary does not match the pinned synthetic-only boundary")

    source = packet.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("files"), dict):
        return errors + ["packet lacks source file digests"]
    for name in SOURCE_FILES:
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if source["files"].get(name) != actual:
            errors.append(f"source digest mismatch: {name}")

    scenarios = packet.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["packet scenarios must be a list"]

    # The required-control SET, not merely three items. Three copies of one control
    # is the defect this replaces: the multiset of ids must equal the required set
    # with each control present exactly once.
    ids = [s.get("id") for s in scenarios if isinstance(s, dict)]
    required = set(EXPECTED_CONTROLS)
    seen = set(ids)
    if len(ids) != len(scenarios):
        errors.append("every scenario must be an object with an id")
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        errors.append(f"duplicate control(s): {dupes} -- each required control must appear exactly once")
    if seen != required:
        missing = sorted(required - seen)
        extra = sorted(seen - required)
        if missing:
            errors.append(f"missing required control(s): {missing}")
        if extra:
            errors.append(f"unexpected control(s): {extra}")

    for item in scenarios:
        if not isinstance(item, dict) or item.get("id") not in EXPECTED_CONTROLS:
            errors.append("unknown scenario")
            continue
        sid = item["id"]
        decision, should_occur, must_differ = EXPECTED_CONTROLS[sid]
        if item.get("policy_decision") != decision:
            errors.append(f"{sid}: wrong policy decision")

        sponsor = item.get("human_sponsorship")
        if not isinstance(sponsor, dict) or sponsor.get("scope") != "owned-fixture-only":
            errors.append(f"{sid}: invalid sponsorship boundary")

        attempted = item.get("attempted_action")
        if item.get("attempted_action_sha256") != sha256(attempted):
            errors.append(f"{sid}: attempted-action digest mismatch")

        authority = item.get("delegated_authority")
        record = item.get("profile_record")
        if not isinstance(authority, dict) or not isinstance(attempted, dict):
            errors.append(f"{sid}: missing authority or attempted action")
            continue
        if not isinstance(record, dict):
            errors.append(f"{sid}: missing profile record")
            continue

        # authorized_action is the digest the authority approved; it must equal the
        # delegated authority's action_digest. Previously this field was never read,
        # so corrupting it passed.
        if item.get("authorized_action") != authority.get("action_digest"):
            errors.append(f"{sid}: authorized_action does not match the delegated authority digest")

        # The delegated authority and the profile record's authorization are the same
        # grant seen from two places; they must be identical. This catches a
        # fixture_id / decision_id / expires_at substitution in either copy.
        if authority != record.get("authorization"):
            errors.append(f"{sid}: delegated_authority and profile authorization disagree")

        differs = authority.get("action_digest") != item.get("attempted_action_sha256")
        if differs != must_differ:
            errors.append(f"{sid}: approval-binding expectation failed")

        errors.extend(f"{sid}: {error}" for error in validate(record))

        # Both occurrence claims must equal the expected outcome. Previously only the
        # profile record's claim was checked, so flipping the top-level expected passed.
        if item.get("expected", {}).get("occurred") != should_occur:
            errors.append(f"{sid}: expected.occurred does not match the expected outcome")
        if record.get("claim", {}).get("occurred") != should_occur:
            errors.append(f"{sid}: profile claim.occurred does not match the expected outcome")

    return errors


def _packet_hash_error(packet_path: Path) -> str | None:
    """Verify the packet file's own SHA-256 against manifest.packet_sha256.

    None on success; an error string otherwise. This is the file-to-manifest consistency
    check the previous command omitted. With the manifest held fixed by an external trust
    anchor (a pinned commit, a verified signature anchored to a trusted key, or a release digest), every byte-level mutation of
    the packet fails before semantic checks even run. It is not integrity on its own: it
    binds the packet to its adjacent manifest, and trusting the manifest is the caller's
    responsibility."""
    manifest_path = REPO_ROOT / "manifest.json"
    if not manifest_path.is_file():
        return f"manifest not found at {manifest_path}; cannot verify packet integrity"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return f"manifest unreadable: {exc}"
    expected_hash = manifest.get("packet_sha256")
    if not expected_hash:
        return "manifest does not declare packet_sha256"
    actual = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    if actual != expected_hash:
        return (f"packet SHA-256 does not match manifest: file={actual} "
                f"manifest={expected_hash}")
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()

    hash_error = _packet_hash_error(args.packet)
    packet = json.loads(args.packet.read_text())
    errors = verify(packet)
    if hash_error:
        errors = [hash_error] + errors

    if errors:
        print("FAIL")
        print("\n".join(errors))
        return 1
    print("PASS: packet SHA-256 matches manifest; the three required controls are "
          "present exactly once (exact allow, wrong-target deny, post-approval-mutation "
          "deny); scope, claim boundary and per-scenario authority invariants verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
