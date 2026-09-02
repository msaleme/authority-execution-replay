from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_replay_packet import build
from verify_replay_packet import verify


class ReplayPacketTests(unittest.TestCase):
    def test_fresh_packet_verifies(self) -> None:
        self.assertEqual(verify(build()), [])

    def test_mutated_attempted_action_fails(self) -> None:
        packet = build()
        packet["scenarios"][2]["attempted_action"]["mode"] = "write"
        self.assertIn("deny-post-approval-mutation: attempted-action digest mismatch", verify(packet))

    def test_mutated_source_digest_fails(self) -> None:
        packet = build()
        packet["source"]["files"]["profile.py"] = "0" * 64
        self.assertIn("source digest mismatch: profile.py", verify(packet))

    def test_policy_decision_flip_fails(self) -> None:
        packet = build()
        packet["scenarios"][0]["policy_decision"] = "DENY_WRONG_TARGET"
        self.assertIn("allow-exact-action: wrong policy decision", verify(packet))

    def test_occurrence_claim_flip_fails(self) -> None:
        packet = build()
        packet["scenarios"][0]["profile_record"]["claim"]["occurred"] = False
        self.assertIn("allow-exact-action: claim occurrence conflicts with execution state", verify(packet))

    def test_post_approval_mutation_erasure_fails(self) -> None:
        packet = build()
        scenario = packet["scenarios"][2]
        scenario["attempted_action"] = {
            "operation": "read_synthetic_sensitive_record",
            "target": "fixture://sensitive/customer-001",
            "mode": "read",
            "payload_class": "synthetic-restricted",
        }
        scenario["attempted_action_sha256"] = scenario["delegated_authority"]["action_digest"]
        self.assertIn("deny-post-approval-mutation: approval-binding expectation failed", verify(packet))

    def test_sponsorship_boundary_widening_fails(self) -> None:
        packet = build()
        packet["scenarios"][0]["human_sponsorship"]["scope"] = "production"
        self.assertIn("allow-exact-action: invalid sponsorship boundary", verify(packet))
