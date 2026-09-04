from __future__ import annotations

import copy
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

    # Regressions for the gaps found by the 2026-09-04 independent cross-evaluation
    # (VrtxOmega, harness #304). Each was a mutation the previous verifier reported
    # PASS for. A verifier that cannot fail is not evidence, so each is asserted.

    def test_duplicate_controls_fail(self) -> None:
        """Three copies of the allow control must not pass as three controls."""
        packet = build()
        packet["scenarios"] = [
            packet["scenarios"][0],
            build()["scenarios"][0],
            build()["scenarios"][0],
        ]
        self.assertTrue(any("duplicate control" in e for e in verify(packet)))

    def test_corrupt_authorized_action_fails(self) -> None:
        packet = build()
        packet["scenarios"][0]["authorized_action"] = "0" * 64
        self.assertIn(
            "allow-exact-action: authorized_action does not match the delegated authority digest",
            verify(packet),
        )

    def test_top_level_expected_occurred_flip_fails(self) -> None:
        """Flipping the top-level expected.occurred, not just the profile claim."""
        packet = build()
        packet["scenarios"][1]["expected"]["occurred"] = True
        self.assertIn(
            "deny-wrong-target: expected.occurred does not match the expected outcome",
            verify(packet),
        )

    def test_packet_scope_widening_fails(self) -> None:
        packet = build()
        packet["scope"] = "synthetic and production replay"
        self.assertIn(
            "packet scope does not match the pinned synthetic-only scope", verify(packet)
        )

    def test_claim_boundary_replacement_fails(self) -> None:
        packet = build()
        packet["claim_boundary"] = "Anything goes."
        self.assertIn(
            "packet claim_boundary does not match the pinned synthetic-only boundary",
            verify(packet),
        )

    def test_fixture_id_substitution_fails(self) -> None:
        """Substituting the delegated authority's fixture_id without changing the
        profile record's authorization must be caught by their disagreement.

        In the shipped JSON packet the two are separate, equal objects; deep-copy
        the authority here so the substitution genuinely diverges the two, as it
        does in the distributed artifact rather than in build()'s shared reference."""
        packet = build()
        scenario = packet["scenarios"][0]
        scenario["delegated_authority"] = copy.deepcopy(scenario["delegated_authority"])
        scenario["delegated_authority"]["fixture_id"] = "other-fixture"
        self.assertIn(
            "allow-exact-action: delegated_authority and profile authorization disagree",
            verify(packet),
        )
