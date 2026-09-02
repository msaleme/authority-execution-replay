from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from profile import validate
from event_bundle import bundle_for
from executor import cross_profile_receipt, observation_for


NOW = datetime(2026, 8, 7, tzinfo=UTC)


def record(state: str = "EXECUTED") -> dict:
    item = {
        "schema_version": "0.1-internal",
        "subject": {"artifact_sha256": "a" * 64},
        "authorization": {
            "decision_id": "fixture-decision-1",
            "action_digest": "b" * 64,
            "expires_at": "2026-08-08T00:00:00Z",
            "fixture_id": "authority-profile-fixture-v1",
        },
        "execution": {"state": state},
        "claim": {"occurred": state == "EXECUTED"},
    }
    if state == "EXECUTED":
        item["execution"] = cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")
    elif state == "DENIED_BEFORE_EXECUTION":
        item["execution"] = cross_profile_receipt(item["authorization"], "FIXTURE_DENIED")
    return item


class AuthorityExecutionProfileTests(unittest.TestCase):
    def test_record_must_be_object(self) -> None:
        self.assertEqual(validate(["caller-asserted-record"], NOW), ["record must be an object"])

    def test_execution_requires_bound_receipt(self) -> None:
        self.assertEqual(validate(record(), NOW), [])

    def test_static_or_denied_state_cannot_claim_execution(self) -> None:
        item = record("DENIED_BEFORE_EXECUTION")
        item["claim"]["occurred"] = True
        self.assertIn("claim occurrence conflicts with execution state", validate(item, NOW))

    def test_claim_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["claim"]["provider_quality"] = "verified"
        self.assertIn("claim contains unsupported fields: provider_quality", validate(item, NOW))

    def test_record_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["external_attestation"] = "verified"
        self.assertIn("record contains unsupported fields: external_attestation", validate(item, NOW))

    def test_subject_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["subject"]["external_attestation"] = "verified"
        self.assertIn("subject contains unsupported fields: external_attestation", validate(item, NOW))

    def test_authorization_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["authorization"]["external_policy_attestation"] = "verified"
        self.assertIn("authorization contains unsupported fields: external_policy_attestation", validate(item, NOW))

    def test_observation_producer_rejects_unprofiled_authorization_fields(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["external_policy_attestation"] = "verified"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_producer_rejects_non_object_authorization(self) -> None:
        with self.assertRaisesRegex(ValueError, "authorization must be an object"):
            cross_profile_receipt(["caller-asserted-authorization"], "FIXTURE_EXECUTED")

    def test_execution_receipt_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["execution"]["receipt"]["external_attestation"] = "verified"
        self.assertIn("execution receipt contains unsupported fields: external_attestation", validate(item, NOW))

    def test_execution_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["execution"]["external_attestation"] = "verified"
        self.assertIn("execution contains unsupported fields: external_attestation", validate(item, NOW))

    def test_controlled_observation_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["execution"]["observation"]["external_attestation"] = "verified"
        self.assertIn("controlled observation contains unsupported fields: external_attestation", validate(item, NOW))

    def test_non_execution_state_rejects_self_asserted_receipt(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["execution"]["receipt"] = {"executor_id": "self"}
        self.assertIn("non-executed states must not carry an execution receipt", validate(item, NOW))

    def test_receipt_must_bind_to_authorized_action(self) -> None:
        item = record()
        item["execution"]["receipt"]["action_digest"] = "d" * 64
        self.assertIn("execution receipt action digest is not bound to authorization", validate(item, NOW))

    def test_observation_and_receipt_must_bind_to_authorization_decision(self) -> None:
        item = record()
        item["execution"]["observation"]["decision_id"] = "fixture-decision-2"
        item["execution"]["receipt"]["decision_id"] = "fixture-decision-2"
        errors = validate(item, NOW)
        self.assertIn("controlled observation decision id is not bound to authorization", errors)
        self.assertIn("execution receipt decision id is not bound to authorization", errors)

    def test_expired_authorization_fails_closed(self) -> None:
        item = record()
        item["authorization"]["expires_at"] = "2026-08-06T00:00:00Z"
        self.assertIn("authorization is expired", validate(item, NOW))

    def test_authorization_expiry_must_be_utc_iso8601(self) -> None:
        item = record()
        item["authorization"]["expires_at"] = "2026-08-07T19:00:00-05:00"
        self.assertIn("authorization expiry must be UTC ISO-8601", validate(item, NOW))

    def test_cross_profile_receipt_requires_observable_fixture_marker(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["execution"] = cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")
        item["claim"]["occurred"] = True
        self.assertEqual(validate(item, NOW), [])

    def test_denial_receipt_does_not_claim_execution(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["execution"] = cross_profile_receipt(item["authorization"], "FIXTURE_DENIED")
        self.assertFalse(item["claim"]["occurred"])
        self.assertEqual(validate(item, NOW), [])

    def test_execution_receipt_must_bind_to_observation(self) -> None:
        item = record()
        item["execution"]["receipt"]["evidence_sha256"] = "d" * 64
        self.assertIn("execution receipt is not bound to controlled observation", validate(item, NOW))

    def test_execution_receipt_bundle_digest_must_bind_to_observation(self) -> None:
        item = record()
        item["execution"]["receipt"]["bundle_sha256"] = "d" * 64
        self.assertIn(
            "execution receipt bundle digest is not bound to controlled observation",
            validate(item, NOW),
        )

    def test_execution_receipt_executor_must_bind_to_observation(self) -> None:
        item = record()
        item["execution"]["receipt"]["executor_id"] = "different-executor"
        self.assertIn("execution receipt executor is not bound to controlled observation", validate(item, NOW))

    def test_controlled_observation_executor_must_be_owned_fixture_executor(self) -> None:
        item = record()
        item["execution"]["observation"]["executor_id"] = "caller-asserted-executor"
        event = {
            key: item["execution"]["observation"][key]
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
        item["execution"]["bundle"] = bundle_for(event)
        item["execution"]["observation"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        item["execution"]["observation"]["bundle_sha256"] = item["execution"]["bundle"]["bundle_sha256"]
        item["execution"]["receipt"]["executor_id"] = "caller-asserted-executor"
        item["execution"]["receipt"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        self.assertIn("controlled observation executor is not the synthetic fixture executor", validate(item, NOW))

    def test_observation_producer_rejects_caller_supplied_executor_identity(self) -> None:
        item = record("NOT_ATTEMPTED")
        with self.assertRaisesRegex(ValueError, "synthetic fixture executor"):
            observation_for(item["authorization"], "FIXTURE_EXECUTED", executor_id="caller-asserted-executor")

    def test_observation_producer_rejects_malformed_marker_type(self) -> None:
        item = record("NOT_ATTEMPTED")
        with self.assertRaisesRegex(ValueError, "marker must be a non-empty string"):
            observation_for(item["authorization"], ["FIXTURE_EXECUTED"])

    def test_execution_receipt_timestamp_must_bind_to_observation(self) -> None:
        item = record()
        item["execution"]["receipt"]["occurred_at"] = "2026-08-07T03:00:00Z"
        self.assertIn("execution receipt timestamp is not bound to controlled observation", validate(item, NOW))

    def test_observation_and_receipt_timestamps_must_be_timezone_aware_iso8601(self) -> None:
        item = record()
        item["execution"]["observation"]["observed_at"] = "not-a-timestamp"
        item["execution"]["receipt"]["occurred_at"] = "not-a-timestamp"
        errors = validate(item, NOW)
        self.assertIn("controlled observation timestamp must be UTC ISO-8601", errors)
        self.assertIn("execution receipt timestamp must be UTC ISO-8601", errors)

    def test_observation_and_receipt_timestamps_must_be_utc_iso8601(self) -> None:
        item = record()
        item["execution"]["observation"]["observed_at"] = "2026-08-06T21:00:00-05:00"
        item["execution"]["receipt"]["occurred_at"] = "2026-08-06T21:00:00-05:00"
        event = {
            key: item["execution"]["observation"][key]
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
        item["execution"]["bundle"] = bundle_for(event)
        item["execution"]["observation"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        item["execution"]["observation"]["bundle_sha256"] = item["execution"]["bundle"]["bundle_sha256"]
        item["execution"]["receipt"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        item["execution"]["receipt"]["bundle_sha256"] = item["execution"]["bundle"]["bundle_sha256"]
        errors = validate(item, NOW)
        self.assertIn("controlled observation timestamp must be UTC ISO-8601", errors)
        self.assertIn("execution receipt timestamp must be UTC ISO-8601", errors)

    def test_observation_and_receipt_timestamps_must_be_inside_authorization_window(self) -> None:
        item = record()
        item["authorization"]["expires_at"] = "2026-08-07T01:00:00Z"
        errors = validate(item)
        self.assertIn("controlled observation timestamp is outside authorization window", errors)
        self.assertIn("execution receipt timestamp is outside authorization window", errors)

    def test_observation_producer_rejects_expired_authorization_window(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["expires_at"] = "2026-08-07T01:00:00Z"
        with self.assertRaisesRegex(ValueError, "after the fixture observation time"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_arbitrary_observation_marker_cannot_mint_a_receipt(self) -> None:
        item = record()
        item["execution"]["observation"]["marker_id"] = "CALLER_SAYS_EXECUTED"
        self.assertIn("controlled observation marker is not recognized", validate(item, NOW))

    def test_marker_state_binding_cannot_be_relabelled(self) -> None:
        item = record()
        item["execution"]["observation"]["marker_id"] = "FIXTURE_DENIED"
        self.assertIn("controlled observation marker conflicts with execution state", validate(item, NOW))

    def test_observation_must_bind_to_authorized_fixture(self) -> None:
        item = record()
        item["execution"]["observation"]["fixture_id"] = "other-fixture"
        self.assertIn("controlled observation fixture is not bound to authorization", validate(item, NOW))

    def test_unknown_fixture_cannot_mint_an_observation(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["fixture_id"] = "unowned-fixture"
        with self.assertRaisesRegex(ValueError, "declared owned fixture"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_authorization_fixture_id_must_be_canonical(self) -> None:
        item = record()
        item["authorization"]["fixture_id"] = "../authority-profile-fixture-v1"
        item["execution"]["observation"]["fixture_id"] = "../authority-profile-fixture-v1"
        self.assertIn("authorization fixture id must be a canonical identifier", validate(item, NOW))

    def test_controlled_observation_fixture_id_must_be_canonical(self) -> None:
        item = record()
        item["execution"]["observation"]["fixture_id"] = "../authority-profile-fixture-v1"
        self.assertIn("controlled observation fixture id must be a canonical identifier", validate(item, NOW))

    def test_observation_producer_rejects_noncanonical_fixture_id(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["fixture_id"] = "../authority-profile-fixture-v1"
        with self.assertRaisesRegex(ValueError, "fixture id must be a canonical identifier"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_producer_rejects_malformed_authorization_fixture_id(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["fixture_id"] = ["authority-profile-fixture-v1"]
        with self.assertRaisesRegex(ValueError, "fixture id"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_unknown_authorization_fixture_fails_closed(self) -> None:
        item = record()
        item["authorization"]["fixture_id"] = "unowned-fixture"
        item["execution"]["observation"]["fixture_id"] = "unowned-fixture"
        event = {
            key: item["execution"]["observation"][key]
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
        item["execution"]["bundle"] = bundle_for(event)
        item["execution"]["observation"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        item["execution"]["observation"]["bundle_sha256"] = item["execution"]["bundle"]["bundle_sha256"]
        item["execution"]["receipt"]["evidence_sha256"] = item["execution"]["bundle"]["event_sha256"]
        item["execution"]["receipt"]["bundle_sha256"] = item["execution"]["bundle"]["bundle_sha256"]
        self.assertIn("authorization fixture is not a declared owned fixture", validate(item, NOW))

    def test_rewritten_fixture_event_bundle_fails_closed(self) -> None:
        item = record()
        item["execution"]["bundle"]["events"][0]["marker_id"] = "FIXTURE_DENIED"
        self.assertIn("observable execution state requires an intact fixture event bundle", validate(item, NOW))

    def test_fixture_event_bundle_cannot_add_unprofiled_assertions(self) -> None:
        item = record()
        item["execution"]["bundle"]["external_attestation"] = "caller-asserted"
        self.assertIn("observable execution state requires an intact fixture event bundle", validate(item, NOW))

    def test_fixture_event_bundle_builder_rejects_unprofiled_event_fields(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["external_attestation"] = "caller-asserted"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            bundle_for(event)

    def test_fixture_event_bundle_builder_rejects_non_string_event_fields(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["decision_id"] = {"caller": "asserted"}
        with self.assertRaisesRegex(ValueError, "event fields must be strings"):
            bundle_for(event)

    def test_fixture_event_bundle_builder_rejects_empty_event_fields(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["decision_id"] = ""
        with self.assertRaisesRegex(ValueError, "event fields must be non-empty strings"):
            bundle_for(event)

    def test_fixture_event_bundle_builder_rejects_noncanonical_event_ids(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["decision_id"] = "../fixture-decision-1"
        with self.assertRaisesRegex(ValueError, "canonical identifiers"):
            bundle_for(event)

    def test_fixture_event_bundle_rejects_noncanonical_event_ids(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["fixture_id"] = "../authority-profile-fixture-v1"
        item["execution"]["bundle"] = {
            "bundle_version": "0.1-internal",
            "events": [event],
            "event_sha256": item["execution"]["bundle"]["event_sha256"],
            "bundle_sha256": item["execution"]["bundle"]["bundle_sha256"],
        }
        self.assertIn("observable execution state requires an intact fixture event bundle", validate(item, NOW))

    def test_fixture_event_bundle_rejects_retyped_event_fields(self) -> None:
        item = record()
        event = dict(item["execution"]["bundle"]["events"][0])
        event["decision_id"] = ["fixture-decision-1"]
        item["execution"]["bundle"] = {
            "bundle_version": "0.1-internal",
            "events": [event],
            "event_sha256": item["execution"]["bundle"]["event_sha256"],
            "bundle_sha256": item["execution"]["bundle"]["bundle_sha256"],
        }
        self.assertIn("observable execution state requires an intact fixture event bundle", validate(item, NOW))

    def test_valid_adjacent_bundle_cannot_replace_observation_event(self) -> None:
        replacement = record()
        item = record()
        replacement["authorization"]["action_digest"] = "c" * 64
        replacement["execution"] = cross_profile_receipt(replacement["authorization"], "FIXTURE_EXECUTED")
        item["execution"]["bundle"] = replacement["execution"]["bundle"]
        item["execution"]["observation"]["evidence_sha256"] = replacement["execution"]["bundle"]["event_sha256"]
        item["execution"]["observation"]["bundle_sha256"] = replacement["execution"]["bundle"]["bundle_sha256"]
        item["execution"]["receipt"]["evidence_sha256"] = replacement["execution"]["bundle"]["event_sha256"]
        self.assertIn("fixture event bundle does not match controlled observation", validate(item, NOW))

    def test_subject_artifact_digest_must_be_hex(self) -> None:
        item = record()
        item["subject"]["artifact_sha256"] = "z" * 64
        self.assertIn("subject artifact SHA-256 must be 64 hex characters", validate(item, NOW))

    def test_authorization_action_digest_must_be_sha256_hex(self) -> None:
        item = record()
        item["authorization"]["action_digest"] = "not-a-digest"
        self.assertIn("authorization action digest must be a 64-character SHA-256 hex digest", validate(item, NOW))

    def test_authorization_decision_id_must_be_canonical(self) -> None:
        item = record()
        item["authorization"]["decision_id"] = "../fixture-decision-1"
        item["execution"]["observation"]["decision_id"] = "../fixture-decision-1"
        item["execution"]["receipt"]["decision_id"] = "../fixture-decision-1"
        self.assertIn("authorization decision id must be a canonical identifier", validate(item, NOW))

    def test_receipt_and_observation_decision_ids_must_be_canonical(self) -> None:
        item = record()
        item["execution"]["observation"]["decision_id"] = "../fixture-decision-1"
        item["execution"]["receipt"]["decision_id"] = "../fixture-decision-1"
        errors = validate(item, NOW)
        self.assertIn("controlled observation decision id must be a canonical identifier", errors)
        self.assertIn("execution receipt decision id must be a canonical identifier", errors)

    def test_observation_producer_rejects_noncanonical_decision_id(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["decision_id"] = "../fixture-decision-1"
        with self.assertRaisesRegex(ValueError, "canonical identifier"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_producer_rejects_malformed_authorization_action_digest(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["action_digest"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "SHA-256 hex digest"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_producer_rejects_malformed_authorization_expiry(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["expires_at"] = "not-a-timestamp"
        with self.assertRaisesRegex(ValueError, "timezone-aware ISO-8601"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_producer_rejects_offset_authorization_expiry(self) -> None:
        item = record("NOT_ATTEMPTED")
        item["authorization"]["expires_at"] = "2026-08-07T19:00:00-05:00"
        with self.assertRaisesRegex(ValueError, "UTC ISO-8601"):
            cross_profile_receipt(item["authorization"], "FIXTURE_EXECUTED")

    def test_observation_and_receipt_digests_must_be_sha256_hex(self) -> None:
        item = record()
        item["execution"]["observation"]["evidence_sha256"] = "z" * 64
        item["execution"]["receipt"]["evidence_sha256"] = "z" * 64
        item["execution"]["receipt"]["bundle_sha256"] = "z" * 64
        errors = validate(item, NOW)
        self.assertIn("controlled observation evidence_sha256 must be a 64-character SHA-256 hex digest", errors)
        self.assertIn("execution receipt evidence_sha256 must be a 64-character SHA-256 hex digest", errors)
        self.assertIn("execution receipt bundle_sha256 must be a 64-character SHA-256 hex digest", errors)

    def test_controlled_observation_requires_bundle_digest(self) -> None:
        item = record()
        del item["execution"]["observation"]["bundle_sha256"]
        self.assertIn("controlled observation requires bundle_sha256", validate(item, NOW))

    def test_unattempted_state_cannot_carry_fixture_event_bundle(self) -> None:
        executed = record()
        item = record("NOT_ATTEMPTED")
        item["execution"]["bundle"] = executed["execution"]["bundle"]
        self.assertIn("unattempted state must not carry a fixture event bundle", validate(item, NOW))
