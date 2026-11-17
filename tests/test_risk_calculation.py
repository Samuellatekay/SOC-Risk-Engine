import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from pydantic import ValidationError

from src.config import Settings, settings
from src.main import calculate_risk
from src.models import RiskInput
from src.strategies import calculate_ahp_2026


class RiskCalculationTests(unittest.TestCase):
    def test_configured_strategy_is_used_when_request_omits_strategy(self):
        payload = RiskInput()

        with patch.object(settings, "risk_strategy", "ahp_2026"):
            result = calculate_risk(payload)

        self.assertEqual(result.breakdown["stage"], 0.5)

    def test_request_strategy_overrides_configured_strategy(self):
        payload = RiskInput(strategy="linear")

        with patch.object(settings, "risk_strategy", "ahp_2026"):
            result = calculate_risk(payload)

        self.assertIn("raw", result.breakdown)
        self.assertEqual(result.breakdown["final_multiplier"], 1.0)

    def test_external_and_internal_multipliers_load_from_environment(self):
        env = {
            "RISK_EXTERNAL_MULTIPLIER": "1.2",
            "RISK_INTERNAL_MULTIPLIER": "1.1",
        }

        with patch.dict(os.environ, env):
            configured = Settings(_env_file=None)

        self.assertEqual(configured.risk_external_multiplier, 1.2)
        self.assertEqual(configured.risk_internal_multiplier, 1.1)

    def test_journal_default_fallbacks_are_explicit_in_breakdown(self):
        result = calculate_ahp_2026(RiskInput())

        self.assertEqual(result.score, 38.52)
        self.assertEqual(result.level, "low")
        self.assertEqual(result.breakdown["target"], 0.57)
        self.assertEqual(result.breakdown["stage"], 0.5)
        self.assertEqual(result.breakdown["feas"], 0.46)
        self.assertEqual(result.breakdown["persist"], 0.54)
        self.assertEqual(result.breakdown["exploitability"], 0.3)
        self.assertEqual(result.breakdown["path_reachability"], 0.5)

    def test_journal_indicators_aggregate_to_their_criteria(self):
        payload = RiskInput(
            asset={
                "business_value": "core",
                "data_sensitivity": "top_secret",
                "attack_surface_exposure": "internet",
            },
            event={"phase_hazard": 1.0, "stage_policy_weight": 1.0},
            threat={
                "ioc_confidence": 1.0,
                "vulnerability_existence": "existing",
                "apt_association": 1.0,
                "intelligence_freshness": 1.0,
                "exploitability": "public_exploit",
                "path_reachability": "direct",
                "protection_bypass_evidence": True,
                "repeat_count": 5,
                "kill_chain_progression": True,
                "lateral_movement_potential": "jump_server",
            },
            environment={"external_multiplier": 1.0, "internal_multiplier": 1.0},
        )

        result = calculate_ahp_2026(payload)

        for criterion in ("target", "stage", "intel", "feas", "persist"):
            self.assertEqual(result.breakdown[criterion], 1.0)
        self.assertEqual(result.breakdown["env"], 0.0)
        self.assertEqual(result.score, 94.0)

    def test_journal_environment_multipliers_scale_base_score(self):
        payload = RiskInput(
            environment={"external_multiplier": 1.2, "internal_multiplier": 1.1}
        )

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.breakdown["env"], 1.0)
        self.assertEqual(result.breakdown["base_score"], 44.52)
        self.assertEqual(result.breakdown["final_multiplier"], 1.32)
        self.assertEqual(result.score, 58.77)
        self.assertEqual(result.level, "medium")

    def test_valid_opencti_graph_evidence_is_verified_and_used(self):
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        payload = RiskInput.model_validate({
            "graph": {
                "snapshot_id": "opencti:test-snapshot",
                "nodes": [
                    {"id": "alert:1", "type": "alert", "source": "event"},
                    {"id": "ioc:1", "type": "ipv4-addr", "source": "event"},
                    {
                        "id": "indicator:1",
                        "type": "indicator",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": timestamp,
                        "updated_at": timestamp,
                        "confidence": 0.9,
                        "valid_from": (now - timedelta(days=1)).isoformat(),
                    },
                ],
                "edges": [
                    {
                        "id": "observes:1",
                        "type": "observes",
                        "from": "alert:1",
                        "to": "ioc:1",
                        "source": "event",
                    },
                    {
                        "id": "matches:1",
                        "type": "matches_observable",
                        "from": "ioc:1",
                        "to": "indicator:1",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": timestamp,
                        "updated_at": timestamp,
                        "confidence": 0.9,
                    },
                ],
            }
        })

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.graph_validation.status, "valid")
        self.assertEqual(result.graph_validation.gate_decision, "retain")
        self.assertTrue(result.graph_validation.confirmed_ioc)
        self.assertEqual(result.graph_validation.ioc_confidence, 0.9)
        self.assertEqual(result.breakdown["ioc_confidence"], 0.9)

    def test_expired_graph_facts_are_quarantined_and_fall_back(self):
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        payload = RiskInput.model_validate({
            "graph": {
                "nodes": [
                    {"id": "ioc:1", "type": "ipv4-addr", "source": "event"},
                    {
                        "id": "indicator:1",
                        "type": "indicator",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": timestamp,
                        "updated_at": timestamp,
                        "confidence": 0.9,
                        "valid_until": (now - timedelta(days=1)).isoformat(),
                    },
                ],
                "edges": [
                    {
                        "id": "matches:1",
                        "type": "matches_observable",
                        "from": "ioc:1",
                        "to": "indicator:1",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": timestamp,
                        "updated_at": timestamp,
                        "confidence": 0.9,
                    }
                ],
            }
        })

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.graph_validation.status, "partial")
        self.assertEqual(result.graph_validation.gate_decision, "fallback")
        self.assertFalse(result.graph_validation.confirmed_ioc)
        self.assertIn("node_temporally_invalid", result.graph_validation.violations)
        self.assertEqual(result.score, 38.52)

    def test_graph_fact_without_provenance_is_quarantined(self):
        now = datetime.now(timezone.utc).isoformat()
        payload = RiskInput.model_validate({
            "graph": {
                "nodes": [
                    {"id": "ioc:1", "type": "ipv4-addr", "source": "event"},
                    {
                        "id": "indicator:1",
                        "type": "indicator",
                        "source": "opencti",
                        "acquired_at": now,
                        "updated_at": now,
                        "confidence": 0.9,
                    },
                ],
                "edges": [
                    {
                        "id": "matches:1",
                        "type": "matches_observable",
                        "from": "ioc:1",
                        "to": "indicator:1",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": now,
                        "updated_at": now,
                        "confidence": 0.9,
                    }
                ],
            }
        })

        result = calculate_ahp_2026(payload)

        self.assertFalse(result.graph_validation.confirmed_ioc)
        self.assertIn("node_provenance_missing", result.graph_validation.violations)
        self.assertEqual(result.graph_validation.gate_decision, "fallback")

    def test_graph_cannot_bypass_provenance_as_an_event_node(self):
        result = calculate_ahp_2026(RiskInput.model_validate({
            "graph": {
                "nodes": [
                    {"id": "ioc:1", "type": "ipv4-addr", "source": "event"},
                    {"id": "indicator:1", "type": "indicator", "source": "event"},
                ],
                "edges": [
                    {
                        "id": "matches:1",
                        "type": "matches_observable",
                        "from": "ioc:1",
                        "to": "indicator:1",
                        "source": "event",
                    }
                ],
            }
        }))

        self.assertFalse(result.graph_validation.confirmed_ioc)
        self.assertEqual(result.graph_validation.gate_decision, "fallback")
        self.assertIn("event_node_type_invalid", result.graph_validation.violations)

    def test_risk_gate_retains_high_criticality_asset_without_graph(self):
        result = calculate_ahp_2026(RiskInput(asset={"criticality": 4.0}))

        self.assertEqual(result.graph_validation.status, "not_provided")
        self.assertEqual(result.graph_validation.gate_decision, "retain")
        self.assertIn("high_criticality_asset", result.graph_validation.evidence)

    def test_apt_association_informs_score_but_does_not_alone_trigger_gate(self):
        now = datetime.now(timezone.utc).isoformat()
        result = calculate_ahp_2026(RiskInput.model_validate({
            "graph": {
                "nodes": [
                    {
                        "id": "intrusion-set:1",
                        "type": "intrusion-set",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": now,
                        "updated_at": now,
                        "confidence": 0.9,
                    },
                    {
                        "id": "threat-actor:1",
                        "type": "threat-actor",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": now,
                        "updated_at": now,
                        "confidence": 0.9,
                    },
                ],
                "edges": [
                    {
                        "id": "attributed:1",
                        "type": "attributed-to",
                        "from": "intrusion-set:1",
                        "to": "threat-actor:1",
                        "source": "opencti",
                        "provenance": "MISP",
                        "acquired_at": now,
                        "updated_at": now,
                        "confidence": 0.8,
                    }
                ],
            }
        }))

        self.assertTrue(result.graph_validation.apt_association)
        self.assertEqual(result.graph_validation.gate_decision, "fallback")
        self.assertEqual(result.breakdown["apt_association"], 1.0)

    def test_environment_multipliers_cap_final_score_at_100(self):
        payload = RiskInput(
            asset={"business_value": "core", "data_sensitivity": "top_secret"},
            event={"category": "malware"},
            threat={"ioc_match": True, "reputation_score": 100, "repeat_count": 50},
            environment={"external_multiplier": 10.0, "internal_multiplier": 10.0},
        )

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.score, 100)

    def test_accepts_categories_emitted_by_log_analyzer(self):
        for category in ("security", "configuration"):
            with self.subTest(category=category):
                payload = RiskInput.model_validate(
                    {"event": {"category": category}, "strategy": "ahp_2026"}
                )

                result = calculate_ahp_2026(payload)

                self.assertEqual(result.breakdown["stage"], 0.5)

    def test_rejects_out_of_range_risk_inputs(self):
        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"threat": {"reputation_score": 101}})

        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"event": {"category": "unknown"}})

        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"event": {"phase_hazard": 1.1}})

        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"environment": {"external_multiplier": 0.9}})


if __name__ == "__main__":
    unittest.main()
