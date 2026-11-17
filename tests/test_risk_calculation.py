import os
import unittest
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
