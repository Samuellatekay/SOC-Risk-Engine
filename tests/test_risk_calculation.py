import unittest
from unittest.mock import patch

from pydantic import ValidationError

from src.config import settings
from src.main import calculate_risk
from src.models import RiskInput
from src.strategies import calculate_ahp_2026


class RiskCalculationTests(unittest.TestCase):
    def test_configured_strategy_is_used_when_request_omits_strategy(self):
        payload = RiskInput()

        with patch.object(settings, "risk_strategy", "ahp_2026"):
            result = calculate_risk(payload)

        self.assertEqual(result.breakdown["stage"], 0.367)

    def test_request_strategy_overrides_configured_strategy(self):
        payload = RiskInput(strategy="linear")

        with patch.object(settings, "risk_strategy", "ahp_2026"):
            result = calculate_risk(payload)

        self.assertIn("raw", result.breakdown)
        self.assertEqual(result.breakdown["global_multiplier"], 1.0)

    def test_environment_multiplier_scales_final_score_and_level(self):
        payload = RiskInput(strategy="ahp_2026")

        with patch.object(settings, "risk_environment_multiplier", 1.2):
            result = calculate_ahp_2026(payload)

        self.assertEqual(result.score, 41.32)
        self.assertEqual(result.level, "medium")
        self.assertEqual(result.breakdown["global_multiplier"], 1.2)

    def test_environment_multiplier_caps_final_score_at_100(self):
        payload = RiskInput(
            asset={"business_value": "core", "data_sensitivity": "top_secret"},
            event={"category": "malware"},
            threat={"ioc_match": True, "reputation_score": 100, "repeat_count": 50},
            environment={"external_multiplier": 1.2, "internal_multiplier": 1.2},
        )

        with patch.object(settings, "risk_environment_multiplier", 10.0):
            result = calculate_ahp_2026(payload)

        self.assertEqual(result.score, 100)

    def test_zero_day_domain_is_treated_as_high_risk(self):
        # FIX: Newly registered domains (0 days) are a high-risk indicator in SOC.
        # Therefore, feasibility score should be 1.0 (high risk), not 0.3.
        payload = RiskInput.model_validate(
            {"threat": {"domain_age_days": 0}, "strategy": "ahp_2026"}
        )

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.breakdown["feas"], 1.0)

    def test_accepts_categories_emitted_by_log_analyzer(self):
        for category in ("security", "configuration"):
            with self.subTest(category=category):
                payload = RiskInput.model_validate(
                    {"event": {"category": category}, "strategy": "ahp_2026"}
                )

                result = calculate_ahp_2026(payload)

                self.assertEqual(result.breakdown["stage"], 0.367)

    def test_rejects_out_of_range_risk_inputs(self):
        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"threat": {"reputation_score": 101}})

        with self.assertRaises(ValidationError):
            RiskInput.model_validate({"event": {"category": "unknown"}})

    def test_ahp_env_factor_is_clamped_to_one(self):
        payload = RiskInput(
            environment={"external_multiplier": 2.0, "internal_multiplier": 2.0},
            strategy="ahp_2026",
        )

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.breakdown["env"], 1.0)

    def test_unknown_domain_age_is_neutral(self):
        payload = RiskInput.model_validate({"strategy": "ahp_2026"})

        result = calculate_ahp_2026(payload)

        self.assertEqual(result.breakdown["feas"], 0.5)

    def test_linear_breakdown_is_normalized(self):
        payload = RiskInput(
            asset={"criticality": 5},
            event={"severity": 5, "outcome": 1},
            threat={"base_weight": 5},
            strategy="linear",
        )

        result = calculate_risk(payload)

        self.assertEqual(result.breakdown["asset"], 1.0)
        self.assertEqual(result.breakdown["severity"], 1.0)
        self.assertEqual(result.breakdown["outcome"], 1.0)
        self.assertEqual(result.breakdown["threat"], 1.0)

    def test_risk_level_boundaries(self):
        from src.strategies import get_risk_level

        self.assertEqual(get_risk_level(39.99), "low")
        self.assertEqual(get_risk_level(40.0), "medium")
        self.assertEqual(get_risk_level(59.99), "medium")
        self.assertEqual(get_risk_level(60.0), "high")
        self.assertEqual(get_risk_level(79.99), "high")
        self.assertEqual(get_risk_level(80.0), "critical")


if __name__ == "__main__":
    unittest.main()
