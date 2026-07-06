import tempfile
import unittest

from usage_controller import UsageController


class UsagePricingTests(unittest.TestCase):
    def make_controller(self, available=None, limits=None):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        return UsageController(
            {
                "models": {"available": available or {}},
                "usage": {
                    "per_model_limits": limits or {},
                    "max_tokens_per_day": 999999999,
                    "max_tokens_per_request": 999999999,
                    "daily_budget": 999999.0,
                    "monthly_budget": 999999.0,
                },
            },
            self.temp_dir.name,
        )

    def test_free_model_has_zero_marginal_cost(self):
        controller = self.make_controller(
            available={"openrouter/owl-alpha": {"free": True}},
            limits={"openrouter/owl-alpha": {"input_cost_per_1m": 1.74, "output_cost_per_1m": 3.48}},
        )

        controller.record_usage("openrouter/owl-alpha", {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000})

        self.assertEqual(controller.model_stats["openrouter/owl-alpha"].cost, 0.0)

    def test_subscription_model_has_zero_marginal_cost(self):
        controller = self.make_controller(
            available={"xiaomi-mimo-sgp-1": {"billing_mode": "subscription"}},
            limits={"xiaomi-mimo-sgp-1": {"input_cost_per_1m": 1.74, "output_cost_per_1m": 3.48}},
        )

        controller.record_usage("xiaomi-mimo-sgp-1", {"prompt_tokens": 2_000_000, "completion_tokens": 1_000_000})

        self.assertEqual(controller.model_stats["xiaomi-mimo-sgp-1"].cost, 0.0)

    def test_model_price_aliases_are_used(self):
        controller = self.make_controller(
            available={"or-gemini": {"input_price": 0.435, "output_price": 0.87}},
        )

        controller.record_usage("or-gemini", {"prompt_tokens": 2_000_000, "completion_tokens": 1_000_000})

        self.assertAlmostEqual(controller.model_stats["or-gemini"].cost, 1.74)


if __name__ == "__main__":
    unittest.main()
