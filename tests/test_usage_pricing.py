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

    def test_trend_uses_configured_provider_for_new_models(self):
        controller = self.make_controller(
            available={"hy3-free": {"provider": "hy3", "free": True}},
        )

        controller.record_usage("hy3-free", {"prompt_tokens": 100, "completion_tokens": 50})

        trend = controller.get_trend_data("4h")
        labels = {dataset["model"] for dataset in trend["datasets"]}

        self.assertIn("hy3", labels)
        self.assertNotIn("other", labels)

        by_model = controller.get_trend_data("4h", group_by="model")
        model_labels = {dataset["model"] for dataset in by_model["datasets"]}

        self.assertIn("hy3-free", model_labels)

    def test_legacy_model_aliases_do_not_fall_into_other(self):
        controller = self.make_controller()
        controller.record_usage("huoshan-doubao-code", {"total_tokens": 100})
        controller.record_usage("token-plan-cn-1", {"total_tokens": 100})

        trend = controller.get_trend_data("4h")
        labels = {dataset["model"] for dataset in trend["datasets"]}

        self.assertIn("volcengine", labels)
        self.assertIn("xiaomi", labels)
        self.assertNotIn("other", labels)

    def test_provider_dataset_lists_its_member_models(self):
        controller = self.make_controller(
            available={"tencent/hy3-free": {"provider": "openrouter", "free": True}},
        )
        controller.record_usage("tencent/hy3-free", {"total_tokens": 100})

        trend = controller.get_trend_data("4h")
        dataset = next(item for item in trend["datasets"] if item["model"] == "openrouter")

        self.assertEqual(dataset["models"], ["tencent/hy3-free"])

    def test_hourly_trend_never_returns_future_zero_buckets(self):
        controller = self.make_controller()
        controller.record_usage("deepseek-v4", {"total_tokens": 100})

        trend = controller.get_trend_data("4h")
        current_hour = __import__("datetime").datetime.now().astimezone().hour

        self.assertEqual(trend["labels"][-1], str(current_hour))
        self.assertEqual(len(trend["datasets"][0]["tokens"]), current_hour + 1)


if __name__ == "__main__":
    unittest.main()
