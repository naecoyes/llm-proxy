import tempfile
import unittest

from model_manager import ModelManager, NoAvailableModelError


class VisionAssistModelTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.manager = ModelManager(
            {
                "providers": {"openrouter": {}},
                "models": {
                    "available": {
                        "vision": {
                            "model": "tencent/hy3:free",
                            "api_key": "test-key",
                            "api_base": "https://example.invalid/v1",
                            "provider": "openrouter",
                            "vision_assist_enabled": True,
                        },
                    },
                },
                "usage": {"per_model_limits": {}},
            },
            stats_dir=self.temp_dir.name,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dedicated_vision_model_is_not_an_auto_candidate(self):
        status = self.manager.get_model_routing_status(
            "vision", {"scan_mode": "redteam"}
        )
        self.assertFalse(status["eligible"])
        self.assertEqual(status["reason"], "vision_assist_only")

    def test_explicit_selection_reserves_configured_model(self):
        name, config = self.manager.select_vision_assist_model("vision")
        self.assertEqual(name, "vision")
        self.assertTrue(config.vision_supported)
        self.manager.usage_controller.release_model(name)

    def test_missing_model_is_rejected_without_fallback(self):
        with self.assertRaises(NoAvailableModelError):
            self.manager.select_vision_assist_model("missing")


if __name__ == "__main__":
    unittest.main()
