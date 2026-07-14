import unittest

from server import (
    SCAN_CONTAINER_ALLOWED_PATHS,
    deep_merge_config,
    is_scan_container_peer,
    parse_scan_container_subnets,
    validate_proxy_config,
)


class ProxyHardeningTests(unittest.TestCase):
    def setUp(self):
        self.base_config = {
            "admin": {"enabled": True},
            "server": {"allowed_ips": ["127.0.0.1"]},
            "providers": {"deepseek": {"fallback_models": ["model-a"]}},
            "models": {
                "available": {
                    "model-a": {
                        "model": "deepseek-chat",
                        "api_base": "https://api.deepseek.com",
                        "provider": "deepseek",
                        "enabled": True,
                    }
                }
            },
            "usage": {"per_model_limits": {}},
        }

    def test_deep_merge_preserves_unspecified_sections(self):
        merged = deep_merge_config(
            self.base_config,
            {"admin": {"enabled": False}, "server": {"allowed_ips": ["10.0.0.1"]}},
        )

        self.assertFalse(merged["admin"]["enabled"])
        self.assertEqual(merged["server"]["allowed_ips"], ["10.0.0.1"])
        self.assertIn("deepseek", merged["providers"])
        self.assertIn("model-a", merged["models"]["available"])

    def test_deep_merge_does_not_erase_models_with_empty_patch(self):
        merged = deep_merge_config(self.base_config, {"models": {"available": {}}})
        self.assertIn("model-a", merged["models"]["available"])

    def test_validate_proxy_config_rejects_missing_models(self):
        broken = deep_merge_config(self.base_config, {"models": None})
        with self.assertRaisesRegex(ValueError, "models"):
            validate_proxy_config(broken)

    def test_validate_proxy_config_rejects_unknown_provider_reference(self):
        broken = deep_merge_config(
            self.base_config,
            {"models": {"available": {"model-a": {"provider": "missing"}}}},
        )
        with self.assertRaisesRegex(ValueError, "unknown provider"):
            validate_proxy_config(broken)

    def test_scan_container_subnets_default_and_match(self):
        networks = parse_scan_container_subnets(self.base_config)
        self.assertTrue(is_scan_container_peer("172.29.0.3", networks))
        self.assertFalse(is_scan_container_peer("192.168.0.100", networks))

    def test_allowed_scan_container_paths_are_inference_only(self):
        self.assertEqual(
            SCAN_CONTAINER_ALLOWED_PATHS,
            {"/v1/chat/completions", "/v1/models"},
        )


if __name__ == "__main__":
    unittest.main()
