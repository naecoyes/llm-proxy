import unittest
from unittest.mock import patch

import strix_runtime_monitor as monitor


class NodeConnectivityCacheTests(unittest.TestCase):
    def setUp(self):
        with monitor._NODE_CHECK_CACHE_LOCK:
            monitor._NODE_CHECK_CACHE.clear()

    @staticmethod
    def config(server="proxy.example.com"):
        return {
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "proxy-a",
                    "server": server,
                    "server_port": 1080,
                    "version": "5",
                },
                {"type": "selector", "tag": "proxy-auto", "outbounds": ["proxy-a"]},
            ]
        }

    @patch("strix_runtime_monitor.check_tcp", return_value={"reachable": True, "latency_ms": 12.5})
    def test_checked_result_survives_regular_refresh(self, check_tcp):
        checked = monitor.parse_sing_box_config(self.config(), check_nodes=True)
        refreshed = monitor.parse_sing_box_config(self.config(), check_nodes=False)

        first = checked["outbounds"]["socks_nodes"][0]["tcp_check"]
        second = refreshed["outbounds"]["socks_nodes"][0]["tcp_check"]
        self.assertTrue(second["reachable"])
        self.assertEqual(second["latency_ms"], 12.5)
        self.assertEqual(second["checked_at"], first["checked_at"])
        self.assertIn("next_check_at", second)
        check_tcp.assert_called_once_with("proxy.example.com", 1080)

    @patch("strix_runtime_monitor.check_tcp", return_value={"reachable": True, "latency_ms": 12.5})
    def test_endpoint_change_does_not_reuse_stale_result(self, _check_tcp):
        monitor.parse_sing_box_config(self.config(), check_nodes=True)
        refreshed = monitor.parse_sing_box_config(self.config("new.example.com"), check_nodes=False)

        node = refreshed["outbounds"]["socks_nodes"][0]
        self.assertNotIn("tcp_check", node)

    @patch("strix_runtime_monitor.check_tcp", return_value={"reachable": True, "latency_ms": 12.5})
    def test_daily_check_interval_skips_fresh_cache(self, check_tcp):
        first = monitor.parse_sing_box_config(self.config(), check_nodes=True)
        second = monitor.parse_sing_box_config(self.config(), check_nodes=True)

        self.assertEqual(
            first["outbounds"]["socks_nodes"][0]["tcp_check"]["checked_at"],
            second["outbounds"]["socks_nodes"][0]["tcp_check"]["checked_at"],
        )
        check_tcp.assert_called_once_with("proxy.example.com", 1080)

    @patch("strix_runtime_monitor.Path.is_file", return_value=True)
    @patch("strix_runtime_monitor.run_command", return_value={"ok": True, "returncode": 0, "stdout": "", "stderr": ""})
    @patch("strix_runtime_monitor.check_tcp", return_value={"reachable": False, "latency_ms": 2503.1, "error": "timed out"})
    def test_unavailable_active_node_is_auto_disabled(self, check_tcp, run_command, _is_file):
        status = monitor.parse_sing_box_config(self.config(), check_nodes=True)
        node = status["outbounds"]["socks_nodes"][0]

        self.assertFalse(node["in_auto_pool"])
        self.assertEqual(status["outbounds"]["auto_pool"], [])
        self.assertEqual(status["auto_actions"][0]["action"], "auto-disable-node")
        self.assertTrue(status["auto_actions"][0]["ok"])
        check_tcp.assert_called_once_with("proxy.example.com", 1080)
        run_command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
