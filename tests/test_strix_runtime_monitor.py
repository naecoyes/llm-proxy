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
        check_tcp.assert_called_once_with("proxy.example.com", 1080)

    @patch("strix_runtime_monitor.check_tcp", return_value={"reachable": True, "latency_ms": 12.5})
    def test_endpoint_change_does_not_reuse_stale_result(self, _check_tcp):
        monitor.parse_sing_box_config(self.config(), check_nodes=True)
        refreshed = monitor.parse_sing_box_config(self.config("new.example.com"), check_nodes=False)

        node = refreshed["outbounds"]["socks_nodes"][0]
        self.assertNotIn("tcp_check", node)


if __name__ == "__main__":
    unittest.main()
