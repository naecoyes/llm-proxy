import tempfile
import unittest
from pathlib import Path

from asset_database import AssetDatabase


class OperationalSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = AssetDatabase(Path(self.temp_dir.name) / "nscan.sqlite3")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_llm_events_are_joinable_from_sqlite(self):
        context = {"scan_id": "scan-1", "scan_target": "example.com", "proxy_slot": "auto1"}
        self.db.record_llm_event({
            "type": "request", "timestamp": "2026-07-01T10:00:00", "request_id": "req-1",
            "actual_model": "model-a", "provider": "provider-a", **context,
        })
        self.db.record_llm_event({
            "type": "model_switch", "timestamp": "2026-07-01T10:00:01", "request_id": "req-1",
            "from_model": "model-a", "to_model": "model-b", "reason": "fallback", **context,
        })
        self.db.record_llm_event({
            "type": "response", "timestamp": "2026-07-01T10:00:02", "request_id": "req-1",
            "model_name": "model-b", "status": "success", "usage": {"total_tokens": 42}, **context,
        })
        events = self.db.read_llm_events(
            start_date="2026-07-01", end_date="2026-07-01", scan_id="scan-1"
        )
        self.assertEqual([event["type"] for event in events], ["request", "model_switch", "response"])
        self.assertEqual(events[-1]["usage"]["total_tokens"], 42)

    def test_usage_health_controls_and_review_state_are_persisted(self):
        self.db.sync_usage_snapshot({
            "date": "2026-07-01",
            "total": {"requests": 2, "tokens": 30},
            "models": {"model-a": {"requests": 2, "tokens": 30, "input_tokens": 20, "output_tokens": 10}},
            "hourly": {"10": {"model-a": {"requests": 2, "tokens": 30}}},
        })
        self.db.sync_health_snapshot({"model-a": {"healthy": False, "reason": "rate_limit"}})
        self.db.record_batch_control({
            "batch_id": "batch-1", "parallel": 4, "source": "dashboard",
            "requested_at": "2026-07-01T10:01:00+00:00",
        })
        self.db.sync_finding_review_state({
            "tags": {"target:finding": ["reviewed"]},
            "stars": {"target:finding": True},
            "verified": {"target:finding": False},
        })
        with self.db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM model_usage_daily").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT healthy FROM model_health_state").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT requested_parallel FROM batch_controls").fetchone()[0], 4)
            review = connection.execute("SELECT starred,verified FROM finding_review_state").fetchone()
            self.assertEqual(tuple(review), (1, 0))


if __name__ == "__main__":
    unittest.main()
