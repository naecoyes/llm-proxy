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

        history = self.db.usage_history(days=30)
        self.assertEqual(history["2026-07-01"]["models"]["model-a"]["tokens"], 30)

    def test_hourly_response_usage_uses_response_ledger(self):
        self.db.record_llm_event({
            "type": "response", "timestamp": "2026-07-01T11:15:00", "request_id": "usage-1",
            "model_name": "model-a", "status": "success",
            "usage": {"prompt_tokens": 80, "completion_tokens": 20, "total_tokens": 100},
        })

        hourly = self.db.hourly_response_usage(usage_date="2026-07-01")
        self.assertEqual(hourly["11"]["model-a"]["requests"], 1)
        self.assertEqual(hourly["11"]["model-a"]["tokens"], 100)

    def test_full_smart_batch_and_job_snapshots_are_persisted(self):
        batch = {
            "batch_id": "smart-batch-db-test", "status": "running", "updated_at": "2026-07-01T10:00:00+00:00",
            "parallel": 2, "tasks": [{"target": "example.ae", "status": "running", "scan_id": "scan-1"}],
        }
        self.db.sync_batch_snapshot(batch, "/tmp/smart-batch-db-test.json")
        restored = self.db.smart_batch_snapshot("smart-batch-db-test")
        self.assertEqual(restored["tasks"][0]["scan_id"], "scan-1")
        self.assertEqual(self.db.smart_batch_snapshots(limit=10)[0]["batch_id"], "smart-batch-db-test")

        job = {
            "job_id": "dashboard-db-test", "status": "started", "engine": "dual", "phase": "strix",
            "submitted_at": "2026-07-01T10:00:00+00:00", "children": [{"engine": "strix", "status": "running"}],
        }
        self.db.sync_smart_batch_job(job, "/tmp/dashboard-db-test.json")
        restored_job = self.db.smart_batch_job("dashboard-db-test")
        self.assertEqual(restored_job["children"][0]["engine"], "strix")

    def test_assets_can_filter_zero_findings_for_coverage_rescan(self):
        zero_id = self.db.upsert_asset("zero.example.ae", source_type="test")
        finding_id = self.db.upsert_asset("finding.example.ae", source_type="test")
        with self.db.transaction() as connection:
            connection.execute("UPDATE assets SET finding_count=0,last_scan_status='success' WHERE id=?", (zero_id,))
            connection.execute("UPDATE assets SET finding_count=3,last_scan_status='success' WHERE id=?", (finding_id,))
            connection.execute(
                """INSERT INTO finding_refs(record_id,asset_id,title,severity)
                VALUES('existing-finding',?,'Existing issue','HIGH')""",
                (finding_id,),
            )

        result = self.db.list_assets(scan_status="success", finding_max=0)

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["target"], "zero.example.ae")

    def test_retest_lookup_is_exact_asset_and_includes_review_state(self):
        asset_id = self.db.upsert_asset("portal.example.ae", source_type="test")
        with self.db.transaction() as connection:
            connection.execute(
                "INSERT INTO finding_refs(record_id,asset_id,finding_id,title,severity,metadata_json) VALUES(?,?,?,?,?,?)",
                ("finding-1", asset_id, "V-1", "Existing issue", "HIGH", '{"target":"portal.example.ae"}'),
            )
            connection.execute(
                "INSERT INTO finding_review_state(state_key,verified,archived,updated_at) VALUES(?,?,?,?)",
                ("portal.example.ae:V-1:Existing issue", 1, 0, "2026-07-01T00:00:00Z"),
            )
        baseline = self.db.retest_asset_findings(["https://portal.example.ae/login"])
        self.assertEqual(baseline["portal.example.ae"]["asset_id"], asset_id)
        self.assertEqual(baseline["portal.example.ae"]["findings"][0]["record_id"], "finding-1")
        self.assertEqual(baseline["portal.example.ae"]["findings"][0]["verified"], 1)

    def test_finding_catalog_refreshes_asset_counts_authoritatively(self):
        self.db.upsert_asset("clean.example.ae", source_type="test")
        self.db.sync_finding_catalog([
            {
                "record_id": "finding-1",
                "target": "vulnerable.example.ae",
                "id": "VULN-1",
                "title": "Example issue",
                "severity": "HIGH",
                "source_file": "catalog.csv",
            }
        ])

        zero = self.db.list_assets(finding_max=0)
        vulnerable = self.db.list_assets(finding_min=1)

        self.assertEqual([item["target"] for item in zero["items"]], ["clean.example.ae"])
        self.assertEqual([item["target"] for item in vulnerable["items"]], ["vulnerable.example.ae"])

    def test_finding_catalog_maps_run_directory_to_real_asset(self):
        asset_id = self.db.upsert_asset("portal.example.ae", source_type="run", source_ref="/runs/portal-example-ae_ab12")
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO artifact_refs(asset_id,artifact_type,path)
                VALUES(?,'run_dir','/runs/portal-example-ae_ab12')""",
                (asset_id,),
            )
        self.db.sync_finding_catalog([
            {
                "record_id": "finding-run-1",
                "target": "portal-example-ae_ab12",
                "id": "VULN-RUN-1",
                "title": "Mapped issue",
                "severity": "CRITICAL",
                "source_file": "run",
            }
        ])

        vulnerable = self.db.list_assets(finding_min=1)

        self.assertEqual([item["target"] for item in vulnerable["items"]], ["portal.example.ae"])


if __name__ == "__main__":
    unittest.main()
