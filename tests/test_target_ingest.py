import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asset_database import AssetDatabase
from smart_batch_jobs import SmartBatchJobManager, SmartBatchPaths, analyze_targets


class TargetIngestPolicyTests(unittest.TestCase):
    def test_zero_timeout_is_preserved_for_unlimited_scans(self):
        options = SmartBatchJobManager()._options({"timeout": 0})
        self.assertEqual(options["timeout"], 0)

    def test_unlimited_dual_engine_single_target_are_defaults(self):
        with patch("smart_batch_jobs.get_chelmon_runtime_status", return_value={"ready": True, "checks": {}}):
            options = SmartBatchJobManager()._options({})
        self.assertEqual(options["engine"], "dual")
        self.assertEqual(options["mode"], "dual")
        self.assertEqual(
            [(item["engine"], item["mode"]) for item in options["engine_plan"]],
            [("strix", "redteam"), ("chelmon-claude", "default")],
        )
        self.assertEqual(options["timeout"], 0)
        self.assertTrue(options["single_targets"])

    def test_default_engine_falls_back_to_strix_when_chelmon_is_unhealthy(self):
        with patch("smart_batch_jobs.get_chelmon_runtime_status", return_value={"ready": False, "checks": {"image": {"ok": False}}}):
            options = SmartBatchJobManager()._options({})
        self.assertEqual(options["engine"], "strix")
        self.assertEqual(options["mode"], "redteam")

    def test_chelmon_claude_engine_is_accepted(self):
        options = SmartBatchJobManager()._options({"engine": "chelmon-claude"})
        self.assertEqual(options["engine"], "chelmon-claude")
        self.assertEqual(options["mode"], "default")

    def test_ansecai_engine_alias_is_accepted(self):
        options = SmartBatchJobManager()._options({"engine": "ansecai"})
        self.assertEqual(options["engine"], "chelmon-claude")
        self.assertEqual(options["mode"], "default")

    def test_chelmon_claude_can_use_explicit_nscan_mode(self):
        options = SmartBatchJobManager()._options({"engine": "chelmon-claude", "mode": "redteam"})
        self.assertEqual(options["mode"], "redteam")

    def test_dual_engine_uses_fixed_serial_plan(self):
        options = SmartBatchJobManager()._options({"engine": "dual", "mode": "deep", "skip_scanned": True})
        self.assertEqual(options["engine"], "dual")
        self.assertEqual(options["mode"], "dual")
        self.assertFalse(options["skip_scanned"])
        self.assertEqual(
            [(item["engine"], item["mode"]) for item in options["engine_plan"]],
            [("strix", "redteam"), ("chelmon-claude", "default")],
        )

    def test_retest_requires_and_normalizes_to_dual_engine(self):
        options = SmartBatchJobManager()._options({"mode": "retest"})
        self.assertEqual(options["engine"], "dual")
        self.assertEqual(options["mode"], "retest")
        self.assertEqual(options["workflow_mode"], "retest")
        with self.assertRaises(ValueError):
            SmartBatchJobManager()._options({"engine": "strix", "mode": "retest"})

    def test_retest_dry_run_writes_immutable_context_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = SmartBatchPaths(root, root / "state", root / "targets", root / "reports", root / "jobs")
            manager = SmartBatchJobManager(paths)
            baseline = {"targets": {"portal.gov.ae": {
                "asset_id": 4, "finding_count": 1, "aliases": ["portal.gov.ae"],
                "records": [{"record_id": "old-1", "title": "Prior issue", "classification": "verified_active"}],
                "instruction": "RETEST BASELINE\n",
            }}}
            with patch("smart_batch_jobs.get_chelmon_runtime_status", return_value={"ready": True, "checks": {}}):
                job = manager.submit({"targets": "portal.gov.ae", "engine": "dual", "mode": "retest", "dry_run": True, "_retest_baseline": baseline})
            self.assertEqual(job["workflow_mode"], "retest")
            self.assertEqual(job["baseline_snapshot"]["portal.gov.ae"]["finding_count"], 1)
            self.assertIn("--retest-context-dir", job["children"][0]["command"])

    def test_dual_engine_dry_run_creates_one_parent_and_two_planned_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = SmartBatchPaths(
                project_root=Path(__file__).resolve().parents[2],
                state_dir=root / "state",
                target_dir=root / "targets",
                report_dir=root / "reports",
                job_dir=root / "jobs",
            )
            manager = SmartBatchJobManager(paths)
            with patch("smart_batch_jobs.get_chelmon_runtime_status", return_value={"ready": True, "checks": {}}):
                job = manager.submit({"targets": "portal.gov.ae", "engine": "dual", "dry_run": True})

            self.assertEqual(job["status"], "dry_run_completed")
            self.assertEqual(job["phase"], "planned")
            self.assertEqual(job["total_passes"], 2)
            self.assertEqual([child["status"] for child in job["children"]], ["planned", "planned"])
            self.assertEqual(
                [(child["engine"], child["mode"]) for child in job["children"]],
                [("strix", "redteam"), ("chelmon-claude", "default")],
            )
            target_file = job["paths"]["target_file"]
            self.assertEqual(Path(target_file).read_text(encoding="utf-8"), "portal.gov.ae\n")
            for child in job["children"]:
                self.assertIn(target_file, child["command"])
                self.assertEqual(child["env"]["NSCAN_PARENT_JOB_ID"], job["job_id"])
            self.assertIn("--probe-live-before-queue", job["children"][0]["command"])
            self.assertNotIn("--probe-live-before-queue", job["children"][1]["command"])
            self.assertEqual(job["children"][1]["preflight"]["mode"], "inherit_parent")

    def test_unknown_engine_is_rejected(self):
        with self.assertRaises(ValueError):
            SmartBatchJobManager()._options({"engine": "unknown"})

    def test_resume_restarts_only_an_interrupted_dual_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = SmartBatchPaths(
                project_root=Path(__file__).resolve().parents[2],
                state_dir=root / "state",
                target_dir=root / "targets",
                report_dir=root / "reports",
                job_dir=root / "jobs",
            )
            paths.job_dir.mkdir(parents=True)
            job_id = "dashboard-resume-test"
            (paths.job_dir / f"{job_id}.json").write_text(__import__("json").dumps({
                "job_id": job_id,
                "engine": "dual",
                "status": "interrupted",
                "options": {"use_socks5": True},
                "paths": {"stdout_file": str(root / "out.log"), "stderr_file": str(root / "err.log")},
                "children": [{"engine": "strix", "status": "completed"}, {"engine": "chelmon-claude", "status": "interrupted"}],
            }), encoding="utf-8")
            manager = SmartBatchJobManager(paths)
            with patch.object(manager, "_start_worker", return_value={
                "worker_mode": "systemd-user", "worker_unit": "nscan-scan-dashboard-resume-test",
                "worker_status": "active/running", "pid": 42, "worker_warning": "",
            }):
                resumed = manager.resume_job(job_id)

            self.assertEqual(resumed["status"], "started")
            self.assertEqual(resumed["phase"], "recovering")
            self.assertEqual(resumed["worker_unit"], "nscan-scan-dashboard-resume-test")
            self.assertEqual(resumed["recovery_state"], "resume_requested")

    def test_scope_gate_only_accepts_high_confidence_official_suffixes(self):
        result = analyze_targets(
            ["example.ae", "portal.gov.ae", "brand.com"],
            source="target_ingest",
            allow_non_uae=False,
        )
        self.assertEqual(result["accepted_targets"], ["portal.gov.ae"])
        rejected = {item["target"]: item["scope_status"] for item in result["scope_rejected_targets"]}
        self.assertEqual(rejected["example.ae"], "scope_review_required")
        self.assertEqual(rejected["brand.com"], "out_of_scope")

    def test_auto_ingest_blocks_non_uae_country_suffixes(self):
        result = analyze_targets(
            ["ministry.gov.sa", "agency.gov.ke", "portal.gov.ae"],
            source="target_ingest",
            allow_non_uae=False,
        )
        self.assertEqual(result["accepted_targets"], ["portal.gov.ae"])
        rejected = {item["target"]: item["reason"] for item in result["scope_rejected_targets"]}
        self.assertEqual(rejected["ministry.gov.sa"], "non_uae_country_suffix")
        self.assertEqual(rejected["agency.gov.ke"], "non_uae_country_suffix")

    def test_manual_submission_cannot_bypass_scope(self):
        result = analyze_targets(
            ["ministry.gov.sa"],
            source="manual",
            allow_non_uae=True,
        )
        self.assertEqual(result["accepted_targets"], [])
        self.assertEqual(result["scope_rejected_count"], 1)

    def test_dashboard_submission_cannot_bypass_scope_without_flag(self):
        result = analyze_targets(
            ["ministry.gov.sa"],
            source="dashboard",
            allow_non_uae=False,
        )
        self.assertEqual(result["accepted_targets"], [])
        self.assertEqual(result["scope_rejected_count"], 1)


class TargetIngestDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = AssetDatabase(Path(self.temp_dir.name) / "nscan.sqlite3")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_target_ingest_creates_group_assets_and_quarantine(self):
        record = self.db.record_target_ingest(
            platform="Partner Platform",
            source_ref="push-1",
            accepted_targets=["example.ae", "brand.com"],
            rejected_targets=[
                {"target": "ministry.gov.sa", "host": "ministry.gov.sa", "reason": "non_uae_country_suffix"}
            ],
            job_id="ingest-1",
            metadata={"source_type": "target_ingest"},
        )
        self.assertEqual(record["platform"], "partner-platform")
        self.assertEqual(record["accepted_count"], 2)
        self.assertEqual(record["rejected_count"], 1)

        groups = self.db.asset_groups()["items"]
        self.assertEqual(groups[0]["group_key"], "platform:partner-platform")
        self.assertEqual(groups[0]["asset_count"], 2)

        assets = self.db.list_assets(platform="partner-platform")
        self.assertEqual(assets["total"], 2)

        quarantine = self.db.target_quarantine_page(platform="partner-platform")
        self.assertEqual(quarantine["total"], 1)
        self.assertEqual(quarantine["items"][0]["raw_target"], "ministry.gov.sa")

    def test_asset_import_replays_cursor_without_duplicate_progress(self):
        first = self.db.record_asset_import(
            source_type="pii_alive_assets",
            source_ref="pii-sync-20260714",
            sync_cursor="10000",
            accepted_targets=["example.ae", "public.example.com"],
            input_count=2,
        )
        replay = self.db.record_asset_import(
            source_type="pii_alive_assets",
            source_ref="pii-sync-20260714",
            sync_cursor="10000",
            accepted_targets=["example.ae", "public.example.com"],
            input_count=2,
        )
        self.assertFalse(first["replayed_cursor"])
        self.assertTrue(replay["replayed_cursor"])
        self.assertEqual(first["import_id"], replay["import_id"])

        progress = self.db.asset_import_progress(
            source_type="pii_alive_assets", source_ref="pii-sync-20260714"
        )["items"][0]
        self.assertEqual(progress["sync_cursor"], "10000")
        self.assertEqual(progress["batches_completed"], 1)
        self.assertEqual(progress["accepted_total"], 2)

        assets = self.db.list_assets(platform="pii_alive_assets")
        self.assertEqual(assets["total"], 2)


if __name__ == "__main__":
    unittest.main()
