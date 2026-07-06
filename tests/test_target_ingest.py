import tempfile
import unittest
from pathlib import Path

from asset_database import AssetDatabase
from smart_batch_jobs import SmartBatchJobManager, analyze_targets


class TargetIngestPolicyTests(unittest.TestCase):
    def test_zero_timeout_is_preserved_for_unlimited_scans(self):
        options = SmartBatchJobManager()._options({"timeout": 0})
        self.assertEqual(options["timeout"], 0)

    def test_unlimited_redteam_single_target_are_defaults(self):
        options = SmartBatchJobManager()._options({})
        self.assertEqual(options["mode"], "redteam")
        self.assertEqual(options["timeout"], 0)
        self.assertTrue(options["single_targets"])

    def test_auto_ingest_accepts_uae_and_generic_tlds(self):
        result = analyze_targets(
            ["example.ae", "portal.gov.ae", "brand.com"],
            source="target_ingest",
            allow_non_uae=False,
        )
        self.assertEqual(result["accepted_targets"], ["example.ae", "portal.gov.ae", "brand.com"])
        self.assertEqual(result["scope_rejected_count"], 0)

    def test_auto_ingest_blocks_non_uae_country_suffixes(self):
        result = analyze_targets(
            ["ministry.gov.sa", "agency.gov.ke", "allowed.com"],
            source="target_ingest",
            allow_non_uae=False,
        )
        self.assertEqual(result["accepted_targets"], ["allowed.com"])
        rejected = {item["target"]: item["reason"] for item in result["scope_rejected_targets"]}
        self.assertEqual(rejected["ministry.gov.sa"], "non_uae_country_suffix")
        self.assertEqual(rejected["agency.gov.ke"], "non_uae_country_suffix")

    def test_manual_override_accepts_non_uae_country_suffix(self):
        result = analyze_targets(
            ["ministry.gov.sa"],
            source="manual",
            allow_non_uae=True,
        )
        self.assertEqual(result["accepted_targets"], ["ministry.gov.sa"])
        self.assertEqual(result["scope_rejected_count"], 0)


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


if __name__ == "__main__":
    unittest.main()
