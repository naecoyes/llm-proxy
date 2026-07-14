import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asset_database import AssetDatabase
from smart_batch_jobs import analyze_targets
from target_policy import classify_target_scope, save_scope_catalog


class TargetScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.catalog_path = Path(self.temp_dir.name) / "scope_catalog.json"
        self.previous_catalog = os.environ.get("NSCAN_SCOPE_CATALOG_PATH")
        os.environ["NSCAN_SCOPE_CATALOG_PATH"] = str(self.catalog_path)
        save_scope_catalog({
            "version": "test-catalog-v1",
            "source": "scopesentry",
            "items": [
                {"host": "entity.ae", "category": "government_entity", "confidence": "high"},
                {"host": "utility.example", "category": "public_utility_infrastructure", "confidence": "high"},
            ],
        })

    def tearDown(self):
        if self.previous_catalog is None:
            os.environ.pop("NSCAN_SCOPE_CATALOG_PATH", None)
        else:
            os.environ["NSCAN_SCOPE_CATALOG_PATH"] = self.previous_catalog
        self.temp_dir.cleanup()

    def test_inherited_catalog_domain_is_admitted(self):
        decision = classify_target_scope("api.entity.ae", certificate_lookup=False)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["category"], "government_entity")
        self.assertEqual(decision["reason"], "curated_high_confidence")

    def test_official_suffix_is_admitted(self):
        decision = classify_target_scope("portal.gov.ae", certificate_lookup=False)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["category"], "government_entity")

    def test_candidate_uae_suffix_requires_review(self):
        decision = classify_target_scope("commercial.co.ae", certificate_lookup=False)
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["scope_status"], "scope_review_required")

    def test_manual_source_cannot_override_scope(self):
        decision = classify_target_scope("commercial.co.ae", source="manual", allow_non_uae=True, certificate_lookup=False)
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["scope_status"], "scope_review_required")

    def test_weak_geography_only_certificate_requires_review(self):
        decision = classify_target_scope(
            "brand.example",
            certificate_lookup=False,
            certificate_subject="CN=Brand, O=Brand LLC, C=AE",
        )
        self.assertEqual(decision["scope_status"], "scope_review_required")

    def test_strong_certificate_entity_is_admitted(self):
        decision = classify_target_scope(
            "entity.example",
            certificate_lookup=False,
            certificate_subject="CN=Example Authority, O=Example Authority, C=AE",
        )
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["category"], "government_entity")

    def test_network_guard_still_precedes_scope(self):
        result = analyze_targets(["127.0.0.1", "portal.gov.ae"], check_dns=False)
        self.assertEqual(result["accepted_targets"], ["portal.gov.ae"])
        self.assertEqual(result["restricted_target_count"], 1)

    def test_inventory_mode_retains_out_of_scope_assets(self):
        result = analyze_targets(["commercial.co.ae", "foreign.example"], check_dns=False, enforce_scope=False)
        self.assertEqual(result["accepted_targets"], ["commercial.co.ae", "foreign.example"])
        self.assertEqual(result["scope_rejected_count"], 2)

    def test_scope_decision_persists_and_filters_assets(self):
        db = AssetDatabase(Path(self.temp_dir.name) / "assets.sqlite3")
        decision = classify_target_scope("portal.gov.ae", certificate_lookup=False)
        db.record_scope_decisions([decision], source_ref="test")
        result = db.list_assets(scope_status="in_scope")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["scope_category"], "government_entity")
        self.assertEqual(db.summary()["scope"]["in_scope"], 1)


if __name__ == "__main__":
    unittest.main()
