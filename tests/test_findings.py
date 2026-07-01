import json
import tempfile
import unittest
from pathlib import Path

import yaml

from findings import FindingsService


class FindingsServiceTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.catalog = root / "viewer"
        self.runs = root / "runs"
        self.catalog.mkdir()
        vuln_dir = self.runs / "example-com_123" / "vulnerabilities"
        vuln_dir.mkdir(parents=True)
        (vuln_dir / "vuln-0001.md").write_text(
            "# SQL injection\n**Severity:** CRITICAL\n**CVSS:** 9.8\n**Found:** 2026-06-19\n",
            encoding="utf-8",
        )
        (vuln_dir / "vuln-0002.md").write_text(
            "# Exposed metadata\n**Severity:** LOW\n", encoding="utf-8"
        )
        (self.catalog / "ALL_VULNERABILITIES_SUMMARY.csv").write_text(
            "target,id,title,severity,cvss,timestamp,file\n"
            "example-com_123,vuln-0001,SQL injection,CRITICAL,9.8,2026-06-19,vulnerabilities/vuln-0001.md\n",
            encoding="utf-8",
        )
        (self.catalog / "SUMMARY.md").write_text("# Summary\n", encoding="utf-8")
        self.state_file = self.catalog / ".vuln_viewer_tags.json"
        self.state_file.write_text(json.dumps({"tags": {}, "unread": {}, "marks": {}, "stars": {}, "archived": {}, "verified": {}}))
        config = {
            "catalog_dir": str(self.catalog),
            "state_file": str(self.state_file),
            "legacy_api_base": "http://127.0.0.1:1",
            "refresh_seconds": 60,
            "max_report_bytes": 1024 * 1024,
            "csv_files": ["ALL_VULNERABILITIES_SUMMARY.csv"],
            "report_files": ["SUMMARY.md"],
            "run_roots": [{"id": "test-runs", "path": str(self.runs)}],
        }
        self.config_path = root / "sources.yaml"
        self.config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        self.service = FindingsService(self.config_path)

    def tearDown(self):
        self.temp.cleanup()

    async def test_indexes_and_deduplicates_csv_and_run_records(self):
        snapshot = await self.service.refresh()
        self.assertEqual(len(snapshot.records), 2)
        self.assertEqual(len({record["record_id"] for record in snapshot.records}), 2)
        result = await self.service.list_records(1, 50, severity="CRITICAL")
        self.assertEqual(result["total"], 1)
        self.assertTrue(result["items"][0]["has_report"])

    async def test_state_filters_and_actions_use_legacy_keys(self):
        snapshot = await self.service.refresh()
        record = snapshot.records[0]
        state = self.service.load_state()
        self.service._apply(state, record["state_key"], {"verified": True, "star": True, "add_tag": "confirmed"})
        self.state_file.write_text(json.dumps(state), encoding="utf-8")
        verified = await self.service.list_records(1, 50, status="verified", tag="confirmed")
        self.assertEqual(verified["total"], 1)
        self.assertTrue(verified["items"][0]["state"]["starred"])

    async def test_report_and_summary_content_are_read_by_index_id(self):
        snapshot = await self.service.refresh()
        record = next(item for item in snapshot.records if item["id"] == "vuln-0001")
        filename, content = await self.service.record_content(record["record_id"])
        self.assertEqual(filename, "vuln-0001.md")
        self.assertIn("SQL injection", content)
        reports = await self.service.reports()
        report_name, report_content = await self.service.report_content(reports[0]["report_id"])
        self.assertEqual(report_name, "SUMMARY.md")
        self.assertIn("Summary", report_content)

    async def test_symlink_escape_is_not_indexed(self):
        outside = Path(self.temp.name) / "outside.md"
        outside.write_text("# Outside", encoding="utf-8")
        link = self.runs / "example-com_123" / "vulnerabilities" / "vuln-escape.md"
        link.symlink_to(outside)
        snapshot = await self.service.refresh()
        self.assertNotIn("vuln-escape", {record["id"] for record in snapshot.records})


if __name__ == "__main__":
    unittest.main()
