import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    async def test_summary_groups_achieved_findings_by_type(self):
        snapshot = await self.service.refresh()
        state = self.service.load_state()
        for record in snapshot.records:
            state["archived"][record["state_key"]] = True
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

        summary = await self.service.summary()
        self.assertEqual(summary["archived"], 2)
        self.assertEqual(summary["achieved_type_count"], 2)
        self.assertEqual(summary["achieved_by_type"]["SQL injection"], 1)
        self.assertEqual(summary["achieved_by_type"]["Exposed metadata"], 1)

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

    async def test_pwndoc_docx_export_generates_word_document(self):
        filename, media_type, content = await self.service.export("pwndoc-docx")
        self.assertEqual(filename, "nscan-pwndoc-report.docx")
        self.assertEqual(media_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.assertTrue(content.startswith(b"PK"))
        self.assertGreater(len(content), 1000)

    async def test_symlink_escape_is_not_indexed(self):
        outside = Path(self.temp.name) / "outside.md"
        outside.write_text("# Outside", encoding="utf-8")
        link = self.runs / "example-com_123" / "vulnerabilities" / "vuln-escape.md"
        link.symlink_to(outside)
        snapshot = await self.service.refresh()
        self.assertNotIn("vuln-escape", {record["id"] for record in snapshot.records})

    def test_report_generator_html_keeps_only_explicit_code_as_code(self):
        rendered = self.service._report_html(
            "## Impact\n\nA verified impact statement.\n\n- First action\n- Second action\n\n```http\nGET /health HTTP/1.1\n```"
        )
        self.assertIn("<h3>Impact</h3>", rendered)
        self.assertIn("<p>A verified impact statement.</p>", rendered)
        self.assertIn("<ul><li>First action</li><li>Second action</li></ul>", rendered)
        self.assertIn("<pre><code>GET /health HTTP/1.1</code></pre>", rendered)
        self.assertNotIn("<pre>A verified impact", rendered)

    async def test_report_generator_requires_verified_finding_and_is_idempotent(self):
        snapshot = await self.service.refresh()
        record = next(item for item in snapshot.records if item["id"] == "vuln-0001")
        with patch.dict("os.environ", {"VRG_API_TOKEN": "test-token", "VRG_BASE_URL": "https://vrg.test"}, clear=False):
            with self.assertRaises(PermissionError):
                await self.service.send_to_report_generator(record["record_id"])

            await self.service.update_state([record["record_id"]], {"star": True})
            calls = []

            def fake_request(method, path, payload=None):
                calls.append((method, path, payload))
                if path == "/api/audits" and method == "GET":
                    return {"value": []}
                if path == "/api/audits":
                    return {"audit": {"_id": "audit-123"}}
                if path == "/api/audits/audit-123/general":
                    return {"_id": "audit-123"}
                if path == "/api/audits/audit-123/findings":
                    return {"_id": "finding-456"}
                if path == "/api/audits/audit-123/findings/finding-456":
                    return {"_id": "finding-456"}
                if path == "/api/ai/complete-field":
                    return {"content": f"Generated {payload['fieldType']}"}
                raise AssertionError(path)

            self.service._report_generator_request = fake_request
            created = await self.service.send_to_report_generator(record["record_id"])
            self.assertEqual(created["status"], "exported")
            self.assertEqual(created["audit_id"], "audit-123")
            self.assertEqual(created["finding_id"], "finding-456")
            self.assertEqual([path for _method, path, _payload in calls], [
                "/api/audits", "/api/audits", "/api/audits/audit-123/general", "/api/audits/audit-123/findings",
            ])
            self.assertNotIn("template", calls[2][2])
            finding_payload = calls[-1][2]
            self.assertEqual(finding_payload["status"], 0)
            self.assertIn("<h2>SQL injection</h2>", finding_payload["poc"])
            self.assertNotIn("<pre>", finding_payload["poc"])

            repeated = await self.service.send_to_report_generator(record["record_id"])
            self.assertEqual(repeated["status"], "already_exported")
            self.assertEqual(len(calls), 4)

            synced = await self.service.sync_report_generator_draft(record["record_id"])
            self.assertEqual(synced["status"], "updated")
            self.assertEqual(calls[-1][1], "/api/audits/audit-123/findings/finding-456")
            self.assertIn("<h2>SQL injection</h2>", calls[-1][2]["poc"])

            generated = await self.service.generate_report_generator_fields(record["record_id"])
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(generated["fields"], ["description", "observation", "remediation", "impact_assessment"])
            ai_calls = [payload for method, path, payload in calls if method == "POST" and path == "/api/ai/complete-field"]
            self.assertEqual([payload["fieldType"] for payload in ai_calls], generated["fields"])
            self.assertEqual(calls[-1][2]["description"], "Generated description")


if __name__ == "__main__":
    unittest.main()
