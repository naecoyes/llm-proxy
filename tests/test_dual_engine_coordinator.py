import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanScript.dual_engine_scan import (
    _pipeline_live_targets,
    child_completed_successfully,
    inherit_parent_preflight,
    prepare_child_resume,
    report_summary,
    retest_classification,
)
from scanScript.probe_live_targets import ProbeResult


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scanScript" / "dual_engine_scan.py"


class DualEngineCoordinatorTests(unittest.TestCase):
    def test_completed_preflight_is_reused_without_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            state_dir.mkdir()
            filtered = state_dir / "_preflight" / "dual.live.txt"
            filtered.parent.mkdir()
            filtered.write_text("example.ae\n", encoding="utf-8")
            targets = root / "targets.txt"
            targets.write_text("example.ae\n", encoding="utf-8")
            job_path = root / "job.json"
            job = {
                "pipeline": {
                    "preflight": {
                        "status": "completed",
                        "filtered_targets_file": str(filtered),
                    },
                    "preflight_progress": {"checked_targets": 1, "total_targets": 1},
                },
            }

            with patch("scanScript.probe_live_targets.execute_probe") as execute:
                selected = _pipeline_live_targets(job_path, job, targets, state_dir)

            self.assertEqual(filtered, selected)
            execute.assert_not_called()
            self.assertIn("reused_at", job["pipeline"]["preflight"])

    def test_preflight_progress_and_stable_artifact_paths_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            state_dir.mkdir()
            targets = root / "targets.txt"
            targets.write_text("example.ae\n", encoding="utf-8")
            job_path = root / "job.json"
            job = {
                "job_id": "dual-test",
                "label": "dual-test",
                "options": {"probe_live_before_queue": True, "use_socks5": False},
            }

            def fake_execute(*_args, **kwargs):
                kwargs["progress_callback"]({
                    "total_targets": 1,
                    "checked_targets": 1,
                    "alive_targets": 1,
                    "dead_targets": 0,
                    "inconclusive_targets": 0,
                    "blocked_targets": 0,
                    "progress_percent": 100.0,
                })
                output = Path(kwargs["output_dir"]) / "source.json"
                output.write_text("{}", encoding="utf-8")
                return {
                    "results": [ProbeResult(host="example.ae", sources=["input"], alive=True, classification="alive")],
                    "summary": {"alive": 1, "dead": 0, "inconclusive": 0, "blocked": 0},
                    "paths": {"json": output},
                }

            with patch("scanScript.probe_live_targets.execute_probe", side_effect=fake_execute):
                selected = _pipeline_live_targets(job_path, job, targets, state_dir)

            self.assertEqual("example.ae\n", selected.read_text(encoding="utf-8"))
            self.assertEqual(100.0, job["preflight_progress"]["progress_percent"])
            self.assertEqual("completed", job["pipeline"]["preflight"]["status"])
            self.assertTrue(job["preflight_resume_path"].endswith("preflight_results.jsonl"))
            self.assertTrue(job["preflight_manifest_path"].endswith("preflight_manifest.json"))
    def test_second_stage_reuses_primary_filtered_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            state_dir.mkdir()
            filtered = root / "targets.live.txt"
            filtered.write_text("example.ae\n", encoding="utf-8")
            (state_dir / "primary-batch.json").write_text(json.dumps({
                "batch_id": "primary-batch",
                "input_source": {"effective_targets_file": str(filtered)},
            }), encoding="utf-8")
            job_path = root / "job.json"
            job = {"project_root": str(root), "job_id": "dual-test"}
            primary = {"engine": "strix", "batch_id": "primary-batch", "env": {"STRIX_BATCH_STATE_DIR": str(state_dir)}}
            secondary = {
                "engine": "chelmon-claude",
                "command": [sys.executable, "-c", "pass", "original-targets.txt"],
                "target_file_index": 3,
                "preflight": {"mode": "inherit_parent", "status": "pending"},
            }

            self.assertTrue(inherit_parent_preflight(job_path, job, primary, secondary))
            self.assertEqual(secondary["command"][3], str(filtered.resolve()))
            self.assertEqual(secondary["preflight"]["status"], "reused")
            self.assertEqual(job["preflight"]["source_batch_id"], "primary-batch")

    def test_runs_children_in_order_and_keeps_second_result_after_first_error(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            trace = temp / "trace.txt"
            parent_report = temp / "parent-report.json"

            def child(engine: str, return_code: int) -> dict:
                output = temp / f"{engine}.json"
                llm_summary = (
                    "'llm_model_usage_by_model': {'model': {'requests': 1}}"
                    if engine == "chelmon-claude" else "'llm_model_usage_by_model': {}"
                )
                script = (
                    "import json, pathlib, sys; "
                    f"pathlib.Path({str(trace)!r}).open('a').write({engine!r} + '\\n'); "
                    f"pathlib.Path({str(output)!r}).write_text(json.dumps({{'summary': {{'total_vulnerabilities': 1, 'total_tasks': 1, 'completed_tasks': 1, 'successful': 1, {llm_summary}}}, 'final_results': [{{'status': 'success'}}]}})); "
                    f"sys.exit({return_code})"
                )
                return {
                    "engine": engine,
                    "mode": "redteam" if engine == "strix" else "default",
                    "status": "pending",
                    "paths": {
                        "output_file": str(output),
                        "stdout_file": str(temp / f"{engine}.stdout.log"),
                        "stderr_file": str(temp / f"{engine}.stderr.log"),
                    },
                    "command": [sys.executable, "-c", script],
                    "env": {},
                }

            job_path = temp / "dual.json"
            job_path.write_text(json.dumps({
                "job_id": "dual-test",
                "engine": "dual",
                "project_root": str(ROOT),
                "target_count": 1,
                "status": "started",
                "phase": "strix",
                "completed_passes": 0,
                "total_passes": 2,
                "paths": {"output_file": str(parent_report)},
                "children": [child("strix", 1), child("chelmon-claude", 2)],
            }), encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(RUNNER), "--job-file", str(job_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            job = json.loads(job_path.read_text(encoding="utf-8"))
            self.assertEqual(trace.read_text(encoding="utf-8").splitlines(), ["strix", "chelmon-claude"])
            self.assertEqual(job["status"], "completed_with_errors")
            self.assertEqual(job["completed_passes"], 2)
            self.assertEqual([item["status"] for item in job["children"]], ["completed_with_errors", "completed"])
            self.assertEqual(json.loads(parent_report.read_text(encoding="utf-8"))["findings_count"], 2)

    def test_zero_exit_with_incomplete_report_is_not_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "incomplete.json"
            report_path.write_text(json.dumps({
                "summary": {"total_tasks": 1, "completed_tasks": 0, "successful": 0},
                "final_results": [{"status": "failed"}],
            }), encoding="utf-8")

            child = {"engine": "chelmon-claude", "report": report_summary(str(report_path))}
            completed, error = child_completed_successfully(child, 0)

            self.assertFalse(completed)
            self.assertIn("0/1", error)

    def test_chelmon_requires_effective_llm_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "no-llm.json"
            report_path.write_text(json.dumps({
                "summary": {"total_tasks": 1, "completed_tasks": 1, "successful": 1},
                "final_results": [{"status": "success"}],
            }), encoding="utf-8")

            child = {"engine": "chelmon-claude", "report": report_summary(str(report_path))}
            completed, error = child_completed_successfully(child, 0)

            self.assertFalse(completed)
            self.assertEqual(error, "no effective LLM run was recorded")

    def test_resume_rewrites_only_unfinished_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            state_dir.mkdir()
            state_file = state_dir / "batch-a.json"
            state_file.write_text(json.dumps({
                "input_source": {"effective_targets_file": str(root / "all.txt")},
                "tasks": [
                    {"target": "done.example", "status": "success"},
                    {"target": "retry.example", "status": "pending"},
                ],
            }), encoding="utf-8")
            (root / "all.txt").write_text("done.example\nretry.example\n", encoding="utf-8")
            job_path = root / "job.json"
            job = {"project_root": str(root)}
            child = {
                "batch_id": "batch-a",
                "status": "interrupted",
                "target_file_index": 2,
                "command": [sys.executable, "-c", "original.txt"],
                "env": {"STRIX_BATCH_STATE_DIR": str(state_dir)},
                "paths": {"output_file": str(root / "report.json")},
            }

            self.assertTrue(prepare_child_resume(job_path, job, child))
            self.assertEqual(child["preserved_success_targets"], ["done.example"])
            self.assertEqual(Path(child["resume_targets_file"]).read_text(encoding="utf-8"), "retry.example\n")
            self.assertEqual(child["command"][2], child["resume_targets_file"])

    def test_retest_classifies_only_exact_baseline_fingerprints_as_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            vuln_dir = run_dir / "vulnerabilities"
            vuln_dir.mkdir(parents=True)
            (vuln_dir / "known.md").write_text(
                "# Known issue\n**CWE:** CWE-79\n**Endpoint:** /old\n**Method:** GET\n",
                encoding="utf-8",
            )
            (vuln_dir / "new.md").write_text(
                "# New issue\n**CWE:** CWE-89\n**Endpoint:** /new\n**Method:** POST\n",
                encoding="utf-8",
            )
            child_report = root / "child.json"
            child_report.write_text(json.dumps({"final_results": [{"output_path": str(run_dir)}]}), encoding="utf-8")
            job = {
                "baseline_snapshot": {
                    "example.ae": {"records": [
                        {"title": "Known issue", "cwe": "CWE-79", "endpoint": "/old", "method": "GET", "classification": "verified_active"},
                        {"title": "Ignore", "classification": "excluded_false_positive"},
                    ]},
                },
                "children": [{"paths": {"output_file": str(child_report)}}],
            }
            self.assertEqual(retest_classification(job), {
                "revalidated_count": 1,
                "new_candidate_count": 1,
                "historical_not_observed_count": 0,
                "excluded_false_positive_count": 1,
            })


if __name__ == "__main__":
    unittest.main()
