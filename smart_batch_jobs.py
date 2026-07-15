"""Submit Smart Batch scan jobs from the Nscan dashboard.

This module is deliberately thin: it validates dashboard input, writes a
timestamped target file, and launches the existing Smart Batch CLI with an
argument list. The scanner remains the source of truth for execution and state.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from strix.target_guard import check_network_target, env_dns_guard_enabled
try:
    from target_policy import classify_target_scope, normalize_platform
    from asset_database import normalize_target
except ModuleNotFoundError:  # package import from the project root
    from .target_policy import classify_target_scope, normalize_platform
    from .asset_database import normalize_target
try:
    from chelmon_runtime import get_chelmon_runtime_status
except ModuleNotFoundError:  # package import from the project root
    from .chelmon_runtime import get_chelmon_runtime_status


TARGET_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,252}$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
ALLOWED_MODES = {"default", "quick", "standard", "deep", "redteam", "getshell", "retest"}
ALLOWED_ENGINES = {"strix", "chelmon-claude", "ansecai", "dual"}
# A single durable Smart Batch owns the scanner-level bounded queue.  Keeping
# a catalog import below an arbitrary API limit would force callers to start
# many independent coordinators and multiply effective concurrency.  This cap
# still bounds request size while allowing a curated ScopeSentry catalog to run
# as one resumable, globally controlled job.
DEFAULT_MAX_TARGETS = 20_000
DEFAULT_MAX_PARALLEL = 4
DEFAULT_ENGINE = "dual"
DEFAULT_WORKER_MODE = os.environ.get("NSCAN_WORKER_MODE", "systemd-user").strip().lower()
DUAL_ENGINE_PLAN = (
    {"engine": "strix", "mode": "redteam", "engine_role": "primary", "engine_sequence": 1},
    {"engine": "chelmon-claude", "mode": "default", "engine_role": "secondary", "engine_sequence": 2},
)


@dataclass(frozen=True)
class SmartBatchPaths:
    project_root: Path
    state_dir: Path
    target_dir: Path
    report_dir: Path
    job_dir: Path


def default_paths() -> SmartBatchPaths:
    project_root = Path(__file__).resolve().parents[1]
    return SmartBatchPaths(
        project_root=project_root,
        state_dir=project_root / "llm_proxy" / "runtime" / "smart_batch",
        target_dir=project_root / "targets" / "dashboard",
        report_dir=project_root / "reports" / "dashboard",
        job_dir=project_root / "llm_proxy" / "runtime" / "smart_batch_jobs",
    )


class SmartBatchJobManager:
    def __init__(self, paths: SmartBatchPaths | None = None) -> None:
        self.paths = paths or default_paths()

    @staticmethod
    def _persist_job(job_file: Path, job: dict[str, Any]) -> None:
        """Persist the job atomically to SQLite and keep a JSON checkpoint."""
        atomic_write_json(job_file, job)
        try:
            from asset_database import get_asset_database

            get_asset_database().sync_smart_batch_job(job, str(job_file))
        except Exception as exc:  # noqa: BLE001
            # A coordinator must remain recoverable from its file checkpoint
            # even if the dashboard database is temporarily unavailable.
            logger.warning("Smart Batch job SQLite sync failed for %s: %s", job.get("job_id"), exc)

    def preview(self, payload: dict[str, Any]) -> dict[str, Any]:
        options = self._options(payload)
        engine_health = get_chelmon_runtime_status() if options["engine"] == "dual" else None
        analysis = analyze_targets(
            payload.get("targets", ""),
            max_targets=self._max_targets(payload),
            allow_private=options["allow_private_targets"],
            check_dns=not options["skip_dns_guard"],
            source=options["source"],
            allow_non_uae=options["allow_non_uae"],
            country=str(payload.get("country") or ""),
            region=str(payload.get("region") or ""),
            certificate_lookup=bool(payload.get("scope_certificate_lookup", True)),
        )
        result = {
            "valid": analysis["restricted_target_count"] == 0 and analysis["scope_rejected_count"] == 0,
            "target_count": len(analysis["accepted_targets"]),
            "targets": analysis["accepted_targets"][:50],
            "accepted_targets": analysis["accepted_targets"],
            "rejected_targets": analysis["rejected_targets"],
            "restricted_targets": analysis["restricted_targets"],
            "scope_rejected_targets": analysis["scope_rejected_targets"],
            "scope_blocked_targets": analysis["scope_blocked_targets"],
            "scope_review_targets": analysis["scope_review_targets"],
            "restricted_target_count": analysis["restricted_target_count"],
            "scope_rejected_count": analysis["scope_rejected_count"],
            "scope_category_counts": analysis["scope_category_counts"],
            "scope_catalog_version": analysis["scope_catalog_version"],
            "scope_decisions": analysis["scope_decisions"],
            "truncated_preview": len(analysis["accepted_targets"]) > 50,
            "options": options,
            "engine_health": engine_health,
        }
        if options["engine"] == "dual":
            result.update({
                "engine_plan": [dict(item) for item in DUAL_ENGINE_PLAN],
                "total_passes": len(DUAL_ENGINE_PLAN),
            })
        return result

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        options = self._options(payload)
        if options["engine"] == "dual":
            runtime = get_chelmon_runtime_status(force=True)
            if not runtime.get("ready"):
                failed = [name for name, check in (runtime.get("checks") or {}).items() if not check.get("ok")]
                raise ValueError(f"Dual engine is unavailable: Chelmon runtime preflight failed ({', '.join(failed) or 'unknown'})")
        analysis = analyze_targets(
            payload.get("targets", ""),
            max_targets=self._max_targets(payload),
            allow_private=options["allow_private_targets"],
            check_dns=not options["skip_dns_guard"],
            source=options["source"],
            allow_non_uae=options["allow_non_uae"],
            country=str(payload.get("country") or ""),
            region=str(payload.get("region") or ""),
            certificate_lookup=bool(payload.get("scope_certificate_lookup", True)),
        )
        dry_run = bool(payload.get("dry_run", False))
        if not dry_run:
            try:
                from asset_database import get_asset_database

                get_asset_database().record_scope_decisions(
                    analysis["scope_decisions"],
                    source_type=options["source"],
                    source_ref=options["source_ref"],
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Scope decision persistence failed: %s", exc)
        if analysis["restricted_targets"] and not options["allow_private_targets"]:
            sample = ", ".join(item["target"] for item in analysis["restricted_targets"][:5])
            raise ValueError(f"Restricted local/private targets blocked: {sample}")
        if analysis["scope_rejected_targets"]:
            sample = ", ".join(item["target"] for item in analysis["scope_rejected_targets"][:5])
            raise ValueError(f"Targets blocked by the high-confidence UAE scope gate: {sample}")
        targets = analysis["accepted_targets"]
        if not targets:
            raise ValueError("No accepted targets supplied")
        source_prefix = "ingest" if options["source"] == "target_ingest" else "dashboard"
        job_id = f"{source_prefix}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        label = clean_label(str(payload.get("label") or targets[0] or "batch"))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        for directory in (self.paths.target_dir, self.paths.report_dir, self.paths.job_dir, self.paths.state_dir):
            directory.mkdir(parents=True, exist_ok=True)

        target_file = self.paths.target_dir / f"{timestamp}_{label}_{job_id}.txt"
        history_file = self.paths.report_dir / f"{timestamp}_{label}_{job_id}_history.txt"
        output_file = self.paths.report_dir / f"{timestamp}_{label}_{job_id}_report.json"
        stdout_file = self.paths.report_dir / f"{timestamp}_{label}_{job_id}.stdout.log"
        stderr_file = self.paths.report_dir / f"{timestamp}_{label}_{job_id}.stderr.log"
        job_file = self.paths.job_dir / f"{job_id}.json"

        target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        baseline_snapshot: dict[str, Any] = {}
        if options["workflow_mode"] == "retest":
            baseline = payload.get("_retest_baseline")
            if not isinstance(baseline, dict):
                raise ValueError("Retest baseline is unavailable; refresh Findings and retry")
            context_dir = self.paths.report_dir / f"{timestamp}_{label}_{job_id}_retest_context"
            context_dir.mkdir(parents=True, exist_ok=True)
            context_files: dict[str, str] = {}
            for target in targets:
                key = normalize_target(target)["canonical_key"]
                item = (baseline.get("targets") or {}).get(key) or {"target": key, "instruction": ""}
                instruction = str(item.get("instruction") or "")
                path = context_dir / f"{safe_job_id(key) or 'target'}.md"
                path.write_text(instruction, encoding="utf-8")
                context_files[key] = str(path)
                baseline_snapshot[key] = {
                    "asset_id": item.get("asset_id"),
                    "finding_count": int(item.get("finding_count") or 0),
                    "omitted_count": int(item.get("omitted_count") or 0),
                    "context_bytes": int(item.get("context_bytes") or 0),
                    "aliases": list(item.get("aliases") or []),
                    "records": [
                        {field: record.get(field) for field in ("record_id", "finding_id", "title", "severity", "cvss", "source", "found_at", "classification", "endpoint", "method", "cwe")}
                        for record in (item.get("records") or [])
                    ],
                }
            options = {**options, "retest_context_dir": str(context_dir), "retest_context_files": context_files}

        job = {
            "job_id": job_id,
            "label": label,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "status": "dry_run_completed" if dry_run else "started",
            "pid": None,
            "target_count": len(targets),
            "engine": options["engine"],
            "scan_mode": options["mode"],
            "workflow_mode": options["workflow_mode"],
            "targets_preview": targets[:20],
            "rejected_targets": analysis["rejected_targets"],
            "restricted_targets": analysis["restricted_targets"],
            "scope_rejected_targets": analysis["scope_rejected_targets"],
            "scope_blocked_targets": analysis["scope_blocked_targets"],
            "scope_review_targets": analysis["scope_review_targets"],
            "scope_category_counts": analysis["scope_category_counts"],
            "scope_catalog_version": analysis["scope_catalog_version"],
            "blocked_count": analysis["restricted_target_count"] + analysis["scope_rejected_count"],
            "source_type": options["source"],
            "platform": options["platform"],
            "source_ref": options["source_ref"],
            "options": options,
            "baseline_snapshot": baseline_snapshot,
            "paths": {
                "target_file": str(target_file),
                "history_file": str(history_file),
                "output_file": str(output_file),
                "stdout_file": str(stdout_file),
                "stderr_file": str(stderr_file),
                "state_dir": str(self.paths.state_dir),
            },
            "project_root": str(self.paths.project_root),
        }
        if options["engine"] == "dual":
            return self._submit_dual_job(
                job=job,
                job_file=job_file,
                options=options,
                dry_run=dry_run,
                timestamp=timestamp,
            )

        args = self._build_scan_args(
            target_file=target_file,
            label=label,
            history_file=history_file,
            output_file=output_file,
            options=options,
            engine=options["engine"],
            mode=options["mode"],
            dry_run=dry_run,
        )
        env, _ = self._scan_environment(job_id, options)
        process = self._start_process(args, stdout_file, stderr_file, env)
        job["pid"] = process.pid
        job["command"] = redact_command(args)
        self._persist_job(job_file, job)
        return job

    def _build_scan_args(
        self,
        *,
        target_file: Path,
        label: str,
        history_file: Path,
        output_file: Path,
        options: dict[str, Any],
        engine: str,
        mode: str,
        dry_run: bool,
        reuse_parent_preflight: bool = False,
    ) -> list[str]:
        args = [
            str(self._python_bin()), "scanScript/smart_batch_scan.py", str(target_file),
            "--engine", engine, "--label", label, "--parallel", str(options["parallel"]),
            "--timeout", str(options["timeout"]), "--history-file", str(history_file),
            "--output", str(output_file),
        ]
        if mode != "default":
            args.extend(["--mode", mode])
        if options["single_targets"]:
            args.append("--single-targets")
        args.append("--use-socks5" if options["use_socks5"] else "--no-socks5")
        if options["monitor"]:
            args.append("--monitor")
        if options["skip_scanned"]:
            args.append("--skip-scanned")
        if options["model"]:
            args.extend(["--model", options["model"]])
        if options.get("retest_context_dir"):
            args.extend(["--retest-context-dir", str(options["retest_context_dir"])])
        if options["allow_private_targets"]:
            args.append("--allow-private-targets")
        if options["skip_dns_guard"]:
            args.append("--trusted-target-list")
        if options["probe_live_before_queue"] and not reuse_parent_preflight:
            args.extend([
                "--probe-live-before-queue", "--probe-concurrency", str(options["probe_concurrency"]),
                "--probe-proxy-quorum", str(options["probe_proxy_quorum"]),
                "--probe-max-proxy-nodes", str(options["probe_max_proxy_nodes"]),
            ])
            if options["probe_keep_inconclusive"]:
                args.append("--probe-keep-inconclusive")
        if dry_run:
            args.append("--dry-run")
        return args

    def _scan_environment(
        self,
        job_id: str,
        options: dict[str, Any],
        *,
        parent_job_id: str = "",
        engine_role: str = "",
        engine_sequence: int = 0,
    ) -> tuple[dict[str, str], dict[str, str]]:
        submitted_at = datetime.now(timezone.utc).isoformat()
        overrides = {
            "STRIX_BATCH_STATE_DIR": str(self.paths.state_dir),
            "NSCAN_GLOBAL_SCAN_LIMIT": os.environ.get("NSCAN_GLOBAL_SCAN_LIMIT", "2"),
            "NSCAN_BATCH_SUBMITTED_AT": submitted_at,
            "NSCAN_BATCH_JOB_ID": job_id,
        }
        if parent_job_id:
            overrides.update({
                "NSCAN_PARENT_JOB_ID": parent_job_id,
                "NSCAN_ENGINE_ROLE": engine_role,
                "NSCAN_ENGINE_SEQUENCE": str(engine_sequence),
            })
        if options.get("use_socks5", True):
            overrides.setdefault("STRIX_DOCKER_NETWORK", os.environ.get("STRIX_DOCKER_NETWORK", "strix-egress"))
            overrides.setdefault("STRIX_USE_SOCKS5", "1")
        if options.get("allow_private_targets", False):
            overrides["NSCAN_ALLOW_PRIVATE_TARGETS"] = "1"
        env = os.environ.copy()
        env.update(overrides)
        return env, overrides

    def _start_process(self, args: list[str], stdout_file: Path, stderr_file: Path, env: dict[str, str]) -> subprocess.Popen[str]:
        stdout_handle = stdout_file.open("a", encoding="utf-8")
        stderr_handle = stderr_file.open("a", encoding="utf-8")
        try:
            return subprocess.Popen(  # noqa: S603
                args, cwd=str(self.paths.project_root), env=env, stdout=stdout_handle,
                stderr=stderr_handle, text=True, start_new_session=True,
            )
        finally:
            stdout_handle.close()
            stderr_handle.close()

    @staticmethod
    def _worker_unit_name(job_id: str) -> str:
        return f"nscan-scan-{safe_job_id(job_id)[:120]}"

    def _systemd_worker_status(self, unit: str) -> dict[str, Any]:
        systemctl = shutil.which("systemctl")
        if not systemctl or not unit:
            return {"available": False, "active": False, "state": "unavailable", "pid": None}
        completed = subprocess.run(  # noqa: S603 - fixed systemctl arguments
            [
                systemctl, "--user", "show", unit,
                "--property=ActiveState", "--property=SubState", "--property=MainPID",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        values = {}
        for line in (completed.stdout or "").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip()
        active_state = values.get("ActiveState", "unknown")
        sub_state = values.get("SubState", "unknown")
        try:
            pid = int(values.get("MainPID", "0"))
        except ValueError:
            pid = 0
        return {
            "available": completed.returncode == 0,
            "active": active_state in {"active", "activating"},
            "state": f"{active_state}/{sub_state}",
            "pid": pid or None,
        }

    def _start_worker(
        self,
        args: list[str],
        stdout_file: Path,
        stderr_file: Path,
        env: dict[str, str],
        overrides: dict[str, str],
        job_id: str,
    ) -> dict[str, Any]:
        """Launch a coordinator outside llm-proxy.service when possible."""
        mode = DEFAULT_WORKER_MODE
        unit = self._worker_unit_name(job_id)
        systemd_run = shutil.which("systemd-run")
        if mode != "process" and systemd_run:
            command = [
                systemd_run,
                "--user",
                f"--unit={unit}",
                "--collect",
                f"--working-directory={self.paths.project_root}",
                f"--property=StandardOutput=append:{stdout_file}",
                f"--property=StandardError=append:{stderr_file}",
                "--property=Restart=no",
                "--property=KillMode=mixed",
            ]
            for key, value in sorted(overrides.items()):
                command.append(f"--setenv={key}={value}")
            command.extend(args)
            completed = subprocess.run(  # noqa: S603 - args are generated locally
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            if completed.returncode == 0:
                status = self._systemd_worker_status(unit)
                return {
                    "worker_mode": "systemd-user",
                    "worker_unit": unit,
                    "worker_status": status["state"],
                    "pid": status["pid"],
                    "worker_warning": "",
                }
            warning = (completed.stderr or completed.stdout or "systemd-run failed").strip()[-300:]
        else:
            warning = "systemd-run is unavailable" if mode != "process" else "worker mode forced to process"

        process = self._start_process(args, stdout_file, stderr_file, env)
        return {
            "worker_mode": "process",
            "worker_unit": "",
            "worker_status": "active/process",
            "pid": process.pid,
            "worker_warning": warning,
        }

    def resume_job(self, job_id: str, source: str = "dashboard") -> dict[str, Any]:
        """Resume only incomplete dual-engine stages from their checkpoints."""
        job_file = self.paths.job_dir / f"{safe_job_id(job_id)}.json"
        job = self._read_job_file(job_file)
        if not job:
            raise KeyError(job_id)
        if job.get("engine") != "dual":
            raise ValueError("Only dual-engine parent jobs support checkpoint resume")
        refreshed = self._refresh_job_state(job)
        if refreshed.get("process_alive"):
            raise ValueError("This dual-engine job already has an active worker")
        if str(job.get("status") or "") in {"completed", "terminated", "dry_run_completed"}:
            raise ValueError(f"Job status {job.get('status')} cannot be resumed")

        children = job.get("children") if isinstance(job.get("children"), list) else []
        incomplete = [child for child in children if str(child.get("status") or "") != "completed"]
        if not incomplete:
            raise ValueError("No incomplete child stage is available to resume")
        options = job.get("options") if isinstance(job.get("options"), dict) else {}
        env, overrides = self._scan_environment(str(job.get("job_id") or job_id), options)
        coordinator_args = [str(self._python_bin()), "scanScript/dual_engine_scan.py", "--job-file", str(job_file)]
        paths = job.get("paths") if isinstance(job.get("paths"), dict) else {}
        worker = self._start_worker(
            coordinator_args,
            Path(str(paths.get("stdout_file") or self.paths.report_dir / f"{job_id}.stdout.log")),
            Path(str(paths.get("stderr_file") or self.paths.report_dir / f"{job_id}.stderr.log")),
            env,
            overrides,
            str(job.get("job_id") or job_id),
        )
        job.update({
            "status": "started",
            "phase": "recovering",
            "pid": worker["pid"],
            "worker_mode": worker["worker_mode"],
            "worker_unit": worker["worker_unit"],
            "worker_status": worker["worker_status"],
            "worker_warning": worker["worker_warning"],
            "worker_started_at": datetime.now(timezone.utc).isoformat(),
            "recovery_state": "resume_requested",
            "resume_requested_at": datetime.now(timezone.utc).isoformat(),
            "resume_source": source,
        })
        self._persist_job(job_file, job)
        return job

    def runtime_summary(self) -> dict[str, Any]:
        """Lightweight worker status for navigation and overview polling."""
        jobs = self.list_jobs(limit=200).get("jobs", [])
        active = [job for job in jobs if job.get("process_alive")]
        interrupted = [job for job in jobs if str(job.get("status") or "") == "interrupted"]
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "active_workers": len(active),
            "interrupted_jobs": len(interrupted),
            "workers": [
                {
                    "job_id": job.get("job_id"),
                    "label": job.get("label"),
                    "worker_unit": job.get("worker_unit"),
                    "worker_status": job.get("worker_status"),
                    "recovery_state": job.get("recovery_state"),
                    "phase": job.get("phase"),
                }
                for job in active[:20]
            ],
        }

    def _submit_dual_job(
        self,
        *,
        job: dict[str, Any],
        job_file: Path,
        options: dict[str, Any],
        dry_run: bool,
        timestamp: str,
    ) -> dict[str, Any]:
        parent_job_id = str(job["job_id"])
        target_file = Path(job["paths"]["target_file"])
        children: list[dict[str, Any]] = []
        for plan in DUAL_ENGINE_PLAN:
            engine, mode = plan["engine"], plan["mode"]
            reuse_parent_preflight = int(plan["engine_sequence"]) > 1
            suffix = f"{engine}-{plan['engine_sequence']}"
            child_label = clean_label(f"{job['label']}-{engine}")
            child_paths = {
                "history_file": str(self.paths.report_dir / f"{timestamp}_{child_label}_{parent_job_id}_{suffix}_history.txt"),
                "output_file": str(self.paths.report_dir / f"{timestamp}_{child_label}_{parent_job_id}_{suffix}_report.json"),
                "stdout_file": str(self.paths.report_dir / f"{timestamp}_{child_label}_{parent_job_id}_{suffix}.stdout.log"),
                "stderr_file": str(self.paths.report_dir / f"{timestamp}_{child_label}_{parent_job_id}_{suffix}.stderr.log"),
            }
            args = self._build_scan_args(
                target_file=target_file,
                label=child_label,
                history_file=Path(child_paths["history_file"]),
                output_file=Path(child_paths["output_file"]),
                options=options,
                engine=engine,
                mode=mode,
                dry_run=dry_run,
                reuse_parent_preflight=reuse_parent_preflight,
            )
            _, overrides = self._scan_environment(
                f"{parent_job_id}-{engine}", options, parent_job_id=parent_job_id,
                engine_role=str(plan["engine_role"]), engine_sequence=int(plan["engine_sequence"]),
            )
            children.append({
                **plan,
                "status": "planned" if dry_run else "pending",
                "pid": None,
                "paths": child_paths,
                "command": redact_command(args),
                "env": overrides,
                "target_file_index": 2,
                "preflight": {
                    "mode": "inherit_parent" if reuse_parent_preflight else "run_once",
                    "status": "pending" if reuse_parent_preflight else "not_started",
                },
            })

        job.update({
            "engine_plan": [dict(item) for item in DUAL_ENGINE_PLAN],
            "phase": "planned" if dry_run else "strix",
            "children": children,
            "completed_passes": 0,
            "total_passes": len(children),
            "command": [],
        })
        if dry_run:
            self._persist_job(job_file, job)
            return job

        coordinator_args = [str(self._python_bin()), "scanScript/dual_engine_scan.py", "--job-file", str(job_file)]
        env, overrides = self._scan_environment(parent_job_id, options)
        job["command"] = redact_command(coordinator_args)
        self._persist_job(job_file, job)
        worker = self._start_worker(
            coordinator_args,
            Path(job["paths"]["stdout_file"]),
            Path(job["paths"]["stderr_file"]),
            env,
            overrides,
            parent_job_id,
        )
        job.update({
            "pid": worker["pid"],
            "worker_mode": worker["worker_mode"],
            "worker_unit": worker["worker_unit"],
            "worker_status": worker["worker_status"],
            "worker_warning": worker["worker_warning"],
            "worker_started_at": datetime.now(timezone.utc).isoformat(),
            "recovery_state": "active",
        })
        job["status"] = "started"
        self._persist_job(job_file, job)
        return job

    def list_jobs(self, limit: int = 50) -> dict[str, Any]:
        self.paths.job_dir.mkdir(parents=True, exist_ok=True)
        try:
            from asset_database import get_asset_database

            stored = get_asset_database().smart_batch_jobs(limit=limit)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Smart Batch jobs SQLite read failed: %s", exc)
            stored = []
        if stored:
            jobs = [self._refresh_and_persist(job) for job in stored]
            return {"generated_at": datetime.now(timezone.utc).isoformat(), "jobs": jobs}
        files = sorted(self.paths.job_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        jobs = []
        for path in files:
            job = self._read_job_file(path)
            if job:
                if len(jobs) < max(1, min(int(limit or 50), 200)):
                    jobs.append(self._refresh_and_persist(job))
        return {"generated_at": datetime.now(timezone.utc).isoformat(), "jobs": jobs}

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job_file = self.paths.job_dir / f"{safe_job_id(job_id)}.json"
        try:
            from asset_database import get_asset_database

            job = get_asset_database().smart_batch_job(job_id)
        except Exception:  # noqa: BLE001
            job = None
        if not job:
            job = self._read_job_file(job_file)
        return self._refresh_and_persist(job) if job else None

    def _refresh_and_persist(self, job: dict[str, Any]) -> dict[str, Any]:
        """Make reconciliation durable for both SQLite and JSON consumers."""
        refreshed = self._refresh_job_state(job)
        job_id = str(refreshed.get("job_id") or "")
        if job_id:
            self._persist_job(self.paths.job_dir / f"{safe_job_id(job_id)}.json", refreshed)
        return refreshed

    def job_report(self, job_id: str) -> dict[str, Any]:
        job = self.get_job(job_id)
        if not job:
            raise KeyError(job_id)
        if job.get("engine") == "dual":
            return self._dual_job_report(job)
        paths = job.get("paths") if isinstance(job.get("paths"), dict) else {}
        report_path = Path(str(paths.get("output_file") or ""))
        target_count = int(job.get("target_count") or 0)
        report_exists = report_path.exists() and report_path.is_file() and report_path.stat().st_size > 0
        if not report_exists:
            logs = self.job_logs(job_id, tail=200)
            return {
                "jobId": job_id,
                "reportExists": False,
                "summary": {},
                "finalResults": 0,
                "findingsCount": 0,
                "failedTargets": target_count,
                "targetCount": target_count,
                "errorReason": infer_error_reason(logs.get("errorSummary") or logs.get("stderrTail") or "report_missing"),
            }
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "jobId": job_id,
                "reportExists": False,
                "summary": {},
                "finalResults": 0,
                "findingsCount": 0,
                "failedTargets": target_count,
                "targetCount": target_count,
                "errorReason": f"report_parse_error:{exc}",
            }
        summary = payload.get("summary") if isinstance(payload, dict) and isinstance(payload.get("summary"), dict) else {}
        final_results = payload.get("final_results") if isinstance(payload, dict) and isinstance(payload.get("final_results"), list) else []
        results = payload.get("results") if isinstance(payload, dict) and isinstance(payload.get("results"), list) else []
        findings_count = int(summary.get("total_vulnerabilities") or 0)
        failed_targets = sum(1 for item in final_results if isinstance(item, dict) and str(item.get("status") or "").lower() in {"failed", "error", "timeout"})
        result = {
            "jobId": job_id,
            "reportExists": True,
            "summary": summary,
            "finalResults": len(final_results),
            "totalAttempts": len(results),
            "findingsCount": findings_count,
            "failedTargets": failed_targets,
            "targetCount": target_count,
            "errorReason": "",
            "reportPath": str(report_path),
        }
        result.update(report_quality_warning(summary))
        return result

    def _dual_job_report(self, job: dict[str, Any]) -> dict[str, Any]:
        paths = job.get("paths") if isinstance(job.get("paths"), dict) else {}
        report_path = Path(str(paths.get("output_file") or ""))
        payload: dict[str, Any] = {}
        try:
            loaded = json.loads(report_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except (OSError, json.JSONDecodeError):
            pass
        children = job.get("children") if isinstance(job.get("children"), list) else []
        child_reports = []
        total_findings = 0
        failed_targets = 0
        for child in children:
            report = child.get("report") if isinstance(child.get("report"), dict) else {}
            findings = int(report.get("findings_count") or 0)
            total_findings += findings
            failed_targets += int(report.get("failed_targets") or 0)
            child_reports.append({
                "engine": child.get("engine"), "mode": child.get("mode"),
                "status": child.get("status"), "pid": child.get("pid"),
                "report": report, "paths": child.get("paths", {}),
                "error": child.get("error", ""),
            })
        return {
            "jobId": job.get("job_id"),
            "reportExists": bool(payload),
            "summary": payload,
            "finalResults": 0,
            "findingsCount": int(payload.get("findings_count") or total_findings),
            "failedTargets": failed_targets,
            "targetCount": int(job.get("target_count") or 0),
            "errorReason": "" if job.get("status") not in {"process_exited", "completed_with_errors"} else str(job.get("status")),
            "phase": job.get("phase"),
            "completedPasses": int(job.get("completed_passes") or 0),
            "totalPasses": int(job.get("total_passes") or len(children)),
            "children": child_reports,
            "reportPath": str(report_path),
        }

    def job_logs(self, job_id: str, tail: int = 200) -> dict[str, Any]:
        job = self.get_job(job_id)
        if not job:
            raise KeyError(job_id)
        paths = job.get("paths") if isinstance(job.get("paths"), dict) else {}
        stdout_tail = tail_file(Path(str(paths.get("stdout_file") or "")), tail)
        stderr_tail = tail_file(Path(str(paths.get("stderr_file") or "")), tail)
        history_tail = tail_file(Path(str(paths.get("history_file") or "")), tail)
        error_summary = infer_error_reason(stderr_tail)
        return {
            "jobId": job_id,
            "stdoutTail": stdout_tail,
            "stderrTail": stderr_tail,
            "historyTail": history_tail,
            "errorSummary": error_summary,
        }

    def terminate_job(self, job_id: str, source: str = "dashboard") -> dict[str, Any]:
        job_file = self.paths.job_dir / f"{safe_job_id(job_id)}.json"
        job = self._read_job_file(job_file)
        if not job:
            raise KeyError(job_id)
        if job.get("engine") != "dual":
            raise ValueError("Only dual-engine parent jobs can be terminated here")
        unit = str(job.get("worker_unit") or "")
        if unit:
            systemctl = shutil.which("systemctl")
            if systemctl:
                subprocess.run([systemctl, "--user", "stop", unit], capture_output=True, text=True, check=False, timeout=15)
        pid = job.get("pid")
        if not unit and pid_alive(pid):
            try:
                os.killpg(int(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
        for child in job.get("children") if isinstance(job.get("children"), list) else []:
            if str(child.get("status") or "") in {"pending", "running"}:
                child["status"] = "terminated"
                child["ended_at"] = datetime.now(timezone.utc).isoformat()
        job.update({
            "status": "terminated",
            "phase": "terminated",
            "termination_requested_at": datetime.now(timezone.utc).isoformat(),
            "termination_source": source,
        })
        self._persist_job(job_file, job)
        return self._refresh_job_state(job)

    def _read_job_file(self, path: Path) -> dict[str, Any] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _refresh_job_state(self, job: dict[str, Any]) -> dict[str, Any]:
        unit = str(job.get("worker_unit") or "")
        if unit:
            worker = self._systemd_worker_status(unit)
            job["worker_status"] = worker["state"]
            if worker.get("pid"):
                job["pid"] = worker["pid"]
            job["process_alive"] = bool(worker["active"])
            if job.get("status") in {"started", "running", "dry_run_started"} and not job["process_alive"]:
                job["status"] = "interrupted"
                job["recovery_state"] = "worker_exited"
        else:
            pid = job.get("pid")
            job["process_alive"] = pid_alive(pid)
            if job.get("status") in {"started", "dry_run_started"} and not job["process_alive"]:
                job["status"] = "process_exited"
        if job.get("engine") == "dual":
            job["completed_passes"] = int(job.get("completed_passes") or 0)
            job["total_passes"] = int(job.get("total_passes") or len(job.get("children") or []))
        return job

    def _python_bin(self) -> Path:
        candidate = self.paths.project_root / ".venv" / "bin" / "python"
        if candidate.exists():
            return candidate
        candidate3 = self.paths.project_root / ".venv" / "bin" / "python3"
        if candidate3.exists():
            return candidate3
        return Path(sys.executable)

    def _max_targets(self, payload: dict[str, Any]) -> int:
        requested = payload.get("max_targets", DEFAULT_MAX_TARGETS)
        try:
            value = int(requested)
        except (TypeError, ValueError):
            value = DEFAULT_MAX_TARGETS
        return max(1, min(value, DEFAULT_MAX_TARGETS))

    def _options(self, payload: dict[str, Any]) -> dict[str, Any]:
        requested_engine = payload.get("engine")
        engine = str(requested_engine or DEFAULT_ENGINE).strip().lower()
        if requested_engine in (None, "") and engine == "dual" and not get_chelmon_runtime_status().get("ready"):
            engine = "strix"
        if engine not in ALLOWED_ENGINES:
            raise ValueError(f"Unsupported scan engine: {engine}")
        if engine == "ansecai":
            engine = "chelmon-claude"
        requested_mode = payload.get("mode")
        workflow_mode = "retest" if str(requested_mode or "").strip().lower() == "retest" else ""
        if workflow_mode:
            if str(payload.get("source") or "dashboard").strip().lower() == "target_ingest":
                raise ValueError("Retest is only available for explicit Dashboard or Smart Batch submissions")
            if requested_engine not in (None, "", "dual"):
                raise ValueError("Retest requires engine=dual")
            engine, mode = "dual", "retest"
        else:
            mode = "dual" if engine == "dual" else (str(requested_mode).strip().lower() if requested_mode not in (None, "") else ("default" if engine == "chelmon-claude" else "redteam"))
        if mode != "dual" and mode not in ALLOWED_MODES:
            raise ValueError(f"Unsupported scan mode: {mode}")
        try:
            parallel = int(payload.get("parallel") or 2)
        except (TypeError, ValueError):
            parallel = 2
        try:
            timeout = int(payload["timeout"]) if "timeout" in payload else 0
        except (TypeError, ValueError):
            timeout = 0
        try:
            probe_concurrency = int(payload.get("probe_concurrency") or 40)
        except (TypeError, ValueError):
            probe_concurrency = 40
        try:
            probe_proxy_quorum = int(payload.get("probe_proxy_quorum") or 2)
        except (TypeError, ValueError):
            probe_proxy_quorum = 2
        try:
            probe_max_proxy_nodes = int(payload.get("probe_max_proxy_nodes") or 3)
        except (TypeError, ValueError):
            probe_max_proxy_nodes = 3
        return {
            "engine": engine,
            "mode": mode,
            "workflow_mode": workflow_mode,
            "engine_plan": [dict(item) for item in DUAL_ENGINE_PLAN] if engine == "dual" else [{"engine": engine, "mode": mode, "engine_role": "single", "engine_sequence": 1}],
            "parallel": max(1, min(parallel, DEFAULT_MAX_PARALLEL)),
            "timeout": 0 if timeout == 0 else max(300, min(timeout, 14400)),
            "single_targets": bool(payload.get("single_targets", True)),
            "use_socks5": bool(payload.get("use_socks5", True)),
            "monitor": bool(payload.get("monitor", True)),
            # A dual job promises two complete passes for each accepted target.
            # Reusing the historical skip flag would allow the first pass to
            # suppress the Chelmon pass after it records the target.
            "skip_scanned": False if engine == "dual" else bool(payload.get("skip_scanned", False)),
            "model": str(payload.get("model") or "").strip(),
            "allow_private_targets": bool(payload.get("allow_private_targets", False)),
            "skip_dns_guard": bool(payload.get("skip_dns_guard", True)),
            "probe_live_before_queue": bool(payload.get("probe_live_before_queue", True)),
            "probe_concurrency": max(1, min(probe_concurrency, 200)),
            "probe_proxy_quorum": max(1, min(probe_proxy_quorum, 10)),
            "probe_max_proxy_nodes": max(1, min(probe_max_proxy_nodes, 10)),
            "probe_keep_inconclusive": bool(payload.get("probe_keep_inconclusive", True)),
            "source": str(payload.get("source") or "dashboard").strip().lower(),
            "platform": normalize_platform(str(payload.get("platform") or "dashboard")),
            "source_ref": str(payload.get("source_ref") or "").strip(),
            "allow_non_uae": bool(payload.get("allow_non_uae", False)),
        }



def safe_job_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "", str(value or ""))
    if not cleaned:
        raise ValueError("invalid job id")
    return cleaned[:160]


def tail_file(path: Path, lines: int = 200) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        data = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    return "\n".join(data[-max(1, min(lines, 1000)):])


def infer_error_reason(text: str) -> str:
    lower = str(text or "").lower()
    if "没有符合当前扫描模式和额度策略的可用模型" in str(text) or "no eligible" in lower or "model unavailable" in lower or "model_unavailable" in lower:
        return "model_unavailable"
    if "llm warm-up failed" in lower or "llm connection failed" in lower:
        return "model_unavailable"
    if "report_missing" in lower:
        return "report_missing"
    if "traceback" in lower:
        return "scan_error"
    return ""


def report_quality_warning(summary: dict[str, Any]) -> dict[str, Any]:
    usage_by_model = summary.get("llm_model_usage_by_model") if isinstance(summary.get("llm_model_usage_by_model"), dict) else {}
    requests = 0
    failed_requests = 0
    for usage in usage_by_model.values():
        if not isinstance(usage, dict):
            continue
        try:
            requests += int(usage.get("requests") or 0)
            failed_requests += int(usage.get("failed_requests") or 0)
        except (TypeError, ValueError):
            continue
    if requests < 5:
        return {}
    failure_rate = failed_requests / max(requests, 1)
    if failure_rate < 0.5:
        return {}
    return {
        "qualityWarning": "llm_high_failure_rate",
        "llmFailureRate": round(failure_rate, 4),
        "llmFailedRequests": failed_requests,
        "llmRequests": requests,
    }

def parse_targets(raw: Any, max_targets: int = DEFAULT_MAX_TARGETS) -> list[str]:
    return analyze_targets(raw, max_targets=max_targets, allow_private=False)["accepted_targets"]


def analyze_targets(
    raw: Any,
    max_targets: int = DEFAULT_MAX_TARGETS,
    allow_private: bool = False,
    check_dns: bool | None = None,
    *,
    source: str = "dashboard",
    allow_non_uae: bool = False,
    country: str = "",
    region: str = "",
    certificate_lookup: bool = False,
    enforce_scope: bool = True,
) -> dict[str, Any]:
    if isinstance(raw, list):
        lines = [str(item) for item in raw]
    else:
        lines = str(raw or "").splitlines()
    targets: list[str] = []
    seen: set[str] = set()
    rejected: list[str] = []
    restricted: list[dict[str, Any]] = []
    scope_rejected: list[dict[str, Any]] = []
    scope_blocked: list[dict[str, Any]] = []
    scope_review: list[dict[str, Any]] = []
    scope_decisions: list[dict[str, Any]] = []
    scope_category_counts: dict[str, int] = {}
    scope_catalog_version = "uninitialized"
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        value = value.split("#", 1)[0].strip()
        if not value:
            continue
        if len(value) > 260 or not TARGET_RE.match(value):
            rejected.append(value[:80])
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        guard = check_network_target(
            value,
            allow_private=allow_private,
            check_dns=env_dns_guard_enabled() if check_dns is None else bool(check_dns),
        )
        if not guard.allowed:
            restricted.append(guard.to_dict())
            continue
        scope = classify_target_scope(
            value,
            source=source,
            allow_non_uae=allow_non_uae,
            country=country,
            region=region,
            certificate_lookup=certificate_lookup,
        )
        scope_decisions.append(scope)
        scope_catalog_version = str(scope.get("catalog_version") or scope_catalog_version)
        if not scope["allowed"]:
            scope_rejected.append(scope)
            if scope.get("scope_status") == "scope_review_required":
                scope_review.append(scope)
            else:
                scope_blocked.append(scope)
            if enforce_scope:
                continue
        targets.append(value)
        category = str(scope.get("category") or "")
        if category:
            scope_category_counts[category] = scope_category_counts.get(category, 0) + 1
        if len(targets) > max_targets:
            raise ValueError(f"Too many targets; limit is {max_targets}")
    if rejected:
        raise ValueError(f"Rejected invalid target entries: {', '.join(rejected[:5])}")
    if not targets and not restricted and not scope_rejected:
        raise ValueError("No valid targets supplied")
    return {
        "accepted_targets": targets,
        "rejected_targets": restricted + scope_rejected,
        "restricted_targets": restricted,
        "scope_rejected_targets": scope_rejected,
        "scope_blocked_targets": scope_blocked,
        "scope_review_targets": scope_review,
        "scope_decisions": scope_decisions,
        "restricted_target_count": len(restricted),
        "scope_rejected_count": len(scope_rejected),
        "scope_category_counts": scope_category_counts,
        "scope_catalog_version": scope_catalog_version,
    }


def clean_label(value: str) -> str:
    cleaned = SAFE_NAME_RE.sub("-", value.strip().lower()).strip("-._")
    return (cleaned or "batch")[:48]


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def redact_command(args: list[str]) -> list[str]:
    return [str(item) for item in args]


def pid_alive(pid: Any) -> bool:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return False
    if pid_int <= 0:
        return False
    stat_path = Path(f"/proc/{pid_int}/stat")
    try:
        stat_parts = stat_path.read_text(encoding="utf-8").split()
        if len(stat_parts) > 2 and stat_parts[2] == "Z":
            return False
    except OSError:
        pass
    try:
        os.kill(pid_int, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
