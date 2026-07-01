"""Submit Smart Batch scan jobs from the Nscan dashboard.

This module is deliberately thin: it validates dashboard input, writes a
timestamped target file, and launches the existing Smart Batch CLI with an
argument list. The scanner remains the source of truth for execution and state.
"""

from __future__ import annotations

import json
import os
import re
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


TARGET_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,252}$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
ALLOWED_MODES = {"quick", "standard", "deep", "redteam"}
DEFAULT_MAX_TARGETS = 500
DEFAULT_MAX_PARALLEL = 4


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

    def preview(self, payload: dict[str, Any]) -> dict[str, Any]:
        options = self._options(payload)
        analysis = analyze_targets(
            payload.get("targets", ""),
            max_targets=self._max_targets(payload),
            allow_private=options["allow_private_targets"],
        )
        return {
            "valid": analysis["restricted_target_count"] == 0,
            "target_count": len(analysis["accepted_targets"]),
            "targets": analysis["accepted_targets"][:50],
            "accepted_targets": analysis["accepted_targets"],
            "rejected_targets": analysis["rejected_targets"],
            "restricted_target_count": analysis["restricted_target_count"],
            "truncated_preview": len(analysis["accepted_targets"]) > 50,
            "options": options,
        }

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        options = self._options(payload)
        analysis = analyze_targets(
            payload.get("targets", ""),
            max_targets=self._max_targets(payload),
            allow_private=options["allow_private_targets"],
        )
        if analysis["rejected_targets"] and not options["allow_private_targets"]:
            sample = ", ".join(item["target"] for item in analysis["rejected_targets"][:5])
            raise ValueError(f"Restricted local/private targets blocked: {sample}")
        targets = analysis["accepted_targets"]
        dry_run = bool(payload.get("dry_run", False))
        job_id = f"dashboard-{int(time.time())}-{uuid.uuid4().hex[:8]}"
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

        python_bin = self._python_bin()
        args = [
            str(python_bin),
            "scanScript/smart_batch_scan.py",
            str(target_file),
            "--mode",
            options["mode"],
            "--parallel",
            str(options["parallel"]),
            "--timeout",
            str(options["timeout"]),
            "--history-file",
            str(history_file),
            "--output",
            str(output_file),
        ]
        if options["single_targets"]:
            args.append("--single-targets")
        if options["use_socks5"]:
            args.append("--use-socks5")
        else:
            args.append("--no-socks5")
        if options["monitor"]:
            args.append("--monitor")
        if options["skip_scanned"]:
            args.append("--skip-scanned")
        if options["model"]:
            args.extend(["--model", options["model"]])
        if options["allow_private_targets"]:
            args.append("--allow-private-targets")
        if dry_run:
            args.append("--dry-run")

        env = os.environ.copy()
        env.setdefault("STRIX_BATCH_STATE_DIR", str(self.paths.state_dir))
        if options["use_socks5"]:
            env.setdefault("STRIX_DOCKER_NETWORK", "strix-egress")
            env.setdefault("STRIX_USE_SOCKS5", "1")
        if options["allow_private_targets"]:
            env["NSCAN_ALLOW_PRIVATE_TARGETS"] = "1"

        stdout_handle = stdout_file.open("a", encoding="utf-8")
        stderr_handle = stderr_file.open("a", encoding="utf-8")
        try:
            process = subprocess.Popen(
                args,
                cwd=str(self.paths.project_root),
                env=env,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                start_new_session=True,
            )
        finally:
            stdout_handle.close()
            stderr_handle.close()

        job = {
            "job_id": job_id,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "status": "dry_run_started" if dry_run else "started",
            "pid": process.pid,
            "target_count": len(targets),
            "targets_preview": targets[:20],
            "rejected_targets": analysis["rejected_targets"],
            "options": options,
            "paths": {
                "target_file": str(target_file),
                "history_file": str(history_file),
                "output_file": str(output_file),
                "stdout_file": str(stdout_file),
                "stderr_file": str(stderr_file),
                "state_dir": str(self.paths.state_dir),
            },
            "command": redact_command(args),
        }
        atomic_write_json(job_file, job)
        return job

    def list_jobs(self, limit: int = 50) -> dict[str, Any]:
        self.paths.job_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(self.paths.job_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        jobs = []
        for path in files[: max(1, min(int(limit or 50), 200))]:
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            pid = job.get("pid")
            job["process_alive"] = pid_alive(pid)
            if job.get("status") in {"started", "dry_run_started"} and not job["process_alive"]:
                job["status"] = "process_exited"
            jobs.append(job)
        return {"generated_at": datetime.now(timezone.utc).isoformat(), "jobs": jobs}

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
        mode = str(payload.get("mode") or "redteam").strip().lower()
        if mode not in ALLOWED_MODES:
            raise ValueError(f"Unsupported scan mode: {mode}")
        try:
            parallel = int(payload.get("parallel") or 2)
        except (TypeError, ValueError):
            parallel = 2
        try:
            timeout = int(payload.get("timeout") or 3600)
        except (TypeError, ValueError):
            timeout = 3600
        return {
            "mode": mode,
            "parallel": max(1, min(parallel, DEFAULT_MAX_PARALLEL)),
            "timeout": max(300, min(timeout, 14400)),
            "single_targets": bool(payload.get("single_targets", True)),
            "use_socks5": bool(payload.get("use_socks5", True)),
            "monitor": bool(payload.get("monitor", True)),
            "skip_scanned": bool(payload.get("skip_scanned", False)),
            "model": str(payload.get("model") or "").strip(),
            "allow_private_targets": bool(payload.get("allow_private_targets", False)),
        }


def parse_targets(raw: Any, max_targets: int = DEFAULT_MAX_TARGETS) -> list[str]:
    return analyze_targets(raw, max_targets=max_targets, allow_private=False)["accepted_targets"]


def analyze_targets(raw: Any, max_targets: int = DEFAULT_MAX_TARGETS, allow_private: bool = False) -> dict[str, Any]:
    if isinstance(raw, list):
        lines = [str(item) for item in raw]
    else:
        lines = str(raw or "").splitlines()
    targets: list[str] = []
    seen: set[str] = set()
    rejected: list[str] = []
    restricted: list[dict[str, Any]] = []
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
            check_dns=env_dns_guard_enabled(),
        )
        if not guard.allowed:
            restricted.append(guard.to_dict())
            continue
        targets.append(value)
        if len(targets) > max_targets:
            raise ValueError(f"Too many targets; limit is {max_targets}")
    if rejected:
        raise ValueError(f"Rejected invalid target entries: {', '.join(rejected[:5])}")
    if not targets and not restricted:
        raise ValueError("No valid targets supplied")
    return {
        "accepted_targets": targets,
        "rejected_targets": restricted,
        "restricted_target_count": len(restricted),
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
    try:
        os.kill(pid_int, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
