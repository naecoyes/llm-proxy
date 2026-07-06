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
from target_policy import classify_target_scope, normalize_platform


TARGET_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,252}$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
ALLOWED_MODES = {"quick", "standard", "deep", "redteam", "getshell"}
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
            check_dns=not options["skip_dns_guard"],
            source=options["source"],
            allow_non_uae=options["allow_non_uae"],
            country=str(payload.get("country") or ""),
            region=str(payload.get("region") or ""),
        )
        return {
            "valid": analysis["restricted_target_count"] == 0 and analysis["scope_rejected_count"] == 0,
            "target_count": len(analysis["accepted_targets"]),
            "targets": analysis["accepted_targets"][:50],
            "accepted_targets": analysis["accepted_targets"],
            "rejected_targets": analysis["rejected_targets"],
            "restricted_targets": analysis["restricted_targets"],
            "scope_rejected_targets": analysis["scope_rejected_targets"],
            "restricted_target_count": analysis["restricted_target_count"],
            "scope_rejected_count": analysis["scope_rejected_count"],
            "truncated_preview": len(analysis["accepted_targets"]) > 50,
            "options": options,
        }

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        options = self._options(payload)
        analysis = analyze_targets(
            payload.get("targets", ""),
            max_targets=self._max_targets(payload),
            allow_private=options["allow_private_targets"],
            check_dns=not options["skip_dns_guard"],
            source=options["source"],
            allow_non_uae=options["allow_non_uae"],
            country=str(payload.get("country") or ""),
            region=str(payload.get("region") or ""),
        )
        if analysis["restricted_targets"] and not options["allow_private_targets"]:
            sample = ", ".join(item["target"] for item in analysis["restricted_targets"][:5])
            raise ValueError(f"Restricted local/private targets blocked: {sample}")
        if analysis["scope_rejected_targets"]:
            sample = ", ".join(item["target"] for item in analysis["scope_rejected_targets"][:5])
            raise ValueError(f"Out-of-scope non-UAE targets blocked: {sample}")
        targets = analysis["accepted_targets"]
        if not targets:
            raise ValueError("No accepted targets supplied")
        dry_run = bool(payload.get("dry_run", False))
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

        python_bin = self._python_bin()
        args = [
            str(python_bin),
            "scanScript/smart_batch_scan.py",
            str(target_file),
            "--mode",
            options["mode"],
            "--label",
            label,
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
        if options["skip_dns_guard"]:
            args.append("--trusted-target-list")
        if options["probe_live_before_queue"]:
            args.append("--probe-live-before-queue")
            args.extend(["--probe-concurrency", str(options["probe_concurrency"])])
            args.extend(["--probe-proxy-quorum", str(options["probe_proxy_quorum"])])
            args.extend(["--probe-max-proxy-nodes", str(options["probe_max_proxy_nodes"])])
            if options["probe_keep_inconclusive"]:
                args.append("--probe-keep-inconclusive")
        if dry_run:
            args.append("--dry-run")

        env = os.environ.copy()
        env.setdefault("STRIX_BATCH_STATE_DIR", str(self.paths.state_dir))
        env.setdefault("NSCAN_GLOBAL_SCAN_LIMIT", "2")
        env["NSCAN_BATCH_SUBMITTED_AT"] = datetime.now(timezone.utc).isoformat()
        env["NSCAN_BATCH_JOB_ID"] = job_id
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
            "label": label,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "status": "dry_run_started" if dry_run else "started",
            "pid": process.pid,
            "target_count": len(targets),
            "targets_preview": targets[:20],
            "rejected_targets": analysis["rejected_targets"],
            "restricted_targets": analysis["restricted_targets"],
            "scope_rejected_targets": analysis["scope_rejected_targets"],
            "blocked_count": analysis["restricted_target_count"] + analysis["scope_rejected_count"],
            "source_type": options["source"],
            "platform": options["platform"],
            "source_ref": options["source_ref"],
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
            job = self._read_job_file(path)
            if job:
                jobs.append(self._refresh_job_state(job))
        return {"generated_at": datetime.now(timezone.utc).isoformat(), "jobs": jobs}

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job_file = self.paths.job_dir / f"{safe_job_id(job_id)}.json"
        job = self._read_job_file(job_file)
        return self._refresh_job_state(job) if job else None

    def job_report(self, job_id: str) -> dict[str, Any]:
        job = self.get_job(job_id)
        if not job:
            raise KeyError(job_id)
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

    def _read_job_file(self, path: Path) -> dict[str, Any] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _refresh_job_state(self, job: dict[str, Any]) -> dict[str, Any]:
        pid = job.get("pid")
        job["process_alive"] = pid_alive(pid)
        if job.get("status") in {"started", "dry_run_started"} and not job["process_alive"]:
            job["status"] = "process_exited"
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
        mode = str(payload.get("mode") or "redteam").strip().lower()
        if mode not in ALLOWED_MODES:
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
            "mode": mode,
            "parallel": max(1, min(parallel, DEFAULT_MAX_PARALLEL)),
            "timeout": 0 if timeout == 0 else max(300, min(timeout, 14400)),
            "single_targets": bool(payload.get("single_targets", True)),
            "use_socks5": bool(payload.get("use_socks5", True)),
            "monitor": bool(payload.get("monitor", True)),
            "skip_scanned": bool(payload.get("skip_scanned", False)),
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
        )
        if not scope["allowed"]:
            scope_rejected.append(scope)
            continue
        targets.append(value)
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
        "restricted_target_count": len(restricted),
        "scope_rejected_count": len(scope_rejected),
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
