"""Smart Batch and host resource monitoring helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    import psutil  # type: ignore[import-untyped]
except Exception:  # noqa: BLE001
    psutil = None


FINISHED_BATCH_STATUSES = {
    "completed",
    "completed_with_errors",
    "dry_run_completed",
    "failed",
    "timeout",
    "success",
    "terminated",
}
ACTIVE_BATCH_STATUSES = {"initialized", "planning", "running", "paused"}
STALE_AFTER_SECONDS = 30
VALID_BATCH_ID = re.compile(r"^smart-batch-[A-Za-z0-9-]+$")


def get_state_dir() -> Path:
    return Path(
        os.environ.get(
            "STRIX_BATCH_STATE_DIR",
            str(Path(__file__).resolve().parent / "runtime" / "smart_batch"),
        )
    )


def read_smart_batch_status(
    limit: int = 20,
    include_finished: bool = True,
    include_tasks: bool = True,
) -> dict[str, Any]:
    state_dir = get_state_dir()
    files = (
        sorted(
            (
                path
                for path in state_dir.glob("*.json")
                if not path.name.endswith(".control.json")
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if state_dir.exists()
        else []
    )
    batches: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for path in files:
        try:
            batch = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        enriched = enrich_batch(batch, path)
        if not include_finished and enriched.get("lifecycle") == "finished":
            continue
        if not include_tasks:
            enriched = dict(enriched)
            enriched["task_count"] = len(enriched.get("tasks") or [])
            enriched.pop("tasks", None)
            enriched.pop("recent_events", None)
        batches.append(enriched)
        if len(batches) >= max(1, min(int(limit or 20), 200)):
            break

    return {
        "state_dir": str(state_dir),
        "generated_at": now_iso(),
        "summary": summarize_batches(batches),
        "batches": batches,
        "errors": errors,
    }


def read_smart_batch_detail(batch_id: str) -> dict[str, Any] | None:
    state_dir = get_state_dir()
    path = state_dir / f"{batch_id}.json"
    if not path.exists():
        return None
    try:
        return enrich_batch(json.loads(path.read_text(encoding="utf-8")), path)
    except (OSError, json.JSONDecodeError):
        return None


def set_smart_batch_parallel(batch_id: str, parallel: int, source: str = "dashboard") -> dict[str, Any]:
    """Request a runtime parallelism change for an active Smart Batch.

    The scanner process polls a sibling ``.control.json`` file and applies the
    value before launching new task windows. Existing child scans are not killed.
    """
    batch = read_smart_batch_detail(batch_id)
    if batch is None:
        raise ValueError(f"Smart Batch {batch_id} not found")
    try:
        parallel = int(parallel)
    except (TypeError, ValueError) as exc:
        raise ValueError("parallel must be an integer") from exc
    if parallel < 1 or parallel > 32:
        raise ValueError("parallel must be between 1 and 32")
    if batch.get("lifecycle") == "finished":
        raise ValueError(f"Smart Batch {batch_id} is finished")

    state_file = Path(str(batch.get("state_file") or get_state_dir() / f"{batch_id}.json"))
    control_path = state_file.with_name(f"{batch_id}.control.json")
    control_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "batch_id": batch_id,
        "parallel": parallel,
        "source": source,
        "requested_at": now_iso(),
    }
    tmp_path = control_path.with_suffix(".control.json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, control_path)
    try:
        from asset_database import get_asset_database

        get_asset_database().record_batch_control(payload)
    except Exception:
        # The control file is authoritative for the running scanner.
        pass

    updated = dict(batch)
    updated["parallel_control"] = payload
    updated["control_file"] = str(control_path)
    return updated


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, path)


def set_smart_batch_paused(batch_id: str, paused: bool, source: str = "dashboard") -> dict[str, Any]:
    if not VALID_BATCH_ID.fullmatch(batch_id):
        raise ValueError("invalid Smart Batch ID")
    batch = read_smart_batch_detail(batch_id)
    if batch is None:
        raise ValueError(f"Smart Batch {batch_id} not found")
    if batch.get("lifecycle") == "finished":
        raise ValueError(f"Smart Batch {batch_id} is finished")
    state_file = Path(str(batch.get("state_file") or get_state_dir() / f"{batch_id}.json"))
    control_path = state_file.with_name(f"{batch_id}.control.json")
    payload = {
        "batch_id": batch_id,
        "parallel": int(batch.get("parallel") or 1),
        "paused": bool(paused),
        "source": source,
        "requested_at": now_iso(),
    }
    _write_json_atomic(control_path, payload)
    updated = dict(batch)
    updated["paused"] = bool(paused)
    updated["pause_control"] = payload
    updated["control_file"] = str(control_path)
    return updated


def _batch_parent_pid(batch: dict[str, Any]) -> int | None:
    if psutil is None:
        return None
    candidates = [batch.get("batch_pid")]
    target_file = str((batch.get("input_source") or {}).get("targets_file") or "")
    try:
        process_list = list(psutil.process_iter(["pid", "cmdline"]))
    except (OSError, PermissionError):
        process_list = []
    for proc in process_list:
        try:
            cmdline = [str(item) for item in (proc.info.get("cmdline") or [])]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        joined = " ".join(cmdline)
        if target_file and "smart_batch_scan.py" in joined and (target_file in cmdline or target_file in joined):
            candidates.append(proc.info.get("pid"))
    for candidate in candidates:
        try:
            pid = int(candidate)
            if pid > 1 and psutil.pid_exists(pid):
                return pid
        except (TypeError, ValueError):
            continue
    return None


def terminate_smart_batch(batch_id: str, source: str = "dashboard") -> dict[str, Any]:
    if not VALID_BATCH_ID.fullmatch(batch_id):
        raise ValueError("invalid Smart Batch ID")
    batch = read_smart_batch_detail(batch_id)
    if batch is None:
        raise ValueError(f"Smart Batch {batch_id} not found")
    if batch.get("lifecycle") == "finished":
        raise ValueError(f"Smart Batch {batch_id} is finished")
    if psutil is None:
        raise RuntimeError("psutil is required to terminate a Smart Batch")

    parent_pid = _batch_parent_pid(batch)
    processes: dict[int, Any] = {}
    if parent_pid:
        try:
            parent = psutil.Process(parent_pid)
            processes[parent.pid] = parent
            for child in parent.children(recursive=True):
                processes[child.pid] = child
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    for task in batch.get("tasks") or []:
        try:
            pid = int(task.get("strix_pid") or 0)
            if pid > 1 and psutil.pid_exists(pid):
                processes[pid] = psutil.Process(pid)
        except (TypeError, ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    ordered = [proc for pid, proc in processes.items() if pid != parent_pid]
    if parent_pid and parent_pid in processes:
        ordered.append(processes[parent_pid])
    for proc in ordered:
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(ordered, timeout=5)
    for proc in alive:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    removed_containers: list[str] = []
    try:
        listed = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=nscan.batch_id={batch_id}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        container_ids = [item for item in listed.stdout.splitlines() if item.strip()]
        if container_ids:
            removed = subprocess.run(
                ["docker", "rm", "-f", *container_ids], capture_output=True, text=True, timeout=30, check=False,
            )
            if removed.returncode == 0:
                removed_containers = container_ids
    except (OSError, subprocess.TimeoutExpired):
        pass

    state_file = Path(str(batch.get("state_file") or get_state_dir() / f"{batch_id}.json"))
    raw = json.loads(state_file.read_text(encoding="utf-8"))
    for task in raw.get("tasks") or []:
        if str(task.get("status") or "") in {"pending", "running", "retrying", "retry_pending"}:
            task["status"] = "cancelled"
            task["last_error"] = "Batch terminated by operator"
    raw["status"] = "terminated"
    raw["terminated_at"] = now_iso()
    raw["updated_at"] = raw["terminated_at"]
    raw["paused"] = False
    raw.setdefault("recent_events", []).append({
        "timestamp": raw["terminated_at"], "event": "batch_terminated", "level": "warning",
        "message": "Smart Batch terminated by operator", "source": source,
    })
    _write_json_atomic(state_file, raw)
    return {"status": "terminated", "batch_id": batch_id, "terminated_processes": len(processes), "removed_containers": removed_containers}


def delete_smart_batch(batch_id: str, source: str = "dashboard") -> dict[str, Any]:
    if not VALID_BATCH_ID.fullmatch(batch_id):
        raise ValueError("invalid Smart Batch ID")
    batch = read_smart_batch_detail(batch_id)
    if batch is None:
        raise ValueError(f"Smart Batch {batch_id} not found")
    if _batch_parent_pid(batch) or has_live_running_task(batch):
        raise ValueError("terminate the active Smart Batch before deleting it")
    state_file = Path(str(batch.get("state_file") or get_state_dir() / f"{batch_id}.json"))
    deleted_dir = state_file.parent / "_deleted"
    deleted_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    moved: list[str] = []
    for path in (state_file, state_file.with_name(f"{batch_id}.control.json")):
        if path.exists():
            destination = deleted_dir / f"{stamp}-{path.name}"
            shutil.move(str(path), str(destination))
            moved.append(str(destination))
    return {"status": "deleted", "batch_id": batch_id, "reports_preserved": True, "moved_state_files": moved, "source": source}


def enrich_batch(batch: dict[str, Any], path: Path) -> dict[str, Any]:
    updated_at = parse_datetime(batch.get("updated_at"))
    age_seconds = max(0, (datetime.now(timezone.utc) - updated_at).total_seconds()) if updated_at else None
    status = str(batch.get("status") or "unknown")
    has_live_tasks = has_live_running_task(batch)
    if status in FINISHED_BATCH_STATUSES:
        lifecycle = "finished"
    elif status in ACTIVE_BATCH_STATUSES and (
        has_live_tasks or (age_seconds is not None and age_seconds <= STALE_AFTER_SECONDS)
    ):
        lifecycle = "active"
    elif status in ACTIVE_BATCH_STATUSES:
        lifecycle = "stale"
    else:
        lifecycle = "unknown"

    enriched = dict(batch)
    enriched["summary"] = normalize_batch_summary(batch)
    enriched.update(
        {
            "state_file": str(path),
            "age_seconds": round(age_seconds, 3) if age_seconds is not None else None,
            "has_live_running_tasks": has_live_tasks,
            "lifecycle": lifecycle,
            "is_active": lifecycle == "active",
            "is_stale": lifecycle == "stale",
        }
    )
    return enriched


def normalize_batch_summary(batch: dict[str, Any]) -> dict[str, Any]:
    """Return a stable summary for old and new Smart Batch state schemas."""
    original = batch.get("summary") or {}
    derived = derive_task_summary(batch)
    summary = dict(original)
    for key, value in derived.items():
        if key not in summary or summary.get(key) in (None, ""):
            summary[key] = value

    # Prefer task-derived counts when task rows exist; they are usually fresher
    # than older summary snapshots that only tracked a subset of states.
    if batch.get("tasks"):
        for key in (
            "total_tasks",
            "running",
            "pending",
            "success",
            "failed",
            "timeout",
            "retrying",
            "retry_pending",
            "auto_requeue_pending",
            "queued",
        ):
            summary[key] = derived.get(key, summary.get(key, 0))

    total = int(summary.get("total_tasks") or 0)
    completed = (
        int(summary.get("success") or 0)
        + int(summary.get("failed") or 0)
        + int(summary.get("timeout") or 0)
    )
    summary["completed_tasks"] = completed
    summary["progress_percent"] = round(completed / total * 100, 2) if total else 0
    return summary


def derive_task_summary(batch: dict[str, Any]) -> dict[str, int]:
    counts = {
        "total_tasks": 0,
        "running": 0,
        "pending": 0,
        "queued": 0,
        "success": 0,
        "failed": 0,
        "timeout": 0,
        "retrying": 0,
        "retry_pending": 0,
        "auto_requeue_pending": 0,
        "retry_attempts_total": 0,
        "auto_requeued_tasks": 0,
        "auto_requeue_attempts_total": 0,
        "attempt_count_total": 0,
    }
    tasks = batch.get("tasks") or []
    counts["total_tasks"] = len(tasks)
    for task in tasks:
        status = str(task.get("status") or "pending").lower()
        if status in {"success", "succeeded", "completed"}:
            counts["success"] += 1
        elif status in {"failed", "error"}:
            counts["failed"] += 1
        elif status == "timeout":
            counts["timeout"] += 1
        elif status == "running":
            counts["running"] += 1
        elif status == "retrying":
            counts["retrying"] += 1
        elif status == "retry_pending":
            counts["retry_pending"] += 1
        else:
            counts["pending"] += 1
            counts["queued"] += 1
        if task.get("auto_requeue_at"):
            counts["auto_requeue_pending"] += 1
        counts["retry_attempts_total"] += int(task.get("retry_count") or 0)
        auto_requeue_count = int(task.get("auto_requeue_count") or 0)
        counts["auto_requeue_attempts_total"] += auto_requeue_count
        if auto_requeue_count:
            counts["auto_requeued_tasks"] += 1
        counts["attempt_count_total"] += int(task.get("attempt_count_total") or 0)
    return counts


def summarize_batches(batches: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "total_batches": len(batches),
        "active_batches": 0,
        "stale_batches": 0,
        "finished_batches": 0,
        "total_tasks": 0,
        "running_tasks": 0,
        "pending_tasks": 0,
        "successful_tasks": 0,
        "failed_tasks": 0,
        "timeout_tasks": 0,
        "retrying_tasks": 0,
        "retry_pending_tasks": 0,
        "retry_due_tasks": 0,
        "retry_attempts_total": 0,
        "auto_requeue_pending_tasks": 0,
        "auto_requeue_due_tasks": 0,
        "auto_requeued_tasks": 0,
        "auto_requeue_attempts_total": 0,
        "attempt_count_total": 0,
        "overall_progress_percent": 0,
    }
    for batch in batches:
        lifecycle = batch.get("lifecycle")
        if lifecycle == "active":
            summary["active_batches"] += 1
        elif lifecycle == "stale":
            summary["stale_batches"] += 1
        elif lifecycle == "finished":
            summary["finished_batches"] += 1
        if lifecycle != "active":
            continue
        batch_summary = batch.get("summary") or {}
        summary["total_tasks"] += int(batch_summary.get("total_tasks") or 0)
        summary["running_tasks"] += int(batch_summary.get("running") or 0)
        summary["pending_tasks"] += int(batch_summary.get("pending") or 0)
        summary["successful_tasks"] += int(batch_summary.get("success") or 0)
        summary["failed_tasks"] += int(batch_summary.get("failed") or 0)
        summary["timeout_tasks"] += int(batch_summary.get("timeout") or 0)
        summary["retrying_tasks"] += int(batch_summary.get("retrying") or 0)
        summary["retry_pending_tasks"] += int(batch_summary.get("retry_pending") or 0)
        has_retry_due_summary = "retry_due_tasks" in batch_summary
        has_auto_due_summary = "auto_requeue_due_tasks" in batch_summary
        summary["retry_due_tasks"] += int(batch_summary.get("retry_due_tasks") or 0)
        summary["retry_attempts_total"] += int(batch_summary.get("retry_attempts_total") or 0)
        summary["auto_requeue_pending_tasks"] += int(batch_summary.get("auto_requeue_pending") or 0)
        summary["auto_requeue_due_tasks"] += int(batch_summary.get("auto_requeue_due_tasks") or 0)
        summary["auto_requeued_tasks"] += int(batch_summary.get("auto_requeued_tasks") or 0)
        summary["auto_requeue_attempts_total"] += int(batch_summary.get("auto_requeue_attempts_total") or 0)
        summary["attempt_count_total"] += int(batch_summary.get("attempt_count_total") or 0)
        if not (has_retry_due_summary and has_auto_due_summary):
            derived_due = derive_due_retry_counts(batch)
            if not has_retry_due_summary:
                summary["retry_due_tasks"] += derived_due["retry_due_tasks"]
            if not has_auto_due_summary:
                summary["auto_requeue_due_tasks"] += derived_due["auto_requeue_due_tasks"]
    completed = summary["successful_tasks"] + summary["failed_tasks"] + summary["timeout_tasks"]
    if summary["total_tasks"]:
        summary["overall_progress_percent"] = round(completed / summary["total_tasks"] * 100, 2)
    return summary


def derive_due_retry_counts(batch: dict[str, Any]) -> dict[str, int]:
    """Derive due retry/requeue counts from task rows for older state snapshots."""
    now = datetime.now(timezone.utc)
    counts = {"retry_due_tasks": 0, "auto_requeue_due_tasks": 0}
    for task in batch.get("tasks") or []:
        status = str(task.get("status") or "")
        if status == "retry_pending" and is_due(task.get("next_retry_at"), now):
            counts["retry_due_tasks"] += 1
        if status == "pending" and is_due(task.get("auto_requeue_at"), now):
            counts["auto_requeue_due_tasks"] += 1
    return counts


def is_due(value: Any, now: datetime) -> bool:
    dt = parse_datetime(value)
    return bool(dt and dt <= now)


def has_live_running_task(batch: dict[str, Any]) -> bool:
    """Treat a long-running batch as active when its recorded Strix child PID is alive."""
    if psutil is None:
        return False
    for task in batch.get("tasks") or []:
        if task.get("status") != "running":
            continue
        pid = task.get("strix_pid")
        try:
            if pid and psutil.pid_exists(int(pid)):
                return True
        except (TypeError, ValueError):
            continue
    return False


def get_system_resources() -> dict[str, Any]:
    if psutil is None:
        return {
            "available": False,
            "generated_at": now_iso(),
            "warnings": ["psutil is not installed; install psutil>=5.9 for full resource metrics"],
        }

    warnings: list[str] = []
    process = psutil.Process(os.getpid())
    memory = psutil.virtual_memory()
    root_disk = psutil.disk_usage("/")
    project_disk = psutil.disk_usage(str(Path(__file__).resolve().parent))
    try:
        swap = psutil.swap_memory()
        swap_payload = {
            "total": swap.total,
            "used": swap.used,
            "percent": swap.percent,
        }
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"swap metrics unavailable: {exc}")
        swap_payload = {"total": 0, "used": 0, "percent": 0}
    try:
        net = psutil.net_io_counters()
        net_payload = {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        }
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"network metrics unavailable: {exc}")
        net_payload = {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0}
    try:
        boot_timestamp = psutil.boot_time()
        boot_time = datetime.fromtimestamp(boot_timestamp, tz=timezone.utc)
        uptime_seconds = round(time.time() - boot_timestamp, 3)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"uptime metrics unavailable: {exc}")
        boot_time = None
        uptime_seconds = None
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else None
    smart_batch = read_smart_batch_status(limit=50, include_finished=False, include_tasks=False)
    pids = collect_smart_batch_pids(smart_batch.get("batches", []))

    with process.oneshot():
        proc_mem = process.memory_info()
        proc_cpu = process.cpu_percent(interval=None)

    return {
        "available": True,
        "generated_at": now_iso(),
        "cpu": {
            "percent": psutil.cpu_percent(interval=None),
            "count_logical": psutil.cpu_count(logical=True),
            "count_physical": psutil.cpu_count(logical=False),
            "load_avg": load_avg,
        },
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
        },
        "swap": swap_payload,
        "disk": {
            "root": disk_payload(root_disk),
            "project": disk_payload(project_disk),
        },
        "network": net_payload,
        "uptime": {
            "boot_time": boot_time.isoformat() if boot_time else None,
            "seconds": uptime_seconds,
        },
        "process": {
            "pid": process.pid,
            "rss": proc_mem.rss,
            "vms": proc_mem.vms,
            "cpu_percent": proc_cpu,
            "threads": process.num_threads(),
        },
        "smart_batch_processes": pids,
        "warnings": warnings,
    }


def collect_smart_batch_pids(batches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[int] = set()
    processes: list[dict[str, Any]] = []
    for batch in batches:
        for task in batch.get("tasks") or []:
            pid = task.get("strix_pid")
            if not pid:
                continue
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                continue
            if pid_int in seen:
                continue
            seen.add(pid_int)
            exists = psutil.pid_exists(pid_int) if psutil else False
            info = {
                "pid": pid_int,
                "exists": exists,
                "batch_id": batch.get("batch_id"),
                "scan_id": task.get("scan_id"),
                "target": task.get("target"),
            }
            if exists and psutil is not None:
                try:
                    proc = psutil.Process(pid_int)
                    with proc.oneshot():
                        info.update(
                            {
                                "status": proc.status(),
                                "cpu_percent": proc.cpu_percent(interval=None),
                                "rss": proc.memory_info().rss,
                            }
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    info["exists"] = False
            processes.append(info)
    return processes


def disk_payload(usage: Any) -> dict[str, Any]:
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": usage.percent,
    }


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
