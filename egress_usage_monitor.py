"""Read-only egress usage and scan container attribution helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from smart_batch_monitor import read_smart_batch_status
from strix_runtime_monitor import DEFAULT_BRIDGE_INTERFACE, DEFAULT_DOCKER_NETWORK, get_strix_runtime_status


COMMAND_TIMEOUT_SECONDS = 8
MONITOR_CACHE_TTL_SECONDS = 3.0
TIMESTAMP_MAPPING_WINDOW_SECONDS = 15 * 60
HIGH_CONFIDENCE_WINDOW_SECONDS = 2 * 60
NSCAN_LABEL_PREFIX = "nscan."

_BRIDGE_SAMPLE: dict[str, dict[str, Any]] = {}
_CONTAINER_SAMPLE: dict[str, dict[str, Any]] = {}
_MONITOR_CACHE: dict[str, Any] = {"expires_at": 0.0, "snapshot": None}
_MONITOR_CACHE_LOCK = threading.Lock()


def get_monitor_snapshot(*, force: bool = False) -> dict[str, Any]:
    """Return one shared Docker/egress sample, cached briefly for dashboard polling."""
    now = time.monotonic()
    with _MONITOR_CACHE_LOCK:
        cached = _MONITOR_CACHE.get("snapshot")
        if not force and cached is not None and now < float(_MONITOR_CACHE.get("expires_at") or 0):
            return cached

        runtime = get_strix_runtime_status(check_nodes=False)
        batch_status = read_smart_batch_status(limit=50, include_finished=True)
        docker_network = runtime.get("docker", {}).get("network") or os.environ.get(
            "STRIX_DOCKER_NETWORK", DEFAULT_DOCKER_NETWORK
        )
        containers = _collect_scan_containers(
            batch_status=batch_status,
            docker_network=docker_network,
        )
        egress_usage = _build_egress_usage(runtime, containers)
        snapshot = {
            "generated_at": now_iso(),
            "cache_ttl_seconds": MONITOR_CACHE_TTL_SECONDS,
            "runtime": runtime,
            "batch_status": batch_status,
            "containers": containers,
            "egress_usage": egress_usage,
        }
        _MONITOR_CACHE["snapshot"] = snapshot
        _MONITOR_CACHE["expires_at"] = time.monotonic() + MONITOR_CACHE_TTL_SECONDS
        return snapshot


def get_egress_usage(*, force: bool = False) -> dict[str, Any]:
    """Return cached bridge, proxy pool, and attributed scan container usage."""
    return get_monitor_snapshot(force=force)["egress_usage"]


def get_scan_containers(*, force: bool = False) -> dict[str, Any]:
    """Return cached Docker scan container telemetry."""
    return get_monitor_snapshot(force=force)["containers"]


def cleanup_orphan_scan_containers(*, dry_run: bool = False) -> dict[str, Any]:
    """Stop/remove containers that are confidently orphaned from Smart Batch."""
    snapshot = get_monitor_snapshot(force=True)
    containers = snapshot.get("containers", {}).get("strix_containers", [])
    orphaned = [
        item
        for item in containers
        if item.get("orphan_container") and str(item.get("state") or "").lower() == "running"
    ]
    actions: list[dict[str, Any]] = []
    for item in orphaned:
        container_id = str(item.get("id") or item.get("full_id") or "")
        if not container_id:
            continue
        action = {
            "id": container_id[:12],
            "name": item.get("name"),
            "target": item.get("target"),
            "dry_run": dry_run,
            "stopped": False,
            "removed": False,
            "error": "",
        }
        if not dry_run:
            stop_result = run_command(["docker", "stop", container_id], timeout=15)
            action["stopped"] = stop_result["returncode"] == 0
            if stop_result["returncode"] != 0:
                action["error"] = trim_output(stop_result["stderr"] or stop_result["stdout"])
            rm_result = run_command(["docker", "rm", container_id], timeout=15)
            action["removed"] = rm_result["returncode"] == 0
            if rm_result["returncode"] != 0 and not action["error"]:
                action["error"] = trim_output(rm_result["stderr"] or rm_result["stdout"])
        actions.append(action)
    if not dry_run and actions:
        get_monitor_snapshot(force=True)
    return {
        "generated_at": now_iso(),
        "dry_run": dry_run,
        "orphan_count": len(orphaned),
        "actions": actions,
    }


def _build_egress_usage(
    runtime: dict[str, Any],
    containers_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build egress usage from an already collected runtime/container sample."""
    generated_at = now_iso()
    warnings: list[str] = []
    bridge_name = (
        runtime.get("docker", {}).get("bridge_name")
        or os.environ.get("STRIX_EGRESS_BRIDGE")
        or DEFAULT_BRIDGE_INTERFACE
    )
    warnings.extend(containers_payload.get("warnings") or [])
    bridge_payload = sample_bridge_counters(bridge_name)
    if bridge_payload.get("warning"):
        warnings.append(bridge_payload["warning"])

    egress = runtime.get("egress", {})
    outbounds = egress.get("outbounds", {})
    return {
        "available": bool(bridge_payload.get("available") or containers_payload.get("available")),
        "generated_at": generated_at,
        "bridge": bridge_payload,
        "docker_network": runtime.get("docker", {}),
        "proxy_pool": {
            "selector": outbounds.get("auto_selector") or "",
            "active_tags": outbounds.get("auto_pool") or [],
            "active_display": outbounds.get("auto_pool_display") or [],
            "active_count": len(outbounds.get("auto_pool") or []),
            "total_nodes": len(outbounds.get("socks_nodes") or []),
            "nodes": outbounds.get("socks_nodes") or [],
            "per_node_traffic": {
                "available": False,
                "reason": "sing-box traffic API is not enabled; bridge/container counters are used instead",
            },
        },
        "containers": containers_payload.get("strix_containers", []),
        "summary": {
            **(containers_payload.get("summary") or {}),
            "bridge_rx_bps": bridge_payload.get("rx_bps", 0),
            "bridge_tx_bps": bridge_payload.get("tx_bps", 0),
            "bridge_rx_bytes": bridge_payload.get("rx_bytes", 0),
            "bridge_tx_bytes": bridge_payload.get("tx_bytes", 0),
        },
        "warnings": warnings + runtime.get("warnings", []),
    }


def _collect_scan_containers(
    *,
    batch_status: dict[str, Any] | None = None,
    docker_network: str | None = None,
) -> dict[str, Any]:
    """Return Docker scan containers enriched with Smart Batch attribution."""
    if not shutil.which("docker"):
        return {"available": False, "strix_containers": [], "error": "docker not found", "warnings": ["docker not found"]}
    docker_network = docker_network or os.environ.get("STRIX_DOCKER_NETWORK", DEFAULT_DOCKER_NETWORK)
    batch_status = batch_status or read_smart_batch_status(limit=50, include_finished=True)
    warnings: list[str] = []
    listed = docker_list_containers()
    if not listed["ok"]:
        return {
            "available": False,
            "strix_containers": [],
            "error": listed["error"],
            "warnings": [listed["error"]],
        }
    all_containers = listed["containers"]
    strix = [
        container
        for container in all_containers
        if "strix-scan" in str(container.get("name") or "")
        or "strix-sandbox" in str(container.get("image") or "")
    ]
    other = [container for container in all_containers if container not in strix]
    inspect_by_id = docker_inspect([str(item.get("id") or "") for item in strix])
    running_ids = [
        str(item.get("id") or "")
        for item in strix
        if str(item.get("state") or "").lower() == "running"
    ]
    stats_by_id = docker_stats(running_ids)
    task_index = build_task_index(batch_status)
    timestamp_assignments = assign_by_timestamp(strix, inspect_by_id, task_index)
    enriched: list[dict[str, Any]] = []

    for container in strix:
        container_id = str(container.get("id") or "")
        inspect = inspect_by_id.get(container_id) or inspect_by_id.get(container_id[:12]) or {}
        container_name = str(inspect.get("Name") or container.get("name") or "").lstrip("/")
        stats = stats_by_id.get(container_id) or stats_by_id.get(container_id[:12]) or stats_by_id.get(container_name) or {}
        entry = enrich_container(
            container,
            inspect,
            stats,
            task_index,
            timestamp_assignments.get(container_id) or timestamp_assignments.get(container_id[:12]),
            docker_network,
        )
        enriched.append(entry)

    running_count = sum(1 for item in strix if str(item.get("state") or "").lower() == "running")
    orphan_count = sum(1 for item in enriched if item.get("orphan_container"))
    return {
        "available": True,
        "generated_at": now_iso(),
        "summary": {
            "strix_total": len(strix),
            "strix_running": running_count,
            "strix_exited": len(strix) - running_count,
            "orphan_containers": orphan_count,
            "other_total": len(other),
        },
        "strix_containers": enriched,
        "other_containers": other[:8],
        "warnings": warnings,
    }


def sample_bridge_counters(interface_name: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / interface_name / "statistics"
    now = time.time()
    if not base.exists():
        return {
            "available": False,
            "interface": interface_name,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_bps": 0,
            "tx_bps": 0,
            "warning": f"interface statistics not found: {interface_name}",
        }
    try:
        counters = {
            "rx_bytes": read_counter(base / "rx_bytes"),
            "tx_bytes": read_counter(base / "tx_bytes"),
            "rx_packets": read_counter(base / "rx_packets"),
            "tx_packets": read_counter(base / "tx_packets"),
        }
    except OSError as exc:
        return {
            "available": False,
            "interface": interface_name,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_bps": 0,
            "tx_bps": 0,
            "warning": f"cannot read interface statistics for {interface_name}: {exc}",
        }
    previous = _BRIDGE_SAMPLE.get(interface_name)
    rx_bps = tx_bps = 0.0
    if previous:
        elapsed = max(0.001, now - float(previous.get("timestamp") or now))
        rx_bps = max(0.0, (counters["rx_bytes"] - int(previous.get("rx_bytes") or 0)) / elapsed)
        tx_bps = max(0.0, (counters["tx_bytes"] - int(previous.get("tx_bytes") or 0)) / elapsed)
    _BRIDGE_SAMPLE[interface_name] = {**counters, "timestamp": now}
    return {
        "available": True,
        "interface": interface_name,
        **counters,
        "rx_bps": round(rx_bps, 1),
        "tx_bps": round(tx_bps, 1),
        "sampled_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "sample_age_seconds": 0,
        "sample_state": "sampled" if previous else "warming",
        "stale": False,
    }


def read_counter(path: Path) -> int:
    return int(path.read_text(encoding="utf-8").strip() or "0")


def docker_list_containers() -> dict[str, Any]:
    fmt = '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","state":"{{.State}}","created":"{{.CreatedAt}}"}'
    result = run_command(["docker", "ps", "-a", "--format", fmt], timeout=COMMAND_TIMEOUT_SECONDS)
    if result["returncode"] != 0:
        return {"ok": False, "containers": [], "error": trim_output(result["stderr"] or result["stdout"])}
    containers: list[dict[str, Any]] = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"ok": True, "containers": containers, "error": ""}


def docker_inspect(container_ids: list[str]) -> dict[str, dict[str, Any]]:
    ids = [item for item in container_ids if item]
    if not ids:
        return {}
    result = run_command(["docker", "inspect", *ids], timeout=COMMAND_TIMEOUT_SECONDS)
    if result["returncode"] != 0:
        return {}
    try:
        inspected = json.loads(result["stdout"] or "[]")
    except json.JSONDecodeError:
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for item in inspected:
        full_id = str(item.get("Id") or "")
        if not full_id:
            continue
        by_id[full_id] = item
        by_id[full_id[:12]] = item
    return by_id


def docker_stats(container_ids: list[str]) -> dict[str, dict[str, Any]]:
    ids = [item for item in container_ids if item]
    if not ids:
        return {}
    fmt = "{{json .}}"
    result = run_command(["docker", "stats", "--no-stream", "--format", fmt, *ids], timeout=COMMAND_TIMEOUT_SECONDS)
    if result["returncode"] != 0:
        return {}
    stats: dict[str, dict[str, Any]] = {}
    for line in result["stdout"].splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = str(payload.get("ID") or payload.get("Container") or "")
        if key:
            stats[key] = payload
        name = str(payload.get("Name") or "")
        if name:
            stats[name] = payload
    return stats


def enrich_container(
    container: dict[str, Any],
    inspect: dict[str, Any],
    stats: dict[str, Any],
    task_index: dict[str, Any],
    timestamp_task: dict[str, Any] | None,
    docker_network: str,
) -> dict[str, Any]:
    container_id = str(container.get("id") or inspect.get("Id") or "")
    full_id = str(inspect.get("Id") or container_id)
    labels = inspect.get("Config", {}).get("Labels") or {}
    env = parse_env(inspect.get("Config", {}).get("Env") or [])
    networks = inspect.get("NetworkSettings", {}).get("Networks") or {}
    network_name = str(inspect.get("HostConfig", {}).get("NetworkMode") or container.get("network_mode") or "")
    selected_network = networks.get(docker_network) or networks.get(network_name) or next(iter(networks.values()), {})
    task, source, confidence = resolve_task(labels, env, task_index, timestamp_task, full_id, container_id)
    net_totals = parse_container_net_totals(stats)
    rates = sample_container_rate(full_id or container_id, net_totals)
    target = labels.get("nscan.target") or env.get("STRIX_BATCH_TARGET") or task.get("target") or ""
    scan_id = labels.get("nscan.scan_id") or env.get("STRIX_BATCH_SCAN_ID") or task.get("scan_id") or ""
    scanner_pid = task.get("strix_pid") or ""
    scanner_pid_exists = process_exists(scanner_pid)
    task_status = task.get("status") or ""
    container_state = str(container.get("state") or inspect.get("State", {}).get("Status") or "").lower()
    orphan_reason = ""
    if container_state == "running" and scan_id and task_status not in {"running", "retrying"}:
        orphan_reason = f"task_status_{task_status or 'unknown'}"
    if container_state == "running" and scanner_pid and not scanner_pid_exists:
        orphan_reason = "scanner_pid_missing"
    orphan_container = bool(orphan_reason)
    return {
        **container,
        "id": container_id or full_id[:12],
        "full_id": full_id,
        "name": str(inspect.get("Name") or container.get("name") or "").lstrip("/"),
        "network_mode": network_name,
        "network": network_name,
        "pid": inspect.get("State", {}).get("Pid") or "",
        "started_at": inspect.get("State", {}).get("StartedAt") or container.get("created"),
        "container_ip": selected_network.get("IPAddress") or "",
        "target": target,
        "scan_id": scan_id,
        "batch_id": labels.get("nscan.batch_id") or task.get("batch_id") or "",
        "scan_mode": labels.get("nscan.scan_mode") or task.get("scan_mode") or "",
        "task_status": task_status,
        "scanner_pid": scanner_pid,
        "scanner_pid_exists": scanner_pid_exists,
        "orphan_container": orphan_container,
        "orphan_reason": orphan_reason,
        "proxy_model_alias": labels.get("nscan.proxy_slot") or task.get("proxy_model_alias") or "",
        "target_ips": task.get("target_ips") or resolve_host_ips(target),
        "target_ips_source": task.get("target_ips_source") or ("current_dns" if target else ""),
        "net_rx_bytes": net_totals["rx_bytes"],
        "net_tx_bytes": net_totals["tx_bytes"],
        "net_rx_bps": rates["rx_bps"],
        "net_tx_bps": rates["tx_bps"],
        "mapping_source": source,
        "mapping_confidence": confidence,
    }


def process_exists(pid: Any) -> bool | None:
    try:
        numeric = int(pid)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return False
    return Path(f"/proc/{numeric}").exists()


def build_task_index(batch_status: dict[str, Any]) -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    by_scan_id: dict[str, dict[str, Any]] = {}
    by_container_id: dict[str, dict[str, Any]] = {}
    for batch in batch_status.get("batches") or []:
        for task in batch.get("tasks") or []:
            enriched = {**task, "batch_id": batch.get("batch_id")}
            tasks.append(enriched)
            if enriched.get("scan_id"):
                by_scan_id[str(enriched["scan_id"])] = enriched
            if enriched.get("container_id"):
                cid = str(enriched["container_id"])
                by_container_id[cid] = enriched
                by_container_id[cid[:12]] = enriched
    return {"tasks": tasks, "by_scan_id": by_scan_id, "by_container_id": by_container_id}


def assign_by_timestamp(
    containers: list[dict[str, Any]],
    inspect_by_id: dict[str, dict[str, Any]],
    task_index: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    running_tasks = [
        task
        for task in task_index.get("tasks", [])
        if task.get("status") in {"running", "retrying"} and parse_time(task.get("started_at"))
    ]
    candidates: list[tuple[float, str, str, dict[str, Any]]] = []
    for container in containers:
        container_id = str(container.get("id") or "")
        inspect = inspect_by_id.get(container_id) or {}
        started = parse_time(inspect.get("State", {}).get("StartedAt") or container.get("created"))
        if not started:
            continue
        for task in running_tasks:
            task_started = parse_time(task.get("started_at"))
            if not task_started:
                continue
            diff = abs(started - task_started)
            if diff <= TIMESTAMP_MAPPING_WINDOW_SECONDS:
                candidates.append((diff, container_id, str(task.get("scan_id") or ""), task))
    assignments: dict[str, dict[str, Any]] = {}
    used_tasks: set[str] = set()
    for diff, container_id, scan_id, task in sorted(candidates, key=lambda item: item[0]):
        if container_id in assignments or scan_id in used_tasks:
            continue
        task = dict(task)
        task["_timestamp_diff_seconds"] = round(diff, 3)
        assignments[container_id] = task
        used_tasks.add(scan_id)
    return assignments


def resolve_task(
    labels: dict[str, Any],
    env: dict[str, str],
    task_index: dict[str, Any],
    timestamp_task: dict[str, Any] | None,
    full_id: str,
    short_id: str,
) -> tuple[dict[str, Any], str, str]:
    scan_id = labels.get("nscan.scan_id") or env.get("STRIX_BATCH_SCAN_ID")
    if scan_id and scan_id in task_index.get("by_scan_id", {}):
        return task_index["by_scan_id"][scan_id], "docker_label" if labels.get("nscan.scan_id") else "container_env", "high"
    for key in (full_id, short_id, full_id[:12]):
        if key and key in task_index.get("by_container_id", {}):
            return task_index["by_container_id"][key], "smart_batch_container_id", "high"
    if timestamp_task:
        diff = float(timestamp_task.get("_timestamp_diff_seconds") or 0)
        return timestamp_task, "timestamp", "high" if diff <= HIGH_CONFIDENCE_WINDOW_SECONDS else "medium"
    if labels.get("nscan.target") or env.get("STRIX_BATCH_TARGET"):
        return {}, "docker_label" if labels.get("nscan.target") else "container_env", "medium"
    return {}, "unmapped", "low"


def parse_env(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, item = str(value).partition("=")
        if separator:
            result[key] = item
    return result


def parse_container_net_totals(stats: dict[str, Any]) -> dict[str, int]:
    net_io = str(stats.get("NetIO") or stats.get("Net I/O") or "")
    left, separator, right = net_io.partition("/")
    if not separator:
        return {"rx_bytes": 0, "tx_bytes": 0}
    return {"rx_bytes": parse_byte_size(left), "tx_bytes": parse_byte_size(right)}


def sample_container_rate(container_id: str, totals: dict[str, int]) -> dict[str, float]:
    now = time.time()
    previous = _CONTAINER_SAMPLE.get(container_id)
    rx_bps = tx_bps = 0.0
    if previous:
        elapsed = max(0.001, now - float(previous.get("timestamp") or now))
        rx_bps = max(0.0, (totals["rx_bytes"] - int(previous.get("rx_bytes") or 0)) / elapsed)
        tx_bps = max(0.0, (totals["tx_bytes"] - int(previous.get("tx_bytes") or 0)) / elapsed)
    _CONTAINER_SAMPLE[container_id] = {**totals, "timestamp": now}
    return {"rx_bps": round(rx_bps, 1), "tx_bps": round(tx_bps, 1)}


def parse_byte_size(value: str) -> int:
    text = str(value or "").strip().replace(" ", "")
    match = re.match(r"^([0-9]*\.?[0-9]+)([kmgtp]?i?b?)?$", text, re.IGNORECASE)
    if not match:
        return 0
    number = float(match.group(1))
    unit = (match.group(2) or "b").lower()
    multipliers = {
        "b": 1,
        "kb": 1000,
        "kib": 1024,
        "mb": 1000**2,
        "mib": 1024**2,
        "gb": 1000**3,
        "gib": 1024**3,
        "tb": 1000**4,
        "tib": 1024**4,
        "pb": 1000**5,
        "pib": 1024**5,
    }
    return int(number * multipliers.get(unit, 1))


def resolve_host_ips(host: str, limit: int = 6) -> list[str]:
    if not host:
        return []
    hostname = str(host).split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips: list[str] = []
    for result in results:
        address = result[4][0]
        if address not in ips:
            ips.append(address)
        if len(ips) >= limit:
            break
    return ips


def parse_time(value: Any) -> float | None:
    if not value:
        return None
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def run_command(args: list[str], timeout: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 124, "stdout": "", "stderr": str(exc)}
    return {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}


def trim_output(value: str, limit: int = 240) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
