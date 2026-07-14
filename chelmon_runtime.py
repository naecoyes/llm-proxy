"""Read-only health checks for the Nscan-managed Chelmon container runtime."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import json
from typing import Any
from urllib.request import urlopen

DEFAULT_IMAGE = "nscan/chelmon-engine:1.0.0"
DEFAULT_NETWORK = "strix-egress"
HEALTH_CACHE_SECONDS = 30
DEFAULT_MODEL_STATUS_URL = "http://127.0.0.1:8888/v1/models/available?scan_mode=redteam"

_cached_at = 0.0
_cached_status: dict[str, Any] | None = None


def _run(command: list[str], timeout: int = 8) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return completed.returncode == 0, (completed.stdout or "").strip()[-500:]


def _has_eligible_model() -> tuple[bool, str]:
    endpoint = os.environ.get("NSCAN_CHELMON_MODEL_STATUS_URL", DEFAULT_MODEL_STATUS_URL)
    try:
        with urlopen(endpoint, timeout=5) as response:  # noqa: S310 - local Nscan control plane only
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - health checks must fail closed
        return False, str(exc)
    eligible = [item for item in payload.get("models", []) if item.get("eligible_for_auto")]
    return bool(eligible), None if eligible else "no eligible redteam model"


def get_chelmon_runtime_status(force: bool = False) -> dict[str, Any]:
    """Return cached runtime readiness without exposing model credentials."""
    global _cached_at, _cached_status
    now = time.monotonic()
    if not force and _cached_status is not None and now - _cached_at < HEALTH_CACHE_SECONDS:
        return dict(_cached_status)

    docker = shutil.which("docker")
    image = os.environ.get("NSCAN_CHELMON_ENGINE_IMAGE", DEFAULT_IMAGE)
    network = os.environ.get("STRIX_BATCH_DOCKER_NETWORK") or os.environ.get("STRIX_DOCKER_NETWORK") or DEFAULT_NETWORK
    checks: dict[str, dict[str, Any]] = {}
    if not docker:
        checks["docker"] = {"ok": False, "detail": "docker executable not found"}
        status = {"ready": False, "image": image, "network": network, "checks": checks}
        _cached_at, _cached_status = now, status
        return dict(status)

    # Keep status details compact: inspect output can contain the whole image
    # config and would otherwise make the dashboard response unnecessarily large.
    for key, command in {
        "image": [docker, "image", "inspect", "--format", "{{.Id}}", image],
        "network": [docker, "network", "inspect", "--format", "{{.Name}}", network],
        "proxy": [docker, "run", "--rm", "--pull", "never", "--network", network, image, "--healthcheck"],
    }.items():
        ok, detail = _run(command)
        checks[key] = {"ok": ok, "detail": detail or None}
        if not ok:
            break

    if all(item.get("ok") for item in checks.values()):
        ok, detail = _has_eligible_model()
        checks["model"] = {"ok": ok, "detail": detail}

    status = {
        "ready": all(item.get("ok") for item in checks.values()) and len(checks) == 4,
        "image": image,
        "network": network,
        "checks": checks,
    }
    _cached_at, _cached_status = now, status
    return dict(status)
