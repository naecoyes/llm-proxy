"""Read-only index of targets recorded by Smart Batch history files."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


_LOCK = threading.Lock()
_CACHE: dict[str, object] = {"expires_at": 0.0, "items": []}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _history_files() -> list[Path]:
    configured = os.environ.get("NSCAN_SCANNED_HISTORY_PATHS", "")
    if configured:
        candidates = [Path(value) for value in configured.split(os.pathsep) if value]
    else:
        root = _project_root()
        candidates = [root / "scanned_domains.txt"]
        candidates.extend(root.glob("*_scanned_history.txt"))
        candidates.extend((root / "reports").glob("*scanned_history*.txt"))
        candidates.extend((root / "reports").glob("combined_scanned_history_*.txt"))
        old_root = Path("/home/osboxes/strix-0.8.3")
        if old_root.is_dir():
            candidates.extend(old_root.glob("*_scanned_history.txt"))
    return sorted({path.resolve() for path in candidates if path.is_file()})


def _normalize_target(value: str) -> str:
    value = value.strip().split("\t", 1)[0].strip()
    if not value or value.startswith("#"):
        return ""
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower().rstrip(".")


def _build_index() -> list[dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for path in _history_files():
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        source = path.name
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            target = _normalize_target(line)
            if not target:
                continue
            record = records.setdefault(
                target,
                {"target": target, "sources": [], "last_seen": modified},
            )
            if source not in record["sources"]:
                record["sources"].append(source)
            if modified > str(record["last_seen"]):
                record["last_seen"] = modified
    return sorted(records.values(), key=lambda item: str(item["target"]))


def get_scanned_targets(
    *, query: str = "", source: str = "", page: int = 1, page_size: int = 50
) -> dict[str, object]:
    now = time.monotonic()
    with _LOCK:
        if now >= float(_CACHE["expires_at"]):
            _CACHE["items"] = _build_index()
            _CACHE["expires_at"] = now + 60.0
        items = list(_CACHE["items"])

    query_lower = query.strip().lower()
    source_lower = source.strip().lower()
    if query_lower:
        items = [item for item in items if query_lower in str(item["target"]).lower()]
    if source_lower:
        items = [
            item
            for item in items
            if any(source_lower in str(value).lower() for value in item["sources"])
        ]

    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    start = (page - 1) * page_size
    sources = sorted({value for item in items for value in item["sources"]})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "page": page,
        "page_size": page_size,
        "pages": max(1, (len(items) + page_size - 1) // page_size),
        "sources": sources,
        "items": items[start : start + page_size],
    }


def invalidate_scanned_target_cache() -> None:
    with _LOCK:
        _CACHE["expires_at"] = 0.0
