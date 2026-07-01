"""Findings data adapter for the Nscan dashboard.

Reports remain in their original Strix run directories. The adapter builds a
cached index and owns its local review state file directly so the dashboard can
continue to work without the legacy viewer service.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
VALID_SEVERITIES = set(SEVERITY_ORDER)
STATE_BUCKETS = ("tags", "unread", "marks", "stars", "starred_at", "archived", "verified")
DEFAULT_CONFIG = Path(__file__).with_name("vulnerability_sources.yaml")


@dataclass(frozen=True)
class FileRef:
    root_id: str
    relative_path: str


@dataclass
class FindingsSnapshot:
    records: list[dict[str, Any]]
    by_id: dict[str, dict[str, Any]]
    targets: list[dict[str, Any]]
    reports: list[dict[str, Any]]
    generated_at: str
    duration_ms: int


def _severity(value: Any) -> str:
    value = str(value or "").strip().upper()
    return value if value in VALID_SEVERITIES else "UNKNOWN"


def _state_key(record: dict[str, Any]) -> str:
    return f"{record.get('target', '')}:{record.get('id', '')}:{record.get('title', '')}"


def _record_id(record: dict[str, Any]) -> str:
    ref = record.get("_file_ref")
    ref_text = f"{ref.root_id}:{ref.relative_path}" if isinstance(ref, FileRef) else ""
    return hashlib.sha256(f"{_state_key(record)}|{ref_text}".encode("utf-8", errors="replace")).hexdigest()[:24]


def _markdown_metadata(path: Path) -> tuple[str, str, str, str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read(32768).splitlines()[:15]
    title, severity, cvss, found = path.stem, "UNKNOWN", "", ""
    for line in lines:
        line = line.strip()
        if line.startswith("# ") and title == path.stem:
            title = line[2:].strip() or title
        elif "Severity" in line and ":" in line:
            severity = _severity(line.split(":")[-1].replace("*", "").strip())
        elif "CVSS" in line and ":" in line:
            cvss = line.split(":")[-1].replace("*", "").strip()
        elif "Found" in line and ":" in line:
            found = line.split(":", 1)[-1].replace("*", "").strip()
    return title, severity, cvss, found


def _timestamp_sort_value(value: Any) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    if " " in text and "T" not in text:
        candidates.append(text.replace(" ", "T", 1))
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


class FindingsService:
    def __init__(self, config_path: str | Path = DEFAULT_CONFIG):
        self.config_path = Path(config_path)
        self.config = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.catalog_dir = Path(self.config["catalog_dir"]).expanduser()
        self.state_file = Path(self.config.get("state_file", self.catalog_dir / ".vuln_viewer_tags.json"))
        self.legacy_api_base = str(self.config.get("legacy_api_base", "http://127.0.0.1:8080")).rstrip("/")
        self.refresh_seconds = max(300, int(self.config.get("refresh_seconds", 300)))
        self.max_report_bytes = max(65536, int(self.config.get("max_report_bytes", 5 * 1024 * 1024)))
        self.roots: dict[str, Path] = {"catalog": self.catalog_dir}
        self.root_sources: dict[str, str] = {"catalog": "catalog"}
        for item in self.config.get("run_roots", []):
            root_id = str(item.get("id") or "").strip()
            if root_id:
                self.roots[root_id] = Path(item.get("path", "")).expanduser()
                self.root_sources[root_id] = str(item.get("source") or root_id)
        self._snapshot: FindingsSnapshot | None = None
        self._refresh_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_error: str | None = None
        self._state_available: bool | None = True
        self._last_signature: str | None = None
        self._state_cache: dict[str, Any] | None = None
        self._state_cache_mtime: int | None = None

    async def start(self) -> None:
        self._stop.clear()
        await self.refresh(force=True)
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def check_state_service(self) -> bool:
        self._state_available = True
        return True

    async def stop(self) -> None:
        self._stop.set()
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

    async def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.refresh_seconds)
            except asyncio.TimeoutError:
                await self.refresh()

    async def refresh(self, force: bool = False) -> FindingsSnapshot:
        async with self._refresh_lock:
            try:
                signature = await asyncio.to_thread(self._source_signature)
                if not force and self._snapshot is not None and signature == self._last_signature:
                    return self._snapshot
                snapshot = await asyncio.to_thread(self._build_snapshot)
                self._last_signature = signature
                self._snapshot, self._last_error = snapshot, None
            except Exception as exc:
                self._last_error = str(exc)
                if self._snapshot is None:
                    raise
            return self._snapshot

    async def snapshot(self) -> FindingsSnapshot:
        return self._snapshot or await self.refresh()

    def _file_sig(self, path: Path) -> tuple[str, int, int] | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        return (str(path), int(stat.st_mtime_ns), int(stat.st_size))

    def _source_signature(self) -> str:
        parts: list[Any] = []
        parts.append(self._file_sig(self.config_path))
        for filename in self.config.get("csv_files", []):
            parts.append(self._file_sig(self.catalog_dir / filename))
        for filename in self.config.get("report_files", []):
            parts.append(self._file_sig(self.catalog_dir / filename))
        for root_id, root in sorted(self.roots.items()):
            if root_id == "catalog" or not root.is_dir():
                parts.append((root_id, str(root), "missing"))
                continue
            count = 0
            max_mtime = 0
            try:
                for vuln_dir in root.glob("*/vulnerabilities"):
                    if not vuln_dir.is_dir():
                        continue
                    dir_stat = vuln_dir.stat()
                    max_mtime = max(max_mtime, int(dir_stat.st_mtime_ns))
                    for path in vuln_dir.glob("*.md"):
                        try:
                            stat = path.stat()
                        except OSError:
                            continue
                        count += 1
                        max_mtime = max(max_mtime, int(stat.st_mtime_ns))
            except OSError:
                parts.append((root_id, str(root), "error"))
                continue
            parts.append((root_id, str(root), count, max_mtime))
        return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()

    def _safe_ref(self, root_id: str, path: Path, suffixes: set[str] = {".md", ".txt"}) -> FileRef | None:
        root = self.roots.get(root_id)
        if root is None:
            return None
        try:
            root_resolved = root.resolve(strict=True)
            path_resolved = path.resolve(strict=True)
            relative = path_resolved.relative_to(root_resolved)
        except (FileNotFoundError, RuntimeError, ValueError):
            return None
        if not path_resolved.is_file() or path_resolved.suffix.lower() not in suffixes:
            return None
        return FileRef(root_id, relative.as_posix())

    def _resolve_ref(self, ref: FileRef) -> Path:
        root = self.roots.get(ref.root_id)
        if root is None:
            raise FileNotFoundError(ref.root_id)
        root_resolved = root.resolve(strict=True)
        path = (root_resolved / ref.relative_path).resolve(strict=True)
        try:
            path.relative_to(root_resolved)
        except ValueError as exc:
            raise FileNotFoundError("Report path escapes configured root") from exc
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
            raise FileNotFoundError(path)
        if path.stat().st_size > self.max_report_bytes:
            raise ValueError("Report exceeds configured size limit")
        return path

    def _run_records(self) -> list[dict[str, Any]]:
        records = []
        for root_id, root in self.roots.items():
            if root_id == "catalog" or not root.is_dir():
                continue
            for run_dir in sorted(root.iterdir()):
                vuln_dir = run_dir / "vulnerabilities"
                if not run_dir.is_dir() or not vuln_dir.is_dir():
                    continue
                for path in sorted(vuln_dir.glob("*.md")):
                    ref = self._safe_ref(root_id, path)
                    if ref is None:
                        continue
                    try:
                        title, severity, cvss, found = _markdown_metadata(path)
                    except OSError:
                        continue
                    records.append({
                        "target": run_dir.name,
                        "id": path.stem,
                        "title": title,
                        "severity": severity,
                        "cvss": cvss,
                        "timestamp": found,
                        "source_file": self.root_sources.get(root_id, root_id),
                        "is_high_value": False,
                        "_file_ref": ref,
                    })
        return records

    def _high_value_keys(self) -> set[tuple[str, str]]:
        path = self.catalog_dir / "high_value_vulnerabilities_summary.csv"
        if not path.is_file():
            return set()
        keys = set()
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.strip().split(",", 2)
                if len(parts) >= 2:
                    keys.add((parts[0].strip(), parts[1].strip()))
        return keys

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

    def _match_ref(self, file_value: str, target: str, vuln_id: str, run_records: list[dict[str, Any]]) -> FileRef | None:
        if file_value:
            ref = self._safe_ref("catalog", self.catalog_dir / file_value)
            if ref:
                return ref
        candidates = [record for record in run_records if record.get("id") == vuln_id]
        target_slug = self._slug(target)
        for record in candidates:
            run_slug = self._slug(str(record.get("target", "")))
            if target_slug and (run_slug.startswith(target_slug) or target_slug.startswith(run_slug)):
                return record.get("_file_ref")
        return candidates[0].get("_file_ref") if candidates else None

    def _csv_records(self, run_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records, high_value_keys = [], self._high_value_keys()
        for filename in self.config.get("csv_files", []):
            if filename == "high_value_vulnerabilities_summary.csv":
                continue
            path = self.catalog_dir / filename
            if not path.is_file():
                continue
            current_target = ""
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.DictReader(handle):
                    target = str(row.get("target") or "").strip() or current_target
                    current_target = target or current_target
                    vuln_id = str(row.get("id") or "").strip()
                    title = str(row.get("title") or "").strip()
                    if not title or title.lower() == "title":
                        continue
                    records.append({
                        "target": target,
                        "id": vuln_id,
                        "title": title,
                        "severity": _severity(row.get("severity")),
                        "cvss": str(row.get("cvss") or "").strip(),
                        "timestamp": str(row.get("timestamp") or "").strip(),
                        "source_file": filename,
                        "is_high_value": (vuln_id, title) in high_value_keys,
                        "_file_ref": self._match_ref(str(row.get("file") or "").strip(), target, vuln_id, run_records),
                    })
        high_path = self.catalog_dir / "high_value_vulnerabilities_summary.csv"
        if high_path.is_file():
            with high_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.strip().split(",", 4)
                    if len(parts) < 4 or parts[1].strip().lower() == "title":
                        continue
                    vuln_id, title, severity, timestamp = [part.strip() for part in parts[:4]]
                    file_value = parts[4].strip() if len(parts) > 4 else ""
                    records.append({
                        "target": "", "id": vuln_id, "title": title,
                        "severity": _severity(severity), "cvss": "", "timestamp": timestamp,
                        "source_file": "high_value_vulnerabilities_summary.csv", "is_high_value": True,
                        "_file_ref": self._match_ref(file_value, "", vuln_id, run_records),
                    })
        return records

    def _build_snapshot(self) -> FindingsSnapshot:
        started = datetime.now(timezone.utc)
        run_records = self._run_records()
        combined = self._csv_records(run_records) + run_records
        records, seen = [], set()
        for record in combined:
            duplicate_key = (record["target"], record["id"], record["title"])
            if duplicate_key in seen:
                continue
            seen.add(duplicate_key)
            record["record_id"] = _record_id(record)
            record["state_key"] = _state_key(record)
            records.append(record)
        target_map: dict[str, dict[str, Any]] = {}
        for record in records:
            target = record["target"] or "Unknown"
            item = target_map.setdefault(target, {"target": target, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
            item["total"] += 1
            severity = record["severity"].lower()
            if severity in item:
                item[severity] += 1
        reports = []
        for filename in self.config.get("report_files", []):
            ref = self._safe_ref("catalog", self.catalog_dir / filename)
            if ref:
                reports.append({"report_id": hashlib.sha256(filename.encode()).hexdigest()[:20], "name": filename, "_file_ref": ref})
        ended = datetime.now(timezone.utc)
        return FindingsSnapshot(
            records=records,
            by_id={record["record_id"]: record for record in records},
            targets=sorted(target_map.values(), key=lambda item: (-item["critical"], -item["high"], -item["total"], item["target"])),
            reports=reports,
            generated_at=ended.isoformat(),
            duration_ms=int((ended - started).total_seconds() * 1000),
        )

    def load_state(self) -> dict[str, Any]:
        try:
            stat = self.state_file.stat()
            mtime = int(stat.st_mtime_ns)
        except OSError:
            mtime = None
        if self._state_cache is not None and self._state_cache_mtime == mtime:
            return json.loads(json.dumps(self._state_cache))
        try:
            state = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            state = {}
        for bucket in STATE_BUCKETS:
            if not isinstance(state.get(bucket), dict):
                state[bucket] = {}
        self._state_cache = state
        self._state_cache_mtime = mtime
        return json.loads(json.dumps(state))

    def _legacy_starred_at(self) -> str:
        """Return a stable fallback date for confirmations created before timestamps."""
        try:
            return datetime.fromtimestamp(self.state_file.stat().st_mtime, timezone.utc).isoformat()
        except OSError:
            return ""

    def save_state(self, state: dict[str, Any]) -> None:
        for bucket in STATE_BUCKETS:
            if not isinstance(state.get(bucket), dict):
                state[bucket] = {}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.state_file.with_name(f".{self.state_file.name}.tmp")
        temp_path.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp_path, self.state_file)
        self._state_cache = state
        try:
            self._state_cache_mtime = int(self.state_file.stat().st_mtime_ns)
        except OSError:
            self._state_cache_mtime = None
        try:
            from asset_database import get_asset_database

            get_asset_database().sync_finding_review_state(state)
        except Exception:
            # The legacy state file remains authoritative if SQLite is unavailable.
            pass

    @staticmethod
    def _public(record: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        key = record["state_key"]
        result = {name: value for name, value in record.items() if not name.startswith("_")}
        result["has_report"] = isinstance(record.get("_file_ref"), FileRef)
        result["state"] = {
            "unread": state["unread"].get(key, True) is not False,
            "marked": state["marks"].get(key) is True,
            "starred": state["stars"].get(key) is True,
            "starred_at": state["starred_at"].get(key),
            "archived": state["archived"].get(key) is True,
            "verified": state["verified"].get(key),
            "tags": state["tags"].get(key, []),
        }
        return result

    async def summary(self) -> dict[str, Any]:
        snapshot, state = await self.snapshot(), self.load_state()
        counts = {name.lower(): 0 for name in VALID_SEVERITIES}
        unread = archived = verified = false_positive = 0
        sources: dict[str, int] = {}
        tags = set()
        for record in snapshot.records:
            counts[record["severity"].lower()] += 1
            key = record["state_key"]
            unread += int(state["unread"].get(key, True) is not False)
            archived += int(state["archived"].get(key) is True)
            verified += int(state["stars"].get(key) is True)
            false_positive += int(state["verified"].get(key) is False)
            tags.update(state["tags"].get(key, []))
            source = record["source_file"]
            sources[source] = sources.get(source, 0) + 1
        return {
            "total": len(snapshot.records), "critical": counts["critical"], "high": counts["high"],
            "medium": counts["medium"], "low": counts["low"], "info": counts["info"],
            "unread": unread, "archived": archived, "verified": verified,
            "starred": verified, "false_positive": false_positive,
            "targets": len(snapshot.targets), "reports": len(snapshot.reports),
            "sources": sources, "tags": sorted(tags), "generated_at": snapshot.generated_at,
            "index_duration_ms": snapshot.duration_ms, "index_error": self._last_error,
            "state_write_available": self._state_available is not False,
        }

    async def bootstrap(self, page: int, page_size: int, q: str = "", severity: str = "", status: str = "needs-review", sort: str = "legacy", order: str = "asc") -> dict[str, Any]:
        summary_data, records_data = await asyncio.gather(
            self.summary(),
            self.list_records(page, page_size, q, severity, "", "", status, "", sort, order),
        )
        return {"summary": summary_data, "records": records_data}

    async def list_records(self, page: int, page_size: int, q: str = "", severity: str = "", target: str = "", source: str = "", status: str = "", tag: str = "", sort: str = "legacy", order: str = "asc") -> dict[str, Any]:
        snapshot, state = await self.snapshot(), self.load_state()
        records = snapshot.records
        if q:
            needle = q.casefold()
            records = [record for record in records if needle in " ".join(str(record.get(field, "")) for field in ("target", "id", "title", "source_file")).casefold()]
        if severity:
            records = [record for record in records if record["severity"] == severity.upper()]
        if target:
            records = [record for record in records if record["target"] == target]
        if source:
            records = [record for record in records if record["source_file"] == source]
        if tag:
            records = [record for record in records if tag in state["tags"].get(record["state_key"], [])]
        if status:
            def matches(record):
                key = record["state_key"]
                values = {
                    "unread": state["unread"].get(key, True) is not False,
                    "read": state["unread"].get(key, True) is False,
                    "archived": state["archived"].get(key) is True,
                    "unarchived": state["archived"].get(key) is not True,
                    "needs-review": (
                        state["archived"].get(key) is not True
                        and state["stars"].get(key) is not True
                        and state["verified"].get(key) is not False
                    ),
                    "starred": state["stars"].get(key) is True,
                    "marked": state["marks"].get(key) is True,
                    "verified": state["stars"].get(key) is True,
                    "review-verified": state["verified"].get(key) is True,
                    "false-positive": state["verified"].get(key) is False,
                    "unverified": key not in state["verified"],
                }
                return values.get(status, True)
            records = [record for record in records if matches(record)]
        def sort_value(record):
            if sort in {"legacy", "priority"}:
                key = record["state_key"]
                archived = 1 if state["archived"].get(key) is True else 0
                starred = 0 if state["stars"].get(key) is True else 1
                severity_rank = SEVERITY_ORDER.get(record["severity"], 5)
                try:
                    cvss_rank = -(float(record["cvss"] or 0))
                except ValueError:
                    cvss_rank = 0.0
                return (archived, starred, severity_rank, cvss_rank, str(record.get("target", "")).casefold(), str(record.get("title", "")).casefold())
            if sort == "severity":
                return SEVERITY_ORDER.get(record["severity"], 5)
            if sort == "cvss":
                try:
                    return float(record["cvss"] or 0)
                except ValueError:
                    return 0.0
            if sort in {"timestamp", "found", "time"}:
                return _timestamp_sort_value(record.get("timestamp"))
            if sort in {"verified_at", "starred_at"}:
                key = record["state_key"]
                verified_at = state["starred_at"].get(key)
                if not verified_at and state["stars"].get(key) is True:
                    verified_at = self._legacy_starred_at()
                return _timestamp_sort_value(verified_at)
            return str(record.get(sort, "")).casefold()
        records = sorted(records, key=sort_value, reverse=order == "desc")
        total, start = len(records), (page - 1) * page_size
        return {
            "total": total, "page": page, "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "items": [self._public(record, state) for record in records[start:start + page_size]],
            "generated_at": snapshot.generated_at,
        }

    async def record(self, record_id: str) -> dict[str, Any]:
        record = (await self.snapshot()).by_id.get(record_id)
        if record is None:
            raise KeyError(record_id)
        return self._public(record, self.load_state())

    async def record_content(self, record_id: str) -> tuple[str, str]:
        record = (await self.snapshot()).by_id.get(record_id)
        if record is None or not isinstance(record.get("_file_ref"), FileRef):
            raise FileNotFoundError(record_id)
        path = self._resolve_ref(record["_file_ref"])
        return path.name, path.read_text(encoding="utf-8", errors="replace")

    async def targets(self) -> list[dict[str, Any]]:
        return (await self.snapshot()).targets

    async def reports(self) -> list[dict[str, Any]]:
        return [{key: value for key, value in item.items() if not key.startswith("_")} for item in (await self.snapshot()).reports]

    async def report_content(self, report_id: str) -> tuple[str, str]:
        report = next((item for item in (await self.snapshot()).reports if item["report_id"] == report_id), None)
        if report is None:
            raise FileNotFoundError(report_id)
        path = self._resolve_ref(report["_file_ref"])
        return path.name, path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _apply(state: dict[str, Any], key: str, actions: dict[str, Any]) -> None:
        for bucket in STATE_BUCKETS:
            state.setdefault(bucket, {})
        if "read" in actions:
            state["unread"][key] = not bool(actions["read"])
        if "unread" in actions:
            state["unread"][key] = bool(actions["unread"])
        for action, bucket in (("mark", "marks"), ("star", "stars"), ("archive", "archived")):
            if action in actions:
                if actions[action]:
                    state[bucket][key] = True
                else:
                    state[bucket].pop(key, None)
        if "star" in actions:
            if actions["star"]:
                state["starred_at"][key] = datetime.now(timezone.utc).isoformat()
            else:
                state["starred_at"].pop(key, None)
        if actions.get("archive"):
            state["unread"][key] = False
        if "verified" in actions:
            if actions["verified"] is None:
                state["verified"].pop(key, None)
            else:
                state["verified"][key] = bool(actions["verified"])
        if isinstance(actions.get("tags"), list):
            state["tags"][key] = [str(tag).strip() for tag in actions["tags"] if str(tag).strip()]
        if actions.get("add_tag"):
            tag = str(actions["add_tag"]).strip()
            tags = state["tags"].setdefault(key, [])
            if tag and tag not in tags:
                tags.append(tag)
        if actions.get("remove_tag"):
            tag = str(actions["remove_tag"]).strip()
            state["tags"][key] = [item for item in state["tags"].get(key, []) if item != tag]

    async def update_state(self, record_ids: list[str], actions: dict[str, Any]) -> dict[str, Any]:
        snapshot = await self.snapshot()
        records = [snapshot.by_id[item] for item in record_ids if item in snapshot.by_id]
        if not records:
            raise KeyError("No matching findings")
        async with self._state_lock:
            state = self.load_state()
            for record in records:
                self._apply(state, record["state_key"], actions)
            self.save_state(state)
            self._state_available = True
            return {"status": "ok", "updated": len(records), "state_backend": "local"}

    async def autoclean(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "auto_archived": 0, "state_backend": "local", "message": "Autoclean is not enabled for the independent Findings state backend."}

    async def export(self, fmt: str, severity: str = "", target: str = "") -> tuple[str, str, bytes]:
        snapshot, state = await self.snapshot(), self.load_state()
        records = snapshot.records
        if severity:
            records = [record for record in records if record["severity"] == severity.upper()]
        if target:
            records = [record for record in records if record["target"] == target]
        public = [self._public(record, state) for record in records]
        if fmt == "csv":
            output = io.StringIO()
            fields = ["target", "id", "title", "severity", "cvss", "timestamp", "source_file", "record_id"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for record in public:
                writer.writerow({field: record.get(field, "") for field in fields})
            return "findings.csv", "text/csv; charset=utf-8", output.getvalue().encode()
        return "findings.json", "application/json", json.dumps({"count": len(public), "findings": public}, ensure_ascii=False, indent=2).encode()


def create_findings_router(service: FindingsService) -> APIRouter:
    router = APIRouter()

    @router.get("/proxy/vulnerabilities/summary")
    async def summary():
        return await service.summary()

    @router.get("/proxy/vulnerabilities/bootstrap")
    async def bootstrap(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        q: str = "",
        severity: str = "",
        status: str = "needs-review",
        sort: str = "legacy",
        order: str = "asc",
    ):
        """Return summary + first-page findings in a single request to cut initial load from 4 requests to 1."""
        return await service.bootstrap(page, page_size, q, severity, status, sort, order)


    @router.get("/proxy/vulnerabilities")
    async def findings(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), q: str = "", severity: str = "", target: str = "", source: str = "", status: str = "", tag: str = "", sort: str = "legacy", order: str = "asc"):
        return await service.list_records(page, page_size, q, severity, target, source, status, tag, sort, order)

    @router.post("/proxy/vulnerabilities/refresh")
    async def refresh():
        snapshot = await service.refresh(force=True)
        return {"status": "ok", "count": len(snapshot.records), "generated_at": snapshot.generated_at}

    @router.get("/proxy/vulnerabilities/export")
    async def export(format: str = "json", severity: str = "", target: str = ""):
        if format not in {"json", "csv"}:
            raise HTTPException(status_code=400, detail="format must be json or csv")
        filename, media_type, content = await service.export(format, severity, target)
        return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @router.get("/proxy/vulnerabilities/targets")
    async def targets():
        return {"targets": await service.targets()}

    @router.get("/proxy/vulnerabilities/{record_id}")
    async def detail(record_id: str):
        try:
            return await service.record(record_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Finding not found")

    @router.get("/proxy/vulnerabilities/{record_id}/content")
    async def content(record_id: str, download: bool = False):
        try:
            filename, markdown = await service.record_content(record_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Finding report is not available")
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc))
        if download:
            return Response(content=markdown.encode(), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        return {"filename": filename, "content": markdown}

    @router.patch("/proxy/vulnerabilities/{record_id}/state")
    async def update_state(record_id: str, request: Request):
        try:
            return await service.update_state([record_id], await request.json())
        except KeyError:
            raise HTTPException(status_code=404, detail="Finding not found")

    @router.post("/proxy/vulnerabilities/bulk-state")
    async def bulk_state(request: Request):
        payload = await request.json()
        try:
            return await service.update_state(payload.get("record_ids") or [], payload.get("actions") or {})
        except KeyError:
            raise HTTPException(status_code=404, detail="No matching findings")

    @router.post("/proxy/vulnerabilities/autoclean")
    async def autoclean(request: Request):
        return await service.autoclean(await request.json())

    @router.get("/proxy/vulnerability-reports")
    async def reports():
        return {"reports": await service.reports()}

    @router.get("/proxy/vulnerability-reports/{report_id}")
    async def report(report_id: str, download: bool = False):
        try:
            filename, markdown = await service.report_content(report_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Report not found")
        if download:
            return Response(content=markdown.encode(), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        return {"filename": filename, "content": markdown}

    return router
