#!/usr/bin/env python3
"""Import Nscan/Strix file-based history into the asset database."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from asset_database import AssetDatabase, normalize_target, now_iso


DEFAULT_PROJECT = Path(__file__).resolve().parent.parent
KNOWN_RUN_ROOTS = (
    Path("/home/osboxes/strix-0.8.3/strix_runs"),
    Path("/opt/strix-data/strix-0.8.3-runs"),
    Path("/home/osboxes/strix-1.0.2/strix_runs"),
    Path("/opt/strix-data/strix-1.0.2-runs"),
    Path("/home/osboxes/strix-1.0.4/strix_runs"),
    Path("/home/osboxes/Strix/strix_runs"),
)


def fingerprint(path: Path) -> str:
    stat = path.stat()
    return hashlib.sha256(f"{path.resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode()).hexdigest()


def history_files(project: Path) -> list[Path]:
    candidates = [project / "scanned_domains.txt"]
    candidates.extend(project.glob("*_scanned_history.txt"))
    candidates.extend((project / "reports").glob("*history*.txt"))
    for root in (Path("/home/osboxes/strix-0.8.3"), Path("/home/osboxes/strix-1.0.2"), Path("/home/osboxes/strix-1.0.4")):
        if root.is_dir():
            candidates.extend(root.glob("*_scanned_history.txt"))
            candidates.extend(root.glob("scanned_domains.txt"))
    return sorted({path.resolve() for path in candidates if path.is_file()})


def probe_files(project: Path) -> list[Path]:
    return sorted((project / "targets").glob("*_probe.json")) if (project / "targets").is_dir() else []


def state_files(project: Path) -> list[Path]:
    root = project / "llm_proxy" / "runtime" / "smart_batch"
    return sorted(root.glob("*.json")) if root.is_dir() else []


def read_run_target(events_path: Path) -> tuple[str, str]:
    try:
        with events_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle):
                if index > 60:
                    break
                if "run.configured" not in line:
                    continue
                event = json.loads(line)
                config = event.get("payload", {}).get("scan_config", {})
                targets = config.get("targets") or []
                if targets:
                    item = targets[0]
                    target = item.get("original") or item.get("details", {}).get("target_url") or ""
                    return str(target), str(event.get("timestamp") or "")
    except (OSError, json.JSONDecodeError):
        pass
    return "", ""


def parse_finding_markdown(path: Path) -> tuple[str, str]:
    title = path.stem
    severity = "UNKNOWN"
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:80]:
            line = raw.strip().lstrip("#").strip()
            lower = line.lower()
            if line and title == path.stem and not lower.startswith(("severity", "cvss", "target")):
                title = line[:240]
            if "critical" in lower:
                severity = "CRITICAL"
                break
            if "high" in lower:
                severity = "HIGH"
            elif "medium" in lower and severity == "UNKNOWN":
                severity = "MEDIUM"
            elif "low" in lower and severity == "UNKNOWN":
                severity = "LOW"
    except OSError:
        pass
    return title, severity


class Migrator:
    def __init__(self, db: AssetDatabase, project: Path, dry_run: bool = False) -> None:
        self.db = db
        self.project = project
        self.dry_run = dry_run
        self.counts = {
            "sources_seen": 0,
            "sources_skipped": 0,
            "history_targets": 0,
            "probe_results": 0,
            "batches": 0,
            "run_targets": 0,
            "artifacts": 0,
            "findings": 0,
            "errors": 0,
        }

    def already_imported(self, path: Path, kind: str) -> bool:
        self.counts["sources_seen"] += 1
        if self.dry_run:
            return False
        value = fingerprint(path)
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT fingerprint FROM import_sources WHERE source_ref=? AND source_type=?",
                (str(path), kind),
            ).fetchone()
        if row and row[0] == value:
            self.counts["sources_skipped"] += 1
            return True
        return False

    def mark_imported(self, path: Path, kind: str, records: int, error: str = "") -> None:
        if self.dry_run:
            return
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO import_sources(source_ref,source_type,fingerprint,imported_at,records,error)
                VALUES(?,?,?,?,?,?) ON CONFLICT(source_ref) DO UPDATE SET source_type=excluded.source_type,
                fingerprint=excluded.fingerprint,imported_at=excluded.imported_at,records=excluded.records,error=excluded.error""",
                (str(path), kind, fingerprint(path), now_iso(), records, error),
            )

    def import_history(self, path: Path) -> None:
        if self.already_imported(path, "history"):
            return
        records = 0
        seen_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            target = line.split("\t", 1)[0].strip()
            if not target or target.startswith("#"):
                continue
            records += 1
            if not self.dry_run:
                asset_id = self.db.upsert_asset(target, source_type="history", source_ref=str(path), seen_at=seen_at)
                with self.db.transaction() as connection:
                    connection.execute(
                        "UPDATE assets SET last_scan_status='success',last_scanned_at=COALESCE(last_scanned_at,?),scan_count=MAX(scan_count,1) WHERE id=?",
                        (seen_at, asset_id),
                    )
        self.counts["history_targets"] += records
        self.mark_imported(path, "history", records)

    def import_probe(self, path: Path) -> None:
        if self.already_imported(path, "probe"):
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = len(payload.get("results") or [])
        if not self.dry_run:
            self.db.sync_probe_run(payload, str(path))
        self.counts["probe_results"] += records
        self.mark_imported(path, "probe", records)

    def import_batch(self, path: Path) -> None:
        if self.already_imported(path, "batch_state"):
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not self.dry_run:
            self.db.sync_batch_snapshot(payload, str(path))
        self.counts["batches"] += 1
        self.mark_imported(path, "batch_state", len(payload.get("tasks") or []))

    def import_run(self, run_dir: Path, root_id: str) -> None:
        events = run_dir / "events.jsonl"
        if not events.is_file() or self.already_imported(events, "run"):
            return
        target, started_at = read_run_target(events)
        records = 0
        if target:
            records = 1
            self.counts["run_targets"] += 1
            if not self.dry_run:
                asset_id = self.db.upsert_asset(target, source_type="run", source_ref=str(run_dir), seen_at=started_at or None)
                with self.db.transaction() as connection:
                    connection.execute(
                        "UPDATE assets SET last_scan_status=CASE WHEN last_scan_status='unscanned' THEN 'completed' ELSE last_scan_status END,last_scanned_at=COALESCE(last_scanned_at,?),scan_count=MAX(scan_count,1) WHERE id=?",
                        (started_at or now_iso(), asset_id),
                    )
                    for artifact_type, path in (
                        ("run_dir", run_dir),
                        ("report", run_dir / "penetration_test_report.md"),
                        ("events", events),
                    ):
                        if not path.exists():
                            continue
                        size = path.stat().st_size if path.is_file() else 0
                        connection.execute(
                            """INSERT INTO artifact_refs(asset_id,artifact_type,root_id,path,size_bytes,created_at)
                            VALUES(?,?,?,?,?,?) ON CONFLICT(artifact_type,path) DO UPDATE SET asset_id=excluded.asset_id,size_bytes=excluded.size_bytes""",
                            (asset_id, artifact_type, root_id, str(path), size, started_at or now_iso()),
                        )
                        self.counts["artifacts"] += 1
                    for finding_path in sorted(run_dir.glob("**/*.md")):
                        if finding_path.name == "penetration_test_report.md":
                            continue
                        relative = str(finding_path.relative_to(run_dir))
                        if not any(part in relative.lower() for part in ("vuln", "finding", "evidence")):
                            continue
                        title, severity = parse_finding_markdown(finding_path)
                        record_id = hashlib.sha256(str(finding_path.resolve()).encode()).hexdigest()[:24]
                        connection.execute(
                            """INSERT INTO finding_refs(record_id,asset_id,finding_id,title,severity,source,report_path,found_at,metadata_json)
                            VALUES(?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(record_id) DO UPDATE SET asset_id=excluded.asset_id,title=excluded.title,
                              severity=excluded.severity,report_path=excluded.report_path,found_at=excluded.found_at""",
                            (
                                record_id,
                                asset_id,
                                finding_path.stem,
                                title,
                                severity,
                                root_id,
                                str(finding_path),
                                started_at or now_iso(),
                                json.dumps({"run_dir": str(run_dir), "relative_path": relative}, ensure_ascii=False),
                            ),
                        )
                        self.counts["findings"] += 1
        self.mark_imported(events, "run", records)

    def run(self) -> dict[str, Any]:
        for path in history_files(self.project):
            try:
                self.import_history(path)
            except Exception as exc:
                self.counts["errors"] += 1
                self.mark_imported(path, "history", 0, str(exc))
        for path in probe_files(self.project):
            try:
                self.import_probe(path)
            except Exception as exc:
                self.counts["errors"] += 1
                self.mark_imported(path, "probe", 0, str(exc))
        for path in state_files(self.project):
            try:
                self.import_batch(path)
            except Exception as exc:
                self.counts["errors"] += 1
                self.mark_imported(path, "batch_state", 0, str(exc))
        for root in KNOWN_RUN_ROOTS:
            if not root.is_dir():
                continue
            for run_dir in root.iterdir():
                if run_dir.is_dir():
                    try:
                        self.import_run(run_dir, root.name)
                    except Exception:
                        self.counts["errors"] += 1
        result = {"generated_at": now_iso(), "dry_run": self.dry_run, "counts": self.counts}
        if not self.dry_run:
            result["database"] = self.db.summary()
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path)
    parser.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    db = AssetDatabase(args.db)
    result = Migrator(db, args.project_root, dry_run=args.dry_run).run()
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
