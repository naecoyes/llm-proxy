#!/usr/bin/env python3
"""Backup the asset database and safely archive cold completed Strix runs."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from asset_database import AssetDatabase, now_iso


HOME_RUN_ROOTS = (
    Path("/home/osboxes/strix-0.8.3/strix_runs"),
    Path("/home/osboxes/strix-1.0.2/strix_runs"),
    Path("/home/osboxes/strix-1.0.4/strix_runs"),
    Path("/home/osboxes/Strix/strix_runs"),
)


def tree_stats(root: Path) -> tuple[int, int]:
    files = size = 0
    for path in root.rglob("*"):
        if path.is_file():
            files += 1
            size += path.stat().st_size
    return files, size


def active_run_paths(project: Path) -> set[Path]:
    result: set[Path] = set()
    state_dir = project / "llm_proxy" / "runtime" / "smart_batch"
    for path in state_dir.glob("*.json") if state_dir.is_dir() else []:
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for task in state.get("tasks") or []:
            if task.get("status") not in {"running", "retrying"}:
                continue
            output = task.get("output_path")
            if output:
                result.add(Path(output).resolve())
    return result


def archive_runs(
    db: AssetDatabase,
    *,
    project: Path,
    destination: Path,
    days: int = 30,
    apply: bool = False,
) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    active = active_run_paths(project)
    actions = []
    for root in HOME_RUN_ROOTS:
        if not root.is_dir():
            continue
        version = root.parent.name
        for run_dir in root.iterdir():
            if not run_dir.is_dir() or run_dir.resolve() in active:
                continue
            report = run_dir / "penetration_test_report.md"
            events = run_dir / "events.jsonl"
            if not report.is_file() and not events.is_file():
                continue
            modified = datetime.fromtimestamp(run_dir.stat().st_mtime, timezone.utc)
            if modified > cutoff:
                continue
            target = destination / version / f"{modified:%Y/%m}" / run_dir.name
            action = {"source": str(run_dir), "destination": str(target), "modified_at": modified.isoformat(), "applied": False, "error": ""}
            if not apply:
                actions.append(action)
                continue
            try:
                if target.exists():
                    raise FileExistsError(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(f".{target.name}.nscan-copy")
                if temporary.exists():
                    shutil.rmtree(temporary)
                shutil.copytree(run_dir, temporary, copy_function=shutil.copy2)
                source_stats = tree_stats(run_dir)
                copied_stats = tree_stats(temporary)
                if source_stats != copied_stats:
                    raise RuntimeError(f"archive verification failed: {source_stats} != {copied_stats}")
                os.replace(temporary, target)
                with db.transaction() as connection:
                    rows = connection.execute("SELECT id,path FROM artifact_refs WHERE path=? OR path LIKE ?", (str(run_dir), f"{run_dir}/%")).fetchall()
                    for row in rows:
                        old = Path(row["path"])
                        replacement = target if old == run_dir else target / old.relative_to(run_dir)
                        connection.execute("UPDATE artifact_refs SET path=?,root_id=?,archived_at=? WHERE id=?", (str(replacement), "cold-archive", now_iso(), row["id"]))
                shutil.rmtree(run_dir)
                action["applied"] = True
            except Exception as exc:
                action["error"] = str(exc)
            actions.append(action)
    return {"generated_at": now_iso(), "apply": apply, "cutoff": cutoff.isoformat(), "count": len(actions), "actions": actions}


def rotate_backups(root: Path, keep_daily: int = 14, keep_weekly: int = 8) -> dict[str, int]:
    files = sorted(root.glob("nscan-assets-*.sqlite3"), reverse=True)
    keep: set[Path] = set(files[:keep_daily])
    weeks: set[tuple[int, int]] = set()
    for path in files:
        try:
            date = datetime.strptime(path.stem.removeprefix("nscan-assets-"), "%Y%m%d").date()
        except ValueError:
            continue
        week = date.isocalendar()[:2]
        if week not in weeks and len(weeks) < keep_weekly:
            keep.add(path)
            weeks.add(week)
    removed = 0
    for path in files:
        if path not in keep:
            path.unlink()
            removed += 1
    return {"kept": len(keep), "removed": removed}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("backup", "archive"))
    parser.add_argument("--db", type=Path)
    parser.add_argument("--project-root", type=Path, default=Path("/home/osboxes/Strix"))
    parser.add_argument("--backup-root", type=Path, default=Path("/opt/strix-data/nscan-db-backups"))
    parser.add_argument("--archive-root", type=Path, default=Path("/opt/strix-data/strix-runs"))
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    db = AssetDatabase(args.db)
    if args.action == "backup":
        args.backup_root.mkdir(parents=True, exist_ok=True)
        destination = args.backup_root / f"nscan-assets-{datetime.now(timezone.utc):%Y%m%d}.sqlite3"
        db.backup(destination)
        print(json.dumps({"backup": str(destination), **rotate_backups(args.backup_root)}, indent=2))
    else:
        print(json.dumps(archive_runs(db, project=args.project_root, destination=args.archive_root, days=args.days, apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
