"""SQLite WAL asset inventory for Nscan.

The database stores structured metadata only. Raw Strix reports, SDK databases,
JSONL traces, and logs remain external artifacts referenced by path.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


SCHEMA_VERSION = 2


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_db_path() -> Path:
    return Path(
        os.environ.get(
            "NSCAN_ASSET_DB_PATH",
            str(Path(__file__).resolve().parent / "runtime" / "nscan-assets.sqlite3"),
        )
    )


def normalize_target(value: str) -> dict[str, Any]:
    raw = str(value or "").strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw.split("/", 1)[0]).strip().lower().rstrip(".")
    try:
        host = str(ipaddress.ip_address(host))
        target_type = "ip"
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        target_type = "domain"
    scheme = parsed.scheme.lower()
    port = parsed.port
    path = parsed.path or ""
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    endpoint_port = port or default_port
    canonical_key = host
    return {
        "canonical_key": canonical_key,
        "target": host,
        "target_type": target_type,
        "scheme": scheme,
        "port": endpoint_port,
        "path": path,
        "raw": raw,
    }


class AssetDatabase:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_db_path())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.spool_dir = self.path.parent / "asset_spool"
        self._migration_lock = threading.Lock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._migration_lock, self.transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY,
                    canonical_key TEXT NOT NULL UNIQUE,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    root_domain TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_probe_status TEXT NOT NULL DEFAULT 'unknown',
                    last_probe_at TEXT,
                    last_scan_status TEXT NOT NULL DEFAULT 'unscanned',
                    last_scanned_at TEXT,
                    scan_count INTEGER NOT NULL DEFAULT 0,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    latest_batch_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_assets_scan_status ON assets(last_scan_status);
                CREATE INDEX IF NOT EXISTS idx_assets_probe_status ON assets(last_probe_status);
                CREATE INDEX IF NOT EXISTS idx_assets_last_scanned ON assets(last_scanned_at DESC);
                CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC, target ASC);
                CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
                CREATE INDEX IF NOT EXISTS idx_assets_findings ON assets(finding_count DESC, target ASC);

                CREATE TABLE IF NOT EXISTS asset_aliases (
                    id INTEGER PRIMARY KEY,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    raw_target TEXT NOT NULL,
                    scheme TEXT NOT NULL DEFAULT '',
                    port INTEGER,
                    path TEXT NOT NULL DEFAULT '',
                    source_type TEXT NOT NULL,
                    source_ref TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(asset_id, raw_target, source_type, source_ref)
                );
                CREATE INDEX IF NOT EXISTS idx_alias_asset ON asset_aliases(asset_id);
                CREATE INDEX IF NOT EXISTS idx_alias_source_asset ON asset_aliases(source_type, asset_id, last_seen DESC);

                CREATE TABLE IF NOT EXISTS asset_addresses (
                    id INTEGER PRIMARY KEY,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    ip TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(asset_id, ip, source)
                );
                CREATE INDEX IF NOT EXISTS idx_address_ip ON asset_addresses(ip);

                CREATE TABLE IF NOT EXISTS probe_runs (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL DEFAULT '',
                    source_ref TEXT NOT NULL DEFAULT '',
                    started_at TEXT,
                    completed_at TEXT,
                    total INTEGER NOT NULL DEFAULT 0,
                    alive INTEGER NOT NULL DEFAULT 0,
                    dead INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS probe_results (
                    id INTEGER PRIMARY KEY,
                    probe_run_id TEXT NOT NULL REFERENCES probe_runs(id) ON DELETE CASCADE,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    alive INTEGER NOT NULL,
                    https_status INTEGER,
                    http_status INTEGER,
                    tcp443 INTEGER NOT NULL DEFAULT 0,
                    tcp80 INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL,
                    error TEXT NOT NULL DEFAULT '',
                    checked_at TEXT NOT NULL,
                    UNIQUE(probe_run_id, asset_id)
                );

                CREATE TABLE IF NOT EXISTS scan_batches (
                    batch_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    lifecycle TEXT NOT NULL DEFAULT '',
                    scan_mode TEXT NOT NULL DEFAULT '',
                    started_at TEXT,
                    updated_at TEXT,
                    completed_at TEXT,
                    total_tasks INTEGER NOT NULL DEFAULT 0,
                    success_tasks INTEGER NOT NULL DEFAULT 0,
                    failed_tasks INTEGER NOT NULL DEFAULT 0,
                    pending_tasks INTEGER NOT NULL DEFAULT 0,
                    running_tasks INTEGER NOT NULL DEFAULT 0,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    state_path TEXT NOT NULL DEFAULT '',
                    report_path TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_batches_started ON scan_batches(started_at DESC);

                CREATE TABLE IF NOT EXISTS scan_tasks (
                    id INTEGER PRIMARY KEY,
                    batch_id TEXT NOT NULL REFERENCES scan_batches(batch_id) ON DELETE CASCADE,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    scan_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT '',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    auto_requeue_count INTEGER NOT NULL DEFAULT 0,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    ended_at TEXT,
                    duration_seconds REAL,
                    model_name TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT '',
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    output_path TEXT NOT NULL DEFAULT '',
                    UNIQUE(batch_id, asset_id)
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_asset ON scan_tasks(asset_id, ended_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON scan_tasks(status);

                CREATE TABLE IF NOT EXISTS scan_attempts (
                    id INTEGER PRIMARY KEY,
                    task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
                    attempt_no INTEGER NOT NULL,
                    scan_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    started_at TEXT,
                    ended_at TEXT,
                    model_name TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT '',
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(task_id, attempt_no)
                );
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY,
                    batch_id TEXT NOT NULL REFERENCES scan_batches(batch_id) ON DELETE CASCADE,
                    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    event_type TEXT NOT NULL,
                    level TEXT NOT NULL DEFAULT 'info',
                    message TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    fingerprint TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS artifact_refs (
                    id INTEGER PRIMARY KEY,
                    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    batch_id TEXT REFERENCES scan_batches(batch_id) ON DELETE SET NULL,
                    artifact_type TEXT NOT NULL,
                    root_id TEXT NOT NULL DEFAULT '',
                    path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    checksum TEXT NOT NULL DEFAULT '',
                    created_at TEXT,
                    archived_at TEXT,
                    UNIQUE(artifact_type, path)
                );
                CREATE TABLE IF NOT EXISTS finding_refs (
                    record_id TEXT PRIMARY KEY,
                    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    finding_id TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                    cvss TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    report_path TEXT NOT NULL DEFAULT '',
                    found_at TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_findings_asset ON finding_refs(asset_id);

                CREATE TABLE IF NOT EXISTS import_sources (
                    source_ref TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    records INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT ''
                );
                """
            )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _asset_id(
        self,
        connection: sqlite3.Connection,
        target: str,
        *,
        source_type: str,
        source_ref: str = "",
        seen_at: str | None = None,
        root_domain: str = "",
    ) -> int:
        normalized = normalize_target(target)
        timestamp = seen_at or now_iso()
        connection.execute(
            """
            INSERT INTO assets(canonical_key,target,target_type,root_domain,first_seen,last_seen)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(canonical_key) DO UPDATE SET
              last_seen=excluded.last_seen,
              root_domain=CASE WHEN excluded.root_domain<>'' THEN excluded.root_domain ELSE assets.root_domain END
            """,
            (
                normalized["canonical_key"],
                normalized["target"],
                normalized["target_type"],
                root_domain,
                timestamp,
                timestamp,
            ),
        )
        asset_id = int(
            connection.execute(
                "SELECT id FROM assets WHERE canonical_key=?",
                (normalized["canonical_key"],),
            ).fetchone()[0]
        )
        connection.execute(
            """
            INSERT INTO asset_aliases(asset_id,raw_target,scheme,port,path,source_type,source_ref,first_seen,last_seen)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(asset_id,raw_target,source_type,source_ref)
            DO UPDATE SET last_seen=excluded.last_seen
            """,
            (
                asset_id,
                normalized["raw"],
                normalized["scheme"],
                normalized["port"],
                normalized["path"],
                source_type,
                source_ref,
                timestamp,
                timestamp,
            ),
        )
        return asset_id

    def upsert_asset(
        self,
        target: str,
        *,
        source_type: str,
        source_ref: str = "",
        seen_at: str | None = None,
        root_domain: str = "",
    ) -> int:
        with self.transaction() as connection:
            return self._asset_id(
                connection,
                target,
                source_type=source_type,
                source_ref=source_ref,
                seen_at=seen_at,
                root_domain=root_domain,
            )

    def record_addresses(self, target: str, addresses: list[str], source: str) -> None:
        with self.transaction() as connection:
            asset_id = self._asset_id(connection, target, source_type=source)
            timestamp = now_iso()
            for address in addresses:
                connection.execute(
                    """
                    INSERT INTO asset_addresses(asset_id,ip,source,first_seen,last_seen,active)
                    VALUES(?,?,?,?,?,1)
                    ON CONFLICT(asset_id,ip,source) DO UPDATE SET last_seen=excluded.last_seen,active=1
                    """,
                    (asset_id, str(address), source, timestamp, timestamp),
                )

    def sync_probe_run(self, payload: dict[str, Any], source_ref: str = "") -> None:
        run_id = str(payload.get("label") or "probe") + ":" + str(payload.get("generated_at") or uuid.uuid4())
        summary = payload.get("summary") or {}
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO probe_runs(id,label,source_ref,completed_at,total,alive,dead,blocked,metadata_json)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET completed_at=excluded.completed_at,total=excluded.total,
                  alive=excluded.alive,dead=excluded.dead,blocked=excluded.blocked,metadata_json=excluded.metadata_json
                """,
                (
                    run_id,
                    str(payload.get("label") or ""),
                    source_ref,
                    payload.get("generated_at"),
                    int(summary.get("total") or 0),
                    int(summary.get("alive") or 0),
                    int(summary.get("dead") or 0),
                    int(summary.get("blocked") or 0),
                    json.dumps(summary, ensure_ascii=False),
                ),
            )
            for result in payload.get("results") or []:
                target = str(result.get("host") or "")
                if not target:
                    continue
                asset_id = self._asset_id(connection, target, source_type="probe", source_ref=source_ref)
                alive = bool(result.get("alive"))
                connection.execute(
                    "UPDATE assets SET last_probe_status=?,last_probe_at=? WHERE id=?",
                    ("alive" if alive else "dead", payload.get("generated_at") or now_iso(), asset_id),
                )
                error = "; ".join(
                    str(result.get(key) or "") for key in ("https_error", "http_error") if result.get(key)
                )
                connection.execute(
                    """
                    INSERT INTO probe_results(probe_run_id,asset_id,alive,https_status,http_status,tcp443,tcp80,error,checked_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(probe_run_id,asset_id) DO UPDATE SET alive=excluded.alive,
                      https_status=excluded.https_status,http_status=excluded.http_status,
                      tcp443=excluded.tcp443,tcp80=excluded.tcp80,error=excluded.error
                    """,
                    (
                        run_id,
                        asset_id,
                        int(alive),
                        result.get("https_status"),
                        result.get("http_status"),
                        int(bool(result.get("tcp443"))),
                        int(bool(result.get("tcp80"))),
                        error,
                        payload.get("generated_at") or now_iso(),
                    ),
                )
                for address in result.get("resolved_ips") or []:
                    connection.execute(
                        """INSERT INTO asset_addresses(asset_id,ip,source,first_seen,last_seen,active)
                        VALUES(?,?,?,?,?,1) ON CONFLICT(asset_id,ip,source)
                        DO UPDATE SET last_seen=excluded.last_seen,active=1""",
                        (asset_id, str(address), "probe", now_iso(), now_iso()),
                    )

    def sync_batch_snapshot(self, batch: dict[str, Any], state_path: str = "") -> None:
        batch_id = str(batch.get("batch_id") or "")
        if not batch_id:
            return
        summary = batch.get("summary") or {}
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO scan_batches(batch_id,status,lifecycle,scan_mode,started_at,updated_at,completed_at,
                  total_tasks,success_tasks,failed_tasks,pending_tasks,running_tasks,config_json,state_path,report_path)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(batch_id) DO UPDATE SET status=excluded.status,lifecycle=excluded.lifecycle,
                  scan_mode=excluded.scan_mode,updated_at=excluded.updated_at,completed_at=excluded.completed_at,
                  total_tasks=excluded.total_tasks,success_tasks=excluded.success_tasks,
                  failed_tasks=excluded.failed_tasks,pending_tasks=excluded.pending_tasks,
                  running_tasks=excluded.running_tasks,config_json=excluded.config_json,
                  state_path=excluded.state_path,report_path=excluded.report_path
                """,
                (
                    batch_id,
                    str(batch.get("status") or "unknown"),
                    str(batch.get("lifecycle") or ""),
                    str(batch.get("scan_mode") or ""),
                    batch.get("started_at"),
                    batch.get("updated_at"),
                    batch.get("completed_at") or (batch.get("updated_at") if batch.get("status") in {"completed", "failed", "timeout"} else None),
                    int(summary.get("total_tasks") or len(batch.get("tasks") or [])),
                    int(summary.get("success") or 0),
                    int(summary.get("failed") or 0) + int(summary.get("timeout") or 0),
                    int(summary.get("pending") or 0),
                    int(summary.get("running") or 0),
                    json.dumps({"input_source": batch.get("input_source"), "parallel": batch.get("parallel"), "use_socks5": batch.get("use_socks5")}, ensure_ascii=False),
                    state_path,
                    str(batch.get("report_path") or ""),
                ),
            )
            for task in batch.get("tasks") or []:
                target = str(task.get("target") or "")
                if not target:
                    continue
                asset_id = self._asset_id(
                    connection,
                    target,
                    source_type="smart_batch",
                    source_ref=batch_id,
                    seen_at=task.get("started_at") or batch.get("started_at"),
                    root_domain=str(task.get("root_domain") or ""),
                )
                usage = task.get("llm_usage") or {}
                model_entries = task.get("llm_models_used") or []
                primary_model = str(task.get("llm_model_primary") or "")
                primary_provider = ""
                if isinstance(model_entries, list):
                    for entry in model_entries:
                        if not isinstance(entry, dict):
                            continue
                        if not primary_model or entry.get("actual_model") == primary_model:
                            primary_provider = str(entry.get("provider") or "")
                            primary_model = primary_model or str(entry.get("actual_model") or entry.get("model_id") or "")
                            break
                status = str(task.get("status") or "pending")
                ended_at = task.get("ended_at") or task.get("last_attempt_finished_at")
                connection.execute(
                    """
                    INSERT INTO scan_tasks(batch_id,asset_id,scan_id,status,priority,retry_count,
                      auto_requeue_count,attempt_count,started_at,ended_at,duration_seconds,model_name,
                      provider,prompt_tokens,completion_tokens,total_tokens,findings_count,error,output_path)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(batch_id,asset_id) DO UPDATE SET scan_id=excluded.scan_id,status=excluded.status,
                      priority=excluded.priority,retry_count=excluded.retry_count,
                      auto_requeue_count=excluded.auto_requeue_count,attempt_count=excluded.attempt_count,
                      started_at=excluded.started_at,ended_at=excluded.ended_at,duration_seconds=excluded.duration_seconds,
                      model_name=excluded.model_name,provider=excluded.provider,prompt_tokens=excluded.prompt_tokens,
                      completion_tokens=excluded.completion_tokens,total_tokens=excluded.total_tokens,
                      findings_count=excluded.findings_count,error=excluded.error,output_path=excluded.output_path
                    """,
                    (
                        batch_id,
                        asset_id,
                        str(task.get("scan_id") or task.get("last_attempt_scan_id") or ""),
                        status,
                        str(task.get("priority") or ""),
                        int(task.get("retry_count") or 0),
                        int(task.get("auto_requeue_count") or 0),
                        int(task.get("attempt_count_total") or 0),
                        task.get("started_at"),
                        ended_at,
                        task.get("duration_seconds"),
                        primary_model,
                        primary_provider,
                        int(usage.get("prompt_tokens") or 0),
                        int(usage.get("completion_tokens") or 0),
                        int(usage.get("total_tokens") or 0),
                        int(task.get("vulnerabilities_count") or 0),
                        str(task.get("last_error") or task.get("last_attempt_error") or ""),
                        str(task.get("output_path") or ""),
                    ),
                )
                task_row = connection.execute(
                    "SELECT id FROM scan_tasks WHERE batch_id=? AND asset_id=?",
                    (batch_id, asset_id),
                ).fetchone()
                if task_row:
                    attempt_no = max(
                        1,
                        int(
                            task.get("attempt_count_total")
                            or task.get("retry_count")
                            or task.get("auto_requeue_count")
                            or 1
                        ),
                    )
                    attempt_scan_id = str(task.get("last_attempt_scan_id") or task.get("scan_id") or "")
                    connection.execute(
                        """
                        INSERT INTO scan_attempts(task_id,attempt_no,scan_id,status,started_at,ended_at,
                          model_name,provider,total_tokens,error,metadata_json)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(task_id,attempt_no) DO UPDATE SET scan_id=excluded.scan_id,
                          status=excluded.status,ended_at=excluded.ended_at,model_name=excluded.model_name,
                          provider=excluded.provider,total_tokens=excluded.total_tokens,error=excluded.error,
                          metadata_json=excluded.metadata_json
                        """,
                        (
                            int(task_row[0]),
                            attempt_no,
                            attempt_scan_id,
                            status,
                            task.get("started_at"),
                            ended_at,
                            primary_model,
                            primary_provider,
                            int(usage.get("total_tokens") or 0),
                            str(task.get("last_error") or task.get("last_attempt_error") or ""),
                            json.dumps(
                                {
                                    "proxy_model_alias": task.get("proxy_model_alias"),
                                    "strix_pid": task.get("strix_pid"),
                                    "retry_reason": task.get("retry_reason"),
                                    "auto_requeue_reason": task.get("auto_requeue_reason"),
                                },
                                ensure_ascii=False,
                                default=str,
                            ),
                        ),
                    )
                if ended_at:
                    connection.execute(
                        "UPDATE assets SET last_scan_status=?,last_scanned_at=?,scan_count=MAX(scan_count,1),finding_count=MAX(finding_count,?),latest_batch_id=? WHERE id=?",
                        (status, ended_at, int(task.get("vulnerabilities_count") or 0), batch_id, asset_id),
                    )
                for address in task.get("target_ips") or []:
                    connection.execute(
                        """INSERT INTO asset_addresses(asset_id,ip,source,first_seen,last_seen,active)
                        VALUES(?,?,?,?,?,1) ON CONFLICT(asset_id,ip,source)
                        DO UPDATE SET last_seen=excluded.last_seen,active=1""",
                        (asset_id, str(address), str(task.get("target_ips_source") or "scan"), now_iso(), now_iso()),
                    )
            for event in batch.get("recent_events") or []:
                fingerprint = str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([batch_id, event], sort_keys=True, default=str)))
                target = str(event.get("target") or "")
                asset_id = None
                if target:
                    asset_id = self._asset_id(connection, target, source_type="scan_event", source_ref=batch_id)
                connection.execute(
                    """INSERT OR IGNORE INTO scan_events(batch_id,asset_id,event_type,level,message,created_at,payload_json,fingerprint)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        batch_id,
                        asset_id,
                        str(event.get("type") or "event"),
                        str(event.get("level") or "info"),
                        str(event.get("message") or ""),
                        str(event.get("timestamp") or now_iso()),
                        json.dumps(event.get("extra") or {}, ensure_ascii=False, default=str),
                        fingerprint,
                    ),
                )

    def has_scanned(self, target: str) -> bool:
        key = normalize_target(target)["canonical_key"]
        with self.connect() as connection:
            row = connection.execute(
                "SELECT last_scan_status FROM assets WHERE canonical_key=?",
                (key,),
            ).fetchone()
        return bool(row and str(row[0]) in {"success", "completed", "succeeded"})

    def scanned_targets(self) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT canonical_key FROM assets WHERE last_scan_status IN ('success','completed','succeeded')"
            ).fetchall()
        return {str(row[0]) for row in rows}

    def scanned_targets_page(
        self,
        *,
        query: str = "",
        source: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        page = max(1, int(page))
        page_size = max(1, min(200, int(page_size)))
        where = ["a.last_scan_status IN ('success','completed','succeeded')"]
        params: list[Any] = []
        if query:
            where.append("(a.target LIKE ? OR a.canonical_key LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])
        if source:
            where.append(
                "EXISTS(SELECT 1 FROM asset_aliases al WHERE al.asset_id=a.id AND al.source_type LIKE ?)"
            )
            params.append(f"%{source}%")
        clause = " WHERE " + " AND ".join(where)
        with self.connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM assets a{clause}", params).fetchone()[0])
            rows = connection.execute(
                f"""
                SELECT
                  a.id,
                  a.target,
                  a.canonical_key,
                  a.last_scanned_at AS last_seen,
                  a.latest_batch_id,
                  a.finding_count,
                  (
                    SELECT GROUP_CONCAT(source_type, ', ')
                    FROM (
                      SELECT DISTINCT al.source_type
                      FROM asset_aliases al
                      WHERE al.asset_id=a.id
                      ORDER BY al.last_seen DESC
                      LIMIT 6
                    )
                  ) AS source_text
                FROM assets a{clause}
                ORDER BY COALESCE(a.last_scanned_at, a.last_seen) DESC, a.target ASC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
            source_rows = connection.execute(
                """
                SELECT DISTINCT al.source_type
                FROM asset_aliases al
                JOIN assets a ON a.id=al.asset_id
                WHERE a.last_scan_status IN ('success','completed','succeeded')
                ORDER BY al.source_type
                """
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            sources = [part.strip() for part in str(item.pop("source_text") or "").split(",") if part.strip()]
            item["sources"] = sources
            items.append(item)
        return {
            "generated_at": now_iso(),
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "sources": [str(row[0]) for row in source_rows],
            "items": items,
        }

    def summary(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0])
            statuses = {row[0]: int(row[1]) for row in connection.execute("SELECT last_scan_status,COUNT(*) FROM assets GROUP BY last_scan_status")}
            probes = {row[0]: int(row[1]) for row in connection.execute("SELECT last_probe_status,COUNT(*) FROM assets GROUP BY last_probe_status")}
            findings = int(connection.execute("SELECT COUNT(*) FROM finding_refs").fetchone()[0])
        return {"generated_at": now_iso(), "total": total, "scan_status": statuses, "probe_status": probes, "findings": findings}

    def list_assets(
        self,
        *,
        query: str = "",
        scan_status: str = "",
        probe_status: str = "",
        source: str = "",
        page: int = 1,
        page_size: int = 50,
        sort: str = "last_seen",
    ) -> dict[str, Any]:
        page = max(1, int(page))
        page_size = max(1, min(200, int(page_size)))
        where, params = [], []
        if query:
            where.append("(a.target LIKE ? OR EXISTS(SELECT 1 FROM asset_addresses ip WHERE ip.asset_id=a.id AND ip.ip LIKE ?))")
            params.extend([f"%{query}%", f"%{query}%"])
        if scan_status:
            where.append("a.last_scan_status=?")
            params.append(scan_status)
        if probe_status:
            where.append("a.last_probe_status=?")
            params.append(probe_status)
        if source:
            where.append("EXISTS(SELECT 1 FROM asset_aliases al WHERE al.asset_id=a.id AND al.source_type LIKE ?)")
            params.append(f"%{source}%")
        clause = " WHERE " + " AND ".join(where) if where else ""
        order = {
            "target": "a.target ASC",
            "last_scanned": "a.last_scanned_at DESC, a.target ASC",
            "findings": "a.finding_count DESC, a.target ASC",
        }.get(sort, "a.last_seen DESC, a.target ASC")
        with self.connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM assets a{clause}", params).fetchone()[0])
            rows = connection.execute(
                f"""SELECT a.*,
                (SELECT GROUP_CONCAT(ip, ', ') FROM (SELECT ip FROM asset_addresses x WHERE x.asset_id=a.id ORDER BY x.last_seen DESC LIMIT 4)) AS addresses
                FROM assets a{clause} ORDER BY {order} LIMIT ? OFFSET ?""",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {
            "generated_at": now_iso(),
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "items": [dict(row) for row in rows],
        }

    def asset_detail(self, asset_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            asset = connection.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if not asset:
                return None
            payload = dict(asset)
            payload["aliases"] = [dict(row) for row in connection.execute("SELECT * FROM asset_aliases WHERE asset_id=? ORDER BY last_seen DESC", (asset_id,))]
            payload["addresses"] = [dict(row) for row in connection.execute("SELECT * FROM asset_addresses WHERE asset_id=? ORDER BY last_seen DESC", (asset_id,))]
            payload["probes"] = [dict(row) for row in connection.execute("SELECT pr.*,p.label FROM probe_results pr JOIN probe_runs p ON p.id=pr.probe_run_id WHERE pr.asset_id=? ORDER BY checked_at DESC LIMIT 100", (asset_id,))]
            payload["scans"] = [dict(row) for row in connection.execute("SELECT t.*,b.scan_mode,b.started_at AS batch_started_at FROM scan_tasks t JOIN scan_batches b ON b.batch_id=t.batch_id WHERE t.asset_id=? ORDER BY COALESCE(t.ended_at,t.started_at) DESC LIMIT 100", (asset_id,))]
            payload["attempts"] = [dict(row) for row in connection.execute("SELECT a.*,t.batch_id,t.scan_id AS task_scan_id FROM scan_attempts a JOIN scan_tasks t ON t.id=a.task_id WHERE t.asset_id=? ORDER BY COALESCE(a.ended_at,a.started_at) DESC LIMIT 200", (asset_id,))]
            payload["findings"] = [dict(row) for row in connection.execute("SELECT * FROM finding_refs WHERE asset_id=? ORDER BY found_at DESC", (asset_id,))]
            payload["artifacts"] = [dict(row) for row in connection.execute("SELECT * FROM artifact_refs WHERE asset_id=? ORDER BY created_at DESC", (asset_id,))]
        return payload

    def export_assets(self, format: str = "txt", **filters: Any) -> tuple[bytes, str]:
        page = 1
        items: list[dict[str, Any]] = []
        while True:
            result = self.list_assets(page=page, page_size=200, **filters)
            items.extend(result["items"])
            if page >= int(result.get("pages") or 1):
                break
            page += 1
        if format == "json":
            return json.dumps(items, ensure_ascii=False, indent=2).encode(), "application/json"
        if format == "csv":
            output = io.StringIO()
            fields = ["target", "target_type", "last_probe_status", "last_scan_status", "last_scanned_at", "finding_count"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: item.get(key) for key in fields} for item in items)
            return output.getvalue().encode(), "text/csv"
        return ("\n".join(str(item["target"]) for item in items) + "\n").encode(), "text/plain"

    def safe_event(self, operation: str, payload: dict[str, Any]) -> bool:
        try:
            if operation == "sync_batch":
                self.sync_batch_snapshot(payload.get("batch") or payload, str(payload.get("state_path") or ""))
            elif operation == "sync_probe":
                self.sync_probe_run(payload.get("probe") or payload, str(payload.get("source_ref") or ""))
            elif operation == "asset":
                self.upsert_asset(**payload)
            else:
                raise ValueError(f"unknown asset operation: {operation}")
            return True
        except Exception:
            self.spool_dir.mkdir(parents=True, exist_ok=True)
            path = self.spool_dir / f"asset-spool-{datetime.now(timezone.utc):%Y%m%d}.jsonl"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"operation": operation, "payload": payload, "created_at": now_iso()}, ensure_ascii=False, default=str) + "\n")
            return False

    def replay_spool(self) -> dict[str, int]:
        result = {"files": 0, "events": 0, "failed": 0}
        if not self.spool_dir.is_dir():
            return result
        for path in sorted(self.spool_dir.glob("*.jsonl")):
            result["files"] += 1
            remaining = []
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    event = json.loads(line)
                    operation, payload = event["operation"], event["payload"]
                    if operation == "sync_batch":
                        self.sync_batch_snapshot(payload.get("batch") or payload, str(payload.get("state_path") or ""))
                    elif operation == "sync_probe":
                        self.sync_probe_run(payload.get("probe") or payload, str(payload.get("source_ref") or ""))
                    elif operation == "asset":
                        self.upsert_asset(**payload)
                    result["events"] += 1
                except Exception:
                    remaining.append(line)
                    result["failed"] += 1
            if remaining:
                path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                path.unlink()
        return result

    def backup(self, destination: str | Path) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = self.connect()
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        return destination


_DEFAULT_DATABASE: AssetDatabase | None = None
_DEFAULT_LOCK = threading.Lock()


def get_asset_database() -> AssetDatabase:
    global _DEFAULT_DATABASE
    with _DEFAULT_LOCK:
        if _DEFAULT_DATABASE is None:
            _DEFAULT_DATABASE = AssetDatabase()
        return _DEFAULT_DATABASE
