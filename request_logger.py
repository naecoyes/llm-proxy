"""请求日志记录器"""

import json
import logging
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


SCAN_CONTEXT_FIELD_HEADERS = {
    "scan_id": "X-Strix-Batch-Scan-Id",
    "scan_target": "X-Strix-Batch-Target",
    "scan_root_domain": "X-Strix-Batch-Root-Domain",
    "scan_mode": "X-Strix-Batch-Scan-Mode",
    "proxy_slot": "X-Strix-Batch-Proxy-Slot",
    "scan_retry": "X-Strix-Batch-Retry",
    "scan_pid": "X-Strix-Process-Pid",
}
SCAN_CONTEXT_LOG_FIELDS = tuple(SCAN_CONTEXT_FIELD_HEADERS.keys())
MAX_SCAN_CONTEXT_VALUE_LENGTH = 512


def sanitize_scan_context_value(value: str) -> str:
    """Keep local scan context values safe for HTTP headers and log records."""
    return (value or "").replace("\r", " ").replace("\n", " ").strip()[
        :MAX_SCAN_CONTEXT_VALUE_LENGTH
    ]


def normalize_scan_context(scan_context: Optional[dict]) -> dict:
    """Return stable non-empty scan context log fields."""
    if not scan_context:
        return {}
    fields = {
        key: sanitize_scan_context_value(str(scan_context.get(key) or ""))
        for key in SCAN_CONTEXT_LOG_FIELDS
    }
    return {key: value for key, value in fields.items() if value}


class RequestLogger:
    """记录每次模型调用的详细信息"""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            # 默认使用项目根目录下的 logs 目录
            log_dir = Path(__file__).parent / "logs"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.process_started_at = datetime.now().astimezone()
        self._setup_file_logger()
        self._current_date = datetime.now().astimezone().strftime("%Y-%m-%d")

    def _setup_file_logger(self):
        """设置文件日志记录器"""
        self.file_logger = logging.getLogger("request_logger")
        self.file_logger.setLevel(logging.INFO)

        # 避免重复添加 handler
        if not self.file_logger.handlers:
            # 按日期命名日志文件
            today = datetime.now().astimezone().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"requests_{today}.log"

            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.INFO)

            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)

            self.file_logger.addHandler(handler)

    def _rotate_if_needed(self):
        """按日期轮转日志文件"""
        today = datetime.now().astimezone().strftime("%Y-%m-%d")
        if today != self._current_date:
            self._current_date = today
            # 移除旧的 handler
            for handler in self.file_logger.handlers[:]:
                self.file_logger.removeHandler(handler)
                handler.close()
            # 添加新的 handler
            log_file = self.log_dir / f"requests_{today}.log"
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self.file_logger.addHandler(handler)

    def _persist_entry(self, entry: dict) -> None:
        """Keep JSONL as the raw audit trail and best-effort mirror metadata to SQLite."""
        self.file_logger.info(json.dumps(entry, ensure_ascii=False))
        try:
            from asset_database import get_asset_database

            get_asset_database().record_llm_event(entry)
        except Exception as exc:
            logger.warning("SQLite LLM event mirror failed: %s", exc)

    def log_request(
        self,
        request_id: str,
        client_ip: str,
        requested_model: str,
        actual_model: str,
        provider: str,
        messages: list,
        stream: bool = False,
        model_id: str = "",
        scan_context: Optional[dict] = None,
    ):
        """记录请求开始"""
        self._rotate_if_needed()
        entry = {
            "type": "request",
            "timestamp": datetime.now().astimezone().isoformat(),
            "request_id": request_id,
            "client_ip": client_ip,
            "requested_model": requested_model,
            "actual_model": actual_model,
            "model_id": model_id,
            "provider": provider,
            "stream": stream,
            "message_count": len(messages),
            "first_message_preview": messages[0]["content"][:100] if messages else "",
        }
        entry.update(self._scan_context_fields(scan_context))
        self._persist_entry(entry)

    def log_response(
        self,
        request_id: str,
        model_name: str,
        duration: float,
        status: str,
        usage: Optional[dict] = None,
        error: Optional[str] = None,
        scan_context: Optional[dict] = None,
    ):
        """记录请求完成"""
        self._rotate_if_needed()
        entry = {
            "type": "response",
            "timestamp": datetime.now().astimezone().isoformat(),
            "request_id": request_id,
            "model_name": model_name,
            "duration_seconds": round(duration, 3),
            "status": status,
            "usage": usage or {},
            "error": error,
        }
        entry.update(self._scan_context_fields(scan_context))
        self._persist_entry(entry)

    def log_model_switch(
        self,
        request_id: str,
        from_model: str,
        to_model: str,
        reason: str,
        scan_context: Optional[dict] = None,
    ):
        """记录模型切换"""
        self._rotate_if_needed()
        entry = {
            "type": "model_switch",
            "timestamp": datetime.now().astimezone().isoformat(),
            "request_id": request_id,
            "from_model": from_model,
            "to_model": to_model,
            "reason": reason,
        }
        entry.update(self._scan_context_fields(scan_context))
        self._persist_entry(entry)

    def _scan_context_fields(self, scan_context: Optional[dict]) -> dict:
        """Flatten scan context into stable log fields."""
        return normalize_scan_context(scan_context)

    def read_logs(
        self,
        *,
        limit: int = 100,
        scan_id: str | None = None,
        proxy_slot: str | None = None,
        log_date: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        days: int = 1,
    ) -> dict:
        """Read request logs across one or more dates with optional scan filters."""
        log_files = self._resolve_log_files(
            log_date=log_date,
            start_date=start_date,
            end_date=end_date,
            days=days,
        )
        safe_limit = max(1, min(int(limit or 100), 10000))
        try:
            from asset_database import get_asset_database

            db_logs = get_asset_database().read_llm_events(
                start_date=log_files[0].stem.removeprefix("requests_") if log_files else datetime.now().astimezone().date().isoformat(),
                end_date=log_files[-1].stem.removeprefix("requests_") if log_files else datetime.now().astimezone().date().isoformat(),
                limit=safe_limit,
                scan_id=scan_id or "",
                proxy_slot=proxy_slot or "",
            )
            if db_logs:
                return {
                    "logs": db_logs,
                    "total": len(db_logs),
                    "total_matching": len(db_logs),
                    "files": ["sqlite:nscan-assets.sqlite3"],
                    "storage": "sqlite",
                }
        except Exception as exc:
            logger.warning("SQLite LLM log read failed; using JSONL: %s", exc)
        logs = []
        for log_file in log_files:
            if not log_file.exists():
                continue
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if scan_id and entry.get("scan_id") != scan_id:
                        continue
                    if proxy_slot and str(entry.get("proxy_slot", "")) != str(proxy_slot):
                        continue
                    logs.append(entry)

        total_matching = len(logs)
        return {
            "logs": logs[-safe_limit:],
            "total": len(logs[-safe_limit:]),
            "total_matching": total_matching,
            "files": [str(path) for path in log_files if path.exists()],
            "storage": "jsonl",
        }

    def join_logs(self, logs: list[dict]) -> dict:
        """Join request/response/model_switch entries by request id."""
        requests: dict[str, dict] = {}
        switch_reasons: Counter[str] = Counter()

        def ensure_request(request_id: str) -> dict:
            return requests.setdefault(
                request_id or "unknown",
                {
                    "request_id": request_id or "unknown",
                    "scan_id": "",
                    "scan_target": "",
                    "scan_root_domain": "",
                    "scan_pid": "",
                    "proxy_slot": "",
                    "client_ip": "",
                    "requested_model": "",
                    "actual_model": "",
                    "provider": "",
                    "model_id": "",
                    "request_timestamp": "",
                    "response_timestamp": "",
                    "status": "pending",
                    "duration_seconds": None,
                    "usage": {},
                    "error": None,
                    "model_switches": [],
                },
            )

        for entry in logs:
            request_id = entry.get("request_id") or "unknown"
            joined = ensure_request(request_id)
            for key in SCAN_CONTEXT_LOG_FIELDS:
                if entry.get(key) and not joined.get(key):
                    joined[key] = entry.get(key)

            entry_type = entry.get("type")
            if entry_type == "request":
                joined.update(
                    {
                        "client_ip": entry.get("client_ip", ""),
                        "requested_model": entry.get("requested_model", ""),
                        "actual_model": entry.get("actual_model", ""),
                        "provider": entry.get("provider", ""),
                        "model_id": entry.get("model_id", ""),
                        "request_timestamp": entry.get("timestamp", ""),
                    }
                )
            elif entry_type == "response":
                joined.update(
                    {
                        "response_timestamp": entry.get("timestamp", ""),
                        "status": entry.get("status", "unknown"),
                        "duration_seconds": entry.get("duration_seconds"),
                        "usage": entry.get("usage") or {},
                        "error": entry.get("error"),
                    }
                )
                if entry.get("model_name") and not joined.get("actual_model"):
                    joined["actual_model"] = entry.get("model_name")
            elif entry_type == "model_switch":
                reason = entry.get("reason") or "unknown"
                switch_reasons[reason] += 1
                joined["model_switches"].append(
                    {
                        "timestamp": entry.get("timestamp"),
                        "from_model": entry.get("from_model"),
                        "to_model": entry.get("to_model"),
                        "reason": reason,
                    }
                )

        # A pending request from an older proxy process cannot still complete.
        # Classify it explicitly instead of leaving it as stale_no_response.
        process_started_ts = self.process_started_at.timestamp()
        for joined in requests.values():
            if joined.get("status") != "pending":
                continue
            request_ts = self._timestamp_sort_key(joined.get("request_timestamp"))
            if request_ts and request_ts < process_started_ts:
                joined["status"] = "interrupted"
                joined["error"] = "Proxy restarted before response completed"

        joined_requests = sorted(
            requests.values(),
            key=lambda item: max(
                self._timestamp_sort_key(item.get("response_timestamp")),
                self._timestamp_sort_key(item.get("request_timestamp")),
            ),
            reverse=True,
        )
        return {
            "requests": joined_requests,
            "model_switch_reasons": dict(switch_reasons),
        }

    @staticmethod
    def _timestamp_sort_key(value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return 0.0

    def _resolve_log_files(
        self,
        *,
        log_date: str | None,
        start_date: str | None,
        end_date: str | None,
        days: int,
    ) -> list[Path]:
        """Return request log files ordered oldest to newest."""
        if log_date:
            dates = [self._parse_date(log_date)]
        elif start_date or end_date:
            start = self._parse_date(start_date or end_date)
            end = self._parse_date(end_date or start_date)
            if start > end:
                start, end = end, start
            span = min((end - start).days + 1, 31)
            dates = [start + timedelta(days=offset) for offset in range(span)]
        else:
            safe_days = max(1, min(int(days or 1), 31))
            today = datetime.now().astimezone().date()
            dates = [today - timedelta(days=offset) for offset in range(safe_days)]
            dates.reverse()
        return [self.log_dir / f"requests_{day.isoformat()}.log" for day in dates]

    def _parse_date(self, value: str | None):
        if not value:
            return datetime.now().astimezone().date()
        return date.fromisoformat(value)


# 全局请求日志记录器实例
request_logger = RequestLogger()
