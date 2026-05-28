"""请求日志记录器"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class RequestLogger:
    """记录每次模型调用的详细信息"""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            # 默认使用项目根目录下的 logs 目录
            log_dir = Path(__file__).parent / "logs"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_file_logger()
        self._current_date = datetime.now().strftime("%Y-%m-%d")

    def _setup_file_logger(self):
        """设置文件日志记录器"""
        self.file_logger = logging.getLogger("request_logger")
        self.file_logger.setLevel(logging.INFO)

        # 避免重复添加 handler
        if not self.file_logger.handlers:
            # 按日期命名日志文件
            today = datetime.now().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"requests_{today}.log"

            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.INFO)

            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)

            self.file_logger.addHandler(handler)

    def _rotate_if_needed(self):
        """按日期轮转日志文件"""
        today = datetime.now().strftime("%Y-%m-%d")
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

    def log_request(
        self,
        request_id: str,
        client_ip: str,
        requested_model: str,
        actual_model: str,
        provider: str,
        messages: list,
        stream: bool = False,
    ):
        """记录请求开始"""
        self._rotate_if_needed()
        entry = {
            "type": "request",
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "client_ip": client_ip,
            "requested_model": requested_model,
            "actual_model": actual_model,
            "provider": provider,
            "stream": stream,
            "message_count": len(messages),
            "first_message_preview": messages[0]["content"][:100] if messages else "",
        }
        self.file_logger.info(json.dumps(entry, ensure_ascii=False))

    def log_response(
        self,
        request_id: str,
        model_name: str,
        duration: float,
        status: str,
        usage: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        """记录请求完成"""
        self._rotate_if_needed()
        entry = {
            "type": "response",
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "model_name": model_name,
            "duration_seconds": round(duration, 3),
            "status": status,
            "usage": usage or {},
            "error": error,
        }
        self.file_logger.info(json.dumps(entry, ensure_ascii=False))

    def log_model_switch(
        self,
        request_id: str,
        from_model: str,
        to_model: str,
        reason: str,
    ):
        """记录模型切换"""
        self._rotate_if_needed()
        entry = {
            "type": "model_switch",
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "from_model": from_model,
            "to_model": to_model,
            "reason": reason,
        }
        self.file_logger.info(json.dumps(entry, ensure_ascii=False))


# 全局请求日志记录器实例
request_logger = RequestLogger()
