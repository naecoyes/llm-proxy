"""健康管理器 - 管理模型健康状态"""

import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelHealth:
    """模型健康状态"""
    healthy: bool = True
    reason: str = ""
    failed_at: float = 0.0
    next_probe_at: float = 0.0
    probe_in_flight: bool = False
    consecutive_failures: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_success_at: float = 0.0
    last_failure_at: float = 0.0


class HealthChecker:
    """管理模型健康状态"""

    # 速率限制检测关键词
    RATE_LIMIT_PATTERNS = [
        "429",
        "ratelimit",
        "rate limit",
        "too many requests",
        "insufficient_quota",
        "quota exceeded",
        "resource_exhausted",
        "rate_limit_exceeded",
        "requests per min",
        "tokens per minute",
    ]

    # API 错误检测关键词
    API_ERROR_PATTERNS = [
        "LLM CONNECTION FAILED",
        "Could not establish connection to the language model",
        "LLM request failed",
        "APIConnectionError",
        "AuthenticationError",
        "PermissionDeniedError",
        "BadRequestError",
        "RateLimitError",
        "OpenAIException",
        "MinimaxException",
        "litellm.APIConnectionError",
        "litellm.AuthenticationError",
        "litellm.RateLimitError",
    ]

    def __init__(self, config: dict, stats_dir: str = "stats", model_manager=None):
        self.config = config
        self.stats_dir = Path(stats_dir)
        self.stats_dir.mkdir(parents=True, exist_ok=True)
        self.health_state: Dict[str, ModelHealth] = {}
        self.model_manager = model_manager
        self._update_config(config)
        self._load_health_state()

    def _update_config(self, config: dict):
        """更新配置"""
        failover = config.get("failover", {})
        self.max_consecutive_failures = failover.get("max_consecutive_failures", 3)
        self.recovery_time = failover.get("recovery_time", 3600)
        self.retry_delay = failover.get("retry_delay", 2)
        self.max_retries = failover.get("max_retries", 3)
        self.enabled = failover.get("enabled", True)

        # 自定义速率限制模式
        custom_patterns = failover.get("rate_limit_patterns", [])
        if custom_patterns:
            self.RATE_LIMIT_PATTERNS = custom_patterns

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._update_config(config)
        logger.info("健康管理器配置已更新")

    def _get_health_file(self) -> Path:
        """获取健康状态文件路径"""
        return self.stats_dir / "health_state.json"

    def _load_health_state(self):
        """从磁盘加载健康状态"""
        health_file = self._get_health_file()
        if not health_file.exists():
            return
        
        try:
            with open(health_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for model_name, state in data.items():
                self.health_state[model_name] = ModelHealth(
                    healthy=state.get("healthy", True),
                    reason=state.get("reason", ""),
                    failed_at=state.get("failed_at", 0.0),
                    next_probe_at=state.get("next_probe_at", 0.0),
                    probe_in_flight=state.get("probe_in_flight", False),
                    consecutive_failures=state.get("consecutive_failures", 0),
                    total_failures=state.get("total_failures", 0),
                    total_successes=state.get("total_successes", 0),
                    last_success_at=state.get("last_success_at", 0.0),
                    last_failure_at=state.get("last_failure_at", 0.0),
                )
            
            logger.info(f"已加载健康状态: {len(self.health_state)} 个模型")
        except Exception as e:
            logger.warning(f"加载健康状态失败: {e}")

    def _save_health_state(self):
        """保存健康状态到磁盘"""
        health_file = self._get_health_file()
        try:
            data = {}
            for model_name, state in self.health_state.items():
                data[model_name] = {
                    "healthy": state.healthy,
                    "reason": state.reason,
                    "failed_at": state.failed_at,
                    "next_probe_at": state.next_probe_at,
                    "probe_in_flight": state.probe_in_flight,
                    "consecutive_failures": state.consecutive_failures,
                    "total_failures": state.total_failures,
                    "total_successes": state.total_successes,
                    "last_success_at": state.last_success_at,
                    "last_failure_at": state.last_failure_at,
                }
            
            with open(health_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"保存健康状态失败: {e}")

    def initialize_model(self, model_name: str):
        """初始化模型健康状态"""
        if model_name not in self.health_state:
            self.health_state[model_name] = ModelHealth()

    def mark_unhealthy(self, model_name: str, reason: str):
        """标记模型不健康

        Args:
            model_name: 模型名称
            reason: 不健康原因
        """
        state = self.health_state.get(model_name, ModelHealth())

        # 如果已经是不健康状态，只更新原因
        if not state.healthy:
            state.reason = reason
            state.consecutive_failures += 1
            state.total_failures += 1
            state.last_failure_at = time.time()
        else:
            # 首次标记为不健康
            state.healthy = False
            state.reason = reason
            state.failed_at = time.time()
            state.next_probe_at = time.time() + self.recovery_time
            state.probe_in_flight = False
            state.consecutive_failures = 1
            state.total_failures += 1
            state.last_failure_at = time.time()

        self.health_state[model_name] = state
        self._save_health_state()

        logger.warning(
            f"⚠️ 模型 {model_name} 标记为不健康: {reason} | "
            f"连续失败: {state.consecutive_failures} | "
            f"下次探测: {self._format_time(state.next_probe_at)}"
        )

        # 连续失败超过阈值，自动禁用模型
        if state.consecutive_failures >= self.max_consecutive_failures:
            if self.model_manager:
                logger.warning(
                    f"🚫 模型 {model_name} 连续失败 {state.consecutive_failures} 次，自动禁用"
                )
                self.model_manager.disable_model(model_name)

    def mark_healthy(self, model_name: str):
        """标记模型恢复健康

        Args:
            model_name: 模型名称
        """
        state = self.health_state.get(model_name, ModelHealth())
        was_unhealthy = not state.healthy or state.probe_in_flight

        state.healthy = True
        state.reason = ""
        state.next_probe_at = 0.0
        state.probe_in_flight = False
        state.consecutive_failures = 0
        state.total_successes += 1
        state.last_success_at = time.time()

        self.health_state[model_name] = state
        self._save_health_state()

        if was_unhealthy:
            logger.info(f"🟢 模型 {model_name} 已恢复正常")

    def is_healthy(self, model_name: str) -> bool:
        """检查模型是否健康

        Returns:
            True 表示健康
        """
        state = self.health_state.get(model_name, ModelHealth())
        return state.healthy

    def should_probe(self, model_name: str) -> bool:
        """检查是否应该探测不健康模型

        Returns:
            True 表示应该探测
        """
        state = self.health_state.get(model_name, ModelHealth())

        # 已经健康，不需要探测
        if state.healthy:
            return False

        # 已经有探测在进行中
        if state.probe_in_flight:
            return False

        # 检查是否到达探测时间
        return time.time() >= state.next_probe_at

    def start_probe(self, model_name: str):
        """开始探测模型"""
        state = self.health_state.get(model_name, ModelHealth())
        state.probe_in_flight = True
        self.health_state[model_name] = state
        logger.info(f"🧪 开始探测模型: {model_name}")

    def end_probe(self, model_name: str, success: bool):
        """结束探测

        Args:
            model_name: 模型名称
            success: 探测是否成功
        """
        if success:
            self.mark_healthy(model_name)
        else:
            state = self.health_state.get(model_name, ModelHealth())
            state.probe_in_flight = False
            state.next_probe_at = time.time() + self.recovery_time
            self.health_state[model_name] = state
            logger.warning(f"❌ 模型 {model_name} 探测失败，下次探测: {self._format_time(state.next_probe_at)}")

    def get_healthy_models(self, model_names: List[str]) -> List[str]:
        """返回健康模型列表

        Args:
            model_names: 所有可用模型名称列表

        Returns:
            健康模型名称列表
        """
        return [
            name for name in model_names
            if self.is_healthy(name) or self.should_probe(name)
        ]

    def get_probe_ready_models(self, model_names: List[str]) -> List[str]:
        """返回准备好探测的模型列表

        Args:
            model_names: 所有可用模型名称列表

        Returns:
            准备好探测的模型名称列表
        """
        return [
            name for name in model_names
            if self.should_probe(name)
        ]

    def is_rate_limit_error(self, error_str: str) -> bool:
        """检测是否是速率限制错误

        Args:
            error_str: 错误信息字符串

        Returns:
            True 表示是速率限制错误
        """
        normalized = error_str.lower()
        return any(pattern.lower() in normalized for pattern in self.RATE_LIMIT_PATTERNS)

    def is_api_error(self, error_str: str) -> bool:
        """检测是否是 API 错误

        Args:
            error_str: 错误信息字符串

        Returns:
            True 表示是 API 错误
        """
        return any(pattern in error_str for pattern in self.API_ERROR_PATTERNS)

    def classify_error(self, error_str: str) -> Optional[str]:
        """分类错误类型

        Args:
            error_str: 错误信息字符串

        Returns:
            错误类型: "rate_limit", "api_error", 或 None
        """
        if self.is_rate_limit_error(error_str):
            return "rate_limit"
        if self.is_api_error(error_str):
            return "api_error"
        return None

    def _format_time(self, timestamp: float) -> str:
        """格式化时间戳"""
        if timestamp <= 0:
            return "N/A"
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def get_health_report(self) -> dict:
        """返回健康状态报告"""
        return {
            name: {
                "healthy": state.healthy,
                "reason": state.reason,
                "consecutive_failures": state.consecutive_failures,
                "total_failures": state.total_failures,
                "total_successes": state.total_successes,
                "last_success": self._format_time(state.last_success_at),
                "last_failure": self._format_time(state.last_failure_at),
                "next_probe": self._format_time(state.next_probe_at),
                "probe_in_flight": state.probe_in_flight,
            }
            for name, state in self.health_state.items()
        }

    def get_status(self) -> dict:
        """返回健康管理状态"""
        healthy_count = sum(1 for s in self.health_state.values() if s.healthy)
        unhealthy_count = len(self.health_state) - healthy_count

        return {
            "enabled": self.enabled,
            "total_models": len(self.health_state),
            "healthy_models": healthy_count,
            "unhealthy_models": unhealthy_count,
            "recovery_time": self.recovery_time,
            "max_consecutive_failures": self.max_consecutive_failures,
        }
