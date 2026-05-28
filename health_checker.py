"""健康管理器 - 管理模型健康状态"""

import logging
import time
from dataclasses import dataclass, asdict
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

    def __init__(self, config: dict):
        self.config = config
        self.health_state: Dict[str, ModelHealth] = {}
        self._update_config(config)

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

        logger.warning(
            f"⚠️ 模型 {model_name} 标记为不健康: {reason} | "
            f"连续失败: {state.consecutive_failures} | "
            f"下次探测: {self._format_time(state.next_probe_at)}"
        )

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
