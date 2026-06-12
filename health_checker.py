"""健康管理器 - 管理模型健康状态"""

import json
import logging
import time
from dataclasses import dataclass
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
    recent_results: list = None  # 最近请求结果 [True/False]
    re_enable_at: float = 0.0  # 自动重新启用的时间戳

    def __post_init__(self):
        if self.recent_results is None:
            self.recent_results = []


class HealthChecker:
    """管理模型健康状态"""

    # 速率限制/临时错误检测关键词（只重试不禁用）
    RATE_LIMIT_PATTERNS = [
        "429",
        "ratelimit",
        "rate limit",
        "too many requests",
        "rate_limit_exceeded",
        "requests per min",
        "tokens per minute",
        "server disconnected",
        "connection error",
        "connection reset",
        "connection refused",
        "empty response",
    ]

    # 额度/key 错误检测关键词（立即禁用）
    QUOTA_ERROR_PATTERNS = [
        "insufficient_quota",
        "quota exceeded",
        "resource_exhausted",
        "invalid_api_key",
        "invalid request",
        "authentication",
        "401",
        "403",
        "usage limit exceeded",
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

        # 检查是否是速率限制错误（只重试不禁用）
        is_rate_limit = self.is_rate_limit_error(reason)
        # 检查是否是额度/key 错误（立即禁用）
        is_quota = self.is_quota_error(reason)

        if is_rate_limit:
            # 速率限制：短暂延迟后重试，不禁用模型
            logger.info(f"⏳ 模型 {model_name} 触发速率限制: {reason}，短暂延迟后重试")
            state.total_failures += 1
            state.last_failure_at = time.time()
            # 记录最近结果
            state.recent_results.append(False)
            if len(state.recent_results) > 100:
                state.recent_results = state.recent_results[-100:]
            # 不增加 consecutive_failures，不标记为不健康
            self.health_state[model_name] = state
            self._save_health_state()
            return

        if is_quota:
            # 额度/key 错误：立即禁用
            logger.warning(f"🚫 模型 {model_name} 额度/key 错误: {reason}，立即禁用")
            state.healthy = False
            state.reason = reason
            state.total_failures += 1
            state.last_failure_at = time.time()
            # 记录最近结果
            state.recent_results.append(False)
            if len(state.recent_results) > 100:
                state.recent_results = state.recent_results[-100:]
            self.health_state[model_name] = state
            self._save_health_state()
            if self.model_manager:
                self.model_manager.disable_model(model_name)
            return

        # 其他错误：正常处理
        # 记录最近结果
        state.recent_results.append(False)
        if len(state.recent_results) > 100:
            state.recent_results = state.recent_results[-100:]

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

        # 记录最近结果
        state.recent_results.append(True)
        if len(state.recent_results) > 100:
            state.recent_results = state.recent_results[-100:]

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

    def set_re_enable_time(
        self, model_name: str, re_enable_at: float, reason: str = ""
    ):
        """设置模型自动重新启用时间

        Args:
            model_name: 模型名称
            re_enable_at: 重新启用的时间戳
            reason: 原因
        """
        state = self.health_state.get(model_name, ModelHealth())
        state.re_enable_at = re_enable_at
        state.reason = reason
        state.healthy = False
        self.health_state[model_name] = state
        self._save_health_state()

        re_enable_time = datetime.fromtimestamp(re_enable_at).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        logger.info(
            f"⏰ 模型 {model_name} 将在 {re_enable_time} 自动重新启用: {reason}"
        )

    def check_and_re_enable_models(self, model_manager) -> List[str]:
        """检查并重新启用已到期的模型

        Args:
            model_manager: 模型管理器

        Returns:
            已重新启用的模型列表
        """
        re_enabled = []
        now = time.time()

        for model_name, state in self.health_state.items():
            if state.re_enable_at > 0 and now >= state.re_enable_at:
                # 到达重新启用时间
                state.re_enable_at = 0.0
                state.healthy = True
                state.reason = ""
                state.consecutive_failures = 0
                self.health_state[model_name] = state

                # 启用模型
                model_manager.enable_model(model_name)
                re_enabled.append(model_name)
                logger.info(f"🟢 模型 {model_name} 已自动重新启用")

        if re_enabled:
            self._save_health_state()

        return re_enabled

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
            logger.warning(
                f"❌ 模型 {model_name} 探测失败，下次探测: {self._format_time(state.next_probe_at)}"
            )

    def get_healthy_models(self, model_names: List[str]) -> List[str]:
        """返回健康模型列表

        Args:
            model_names: 所有可用模型名称列表

        Returns:
            健康模型名称列表
        """
        return [
            name
            for name in model_names
            if self.is_healthy(name) or self.should_probe(name)
        ]

    def get_success_rate(self, model_name: str) -> float:
        """获取模型近期成功率（基于最近 100 次请求）

        Args:
            model_name: 模型名称

        Returns:
            成功率 (0.0 ~ 1.0)，无数据返回 1.0
        """
        state = self.health_state.get(model_name)
        if not state or not state.recent_results:
            return 1.0
        success_count = sum(state.recent_results)
        return success_count / len(state.recent_results)

    def get_recent_request_count(self, model_name: str) -> int:
        """获取模型近期请求次数"""
        state = self.health_state.get(model_name)
        if not state or not state.recent_results:
            return 0
        return len(state.recent_results)

    def should_auto_disable(self, model_name: str, min_requests: int = 20, min_rate: float = 0.5) -> bool:
        """判断模型是否应该被自动禁用（连续失败过多）

        Args:
            model_name: 模型名称
            min_requests: 最少请求数才开始判断
            min_rate: 最低成功率阈值

        Returns:
            True 表示应该禁用
        """
        state = self.health_state.get(model_name)
        if not state or not state.recent_results:
            return False
        if len(state.recent_results) < min_requests:
            return False
        rate = sum(state.recent_results) / len(state.recent_results)
        return rate < min_rate

    def filter_by_success_rate(
        self, model_names: List[str], min_rate: float = 0.7
    ) -> List[str]:
        """过滤掉近期成功率过低的模型

        Args:
            model_names: 模型名称列表
            min_rate: 最低成功率阈值 (默认 70%)

        Returns:
            成功率达标的模型列表
        """
        passed = []
        for name in model_names:
            rate = self.get_success_rate(name)
            state = self.health_state.get(name, ModelHealth())
            recent_count = len(state.recent_results) if state.recent_results else 0
            # 至少要有 10 次请求才计算成功率
            if recent_count >= 10 and rate < min_rate:
                logger.warning(
                    f"模型 {name} 近期成功率过低: {rate:.1%} ({recent_count}次请求)，跳过"
                )
                continue
            passed.append(name)
        return passed if passed else model_names  # 如果全部过滤掉，返回原始列表

    def parse_reset_time_from_error(self, error_str: str) -> Optional[float]:
        """从错误信息中解析重置时间

        Args:
            error_str: 错误信息字符串

        Returns:
            重置时间的时间戳，如果没有找到返回 None
        """
        import re

        # 匹配 ISO 格式时间: 2026-06-05T15:00:00+08:00
        patterns = [
            r"resets? at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})",
            r"resets? at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)",
            r"resets? at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        ]

        for pattern in patterns:
            match = re.search(pattern, error_str, re.IGNORECASE)
            if match:
                time_str = match.group(1)
                try:
                    # 解析 ISO 格式时间
                    if "T" in time_str:
                        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                    else:
                        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    return dt.timestamp()
                except Exception as e:
                    logger.warning(f"解析时间失败: {time_str} - {e}")

        return None

    def handle_quota_error_with_reset(
        self, model_name: str, error_str: str, model_manager
    ):
        """处理带有重置时间的配额错误

        Args:
            model_name: 模型名称
            error_str: 错误信息
            model_manager: 模型管理器
        """
        reset_time = self.parse_reset_time_from_error(error_str)

        if reset_time:
            # 找到重置时间，设置定时重新启用
            self.set_re_enable_time(model_name, reset_time, error_str)
            model_manager.disable_model(model_name)

            from datetime import datetime

            reset_time_str = datetime.fromtimestamp(reset_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            logger.info(f"⏰ 模型 {model_name} 将在 {reset_time_str} 自动重新启用")
        else:
            # 没有找到重置时间，使用默认行为
            self.mark_unhealthy(model_name, error_str)
            model_manager.disable_model(model_name)

    def get_probe_ready_models(self, model_names: List[str]) -> List[str]:
        """返回准备好探测的模型列表

        Args:
            model_names: 所有可用模型名称列表

        Returns:
            准备好探测的模型名称列表
        """
        return [name for name in model_names if self.should_probe(name)]

    def is_rate_limit_error(self, error_str: str) -> bool:
        """检测是否是速率限制错误

        Args:
            error_str: 错误信息字符串

        Returns:
            True 表示是速率限制错误
        """
        normalized = error_str.lower()
        return any(
            pattern.lower() in normalized for pattern in self.RATE_LIMIT_PATTERNS
        )

    def is_api_error(self, error_str: str) -> bool:
        """检测是否是 API 错误

        Args:
            error_str: 错误信息字符串

        Returns:
            True 表示是 API 错误
        """
        return any(pattern in error_str for pattern in self.API_ERROR_PATTERNS)

    def is_quota_error(self, error_str: str) -> bool:
        """检测是否是额度/key 错误（需要禁用模型）

        Args:
            error_str: 错误信息字符串

        Returns:
            True 表示是额度/key 错误
        """
        normalized = error_str.lower()
        return any(
            pattern.lower() in normalized for pattern in self.QUOTA_ERROR_PATTERNS
        )

    def classify_error(self, error_str: str) -> Optional[str]:
        """分类错误类型

        Args:
            error_str: 错误信息字符串

        Returns:
            错误类型: "rate_limit", "quota_error", "api_error", 或 None
        """
        if self.is_rate_limit_error(error_str):
            return "rate_limit"
        if self.is_quota_error(error_str):
            return "quota_error"
        if self.is_api_error(error_str):
            return "api_error"
        return None

    def _format_time(self, timestamp: float) -> str:
        """格式化时间戳"""
        if timestamp <= 0:
            return "N/A"
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
