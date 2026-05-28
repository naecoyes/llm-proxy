"""时间控制器 - 管理模型使用时间策略"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class TimeController:
    """控制模型使用时间策略"""

    def __init__(self, config: dict):
        self.config = config
        self._update_config(config)

    def _update_config(self, config: dict):
        """更新配置"""
        schedule = config.get("schedule", {})
        timezone_str = schedule.get("timezone", "Asia/Shanghai")

        # 设置时区
        if timezone_str == "Asia/Shanghai":
            self.timezone = timezone(timedelta(hours=8))
        else:
            self.timezone = timezone.utc

        # 高峰期配置
        self.peak_hours = schedule.get("peak_hours", [[9, 12], [14, 18]])
        self.peak_strategy = schedule.get("peak_strategy", "minimax")
        self.peak_parallel_limit = schedule.get("peak_parallel_limit", 1)
        self.peak_skip_weekends = schedule.get("peak_skip_weekends", True)

        # mimo 优先时段
        self.mimo_priority_hours = schedule.get("mimo_priority_hours", [0, 1, 2, 3, 4, 5, 6, 7])

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._update_config(config)
        logger.info("时间控制器配置已更新")

    def get_current_time(self) -> datetime:
        """获取当前时区时间"""
        return datetime.now(self.timezone)

    def is_peak_hour(self, now: Optional[datetime] = None) -> bool:
        """检查当前是否高峰期"""
        now = now or self.get_current_time()

        # 周末检查
        if self.peak_skip_weekends and now.weekday() >= 5:
            return False

        # 检查是否在高峰期窗口内
        for start_hour, end_hour in self.peak_hours:
            if start_hour <= now.hour < end_hour:
                return True

        return False

    def is_mimo_priority_time(self, now: Optional[datetime] = None) -> bool:
        """检查当前是否 mimo 优先时段"""
        now = now or self.get_current_time()
        return now.hour in self.mimo_priority_hours

    def is_weekend(self, now: Optional[datetime] = None) -> bool:
        """检查当前是否周末"""
        now = now or self.get_current_time()
        return now.weekday() >= 5

    def get_current_strategy(self) -> str:
        """返回当前时段的模型选择策略

        Returns:
            "peak" - 高峰期，使用 peak_strategy 配置的模型
            "mimo_priority" - mimo 优先时段
            "normal" - 正常时段
        """
        now = self.get_current_time()

        # 1. 检查是否高峰期
        if self.is_peak_hour(now):
            return "peak"

        # 2. 检查是否 mimo 优先时段
        if self.is_mimo_priority_time(now):
            return "mimo_priority"

        # 3. 正常时段
        return "normal"

    def get_parallel_limit(self) -> int:
        """返回当前时段的并行限制"""
        if self.is_peak_hour():
            return self.peak_parallel_limit
        return 100  # 默认不限制

    def get_peak_end_time(self) -> Optional[datetime]:
        """获取当前高峰期结束时间"""
        now = self.get_current_time()

        if not self.is_peak_hour(now):
            return None

        for start_hour, end_hour in self.peak_hours:
            if start_hour <= now.hour < end_hour:
                return now.replace(hour=end_hour, minute=0, second=0, microsecond=0)

        return None

    def should_skip_model(self, model_name: str, model_config: dict, now: Optional[datetime] = None) -> bool:
        """检查模型是否在当前时段应该跳过

        Args:
            model_name: 模型名称
            model_config: 模型配置
            now: 当前时间

        Returns:
            True 表示应该跳过该模型
        """
        now = now or self.get_current_time()

        # peak_only 模型在非高峰期跳过
        if model_config.get("peak_only", False) and not self.is_peak_hour(now):
            return True

        return False

    def get_status(self) -> dict:
        """返回当前时间控制状态"""
        now = self.get_current_time()
        strategy = self.get_current_strategy()

        return {
            "current_time": now.isoformat(),
            "timezone": str(self.timezone),
            "strategy": strategy,
            "is_peak_hour": self.is_peak_hour(now),
            "is_mimo_priority": self.is_mimo_priority_time(now),
            "is_weekend": self.is_weekend(now),
            "parallel_limit": self.get_parallel_limit(),
            "peak_end_time": self.get_peak_end_time().isoformat() if self.get_peak_end_time() else None,
            "peak_hours": self.peak_hours,
            "mimo_priority_hours": self.mimo_priority_hours,
        }
