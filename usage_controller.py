"""用量控制器 - 管理模型使用量和费用"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class UsageStats:
    """使用量统计"""
    tokens: int = 0
    cost: float = 0.0
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class RateLimitState:
    """速率限制状态"""
    requests: list = None
    tokens: list = None

    def __post_init__(self):
        self.requests = self.requests or []
        self.tokens = self.tokens or []


class UsageController:
    """控制模型用量和费用"""

    # 小时段标签
    HOUR_SLOTS = [str(h) for h in range(24)]

    def __init__(self, config: dict, stats_dir: str = "stats"):
        self.config = config
        self.stats_dir = Path(stats_dir)
        self.stats_dir.mkdir(parents=True, exist_ok=True)

        # 使用量统计
        self.daily_stats: Dict[str, UsageStats] = defaultdict(UsageStats)
        self.monthly_stats: Dict[str, UsageStats] = defaultdict(UsageStats)
        self.model_stats: Dict[str, UsageStats] = defaultdict(UsageStats)

        # 4小时时段统计: {"0-3": {"total": UsageStats, "model_name": UsageStats}}
        self.hourly_stats: Dict[str, Dict[str, UsageStats]] = defaultdict(lambda: defaultdict(UsageStats))

        # 速率限制状态 (每模型)
        self.rate_limit_states: Dict[str, RateLimitState] = defaultdict(RateLimitState)

        # 加载配置
        self._update_config(config)

        # 加载今日统计
        self._load_daily_stats()

    def _update_config(self, config: dict):
        """更新配置"""
        usage = config.get("usage", {})

        # Token 限制
        self.max_tokens_per_request = usage.get("max_tokens_per_request", 100000)
        self.max_tokens_per_day = usage.get("max_tokens_per_day", 5000000)

        # 费用限制
        self.daily_budget = usage.get("daily_budget", 50.0)
        self.monthly_budget = usage.get("monthly_budget", 500.0)

        # 每模型速率限制
        self.per_model_limits = usage.get("per_model_limits", {})

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._update_config(config)
        logger.info("用量控制器配置已更新")

    def _get_daily_stats_file(self) -> Path:
        """获取今日统计文件路径"""
        today = datetime.now().strftime("%Y-%m-%d")
        return self.stats_dir / f"usage_{today}.json"

    def _get_monthly_stats_file(self) -> Path:
        """获取本月统计文件路径"""
        month = datetime.now().strftime("%Y-%m")
        return self.stats_dir / f"usage_monthly_{month}.json"

    def _get_hour_slot(self, hour: int = None) -> str:
        """获取小时时段标签

        Args:
            hour: 小时数 (0-23)，默认为当前小时

        Returns:
            时段标签，如 "0", "1", "2", ..., "23"
        """
        if hour is None:
            hour = datetime.now().hour
        return str(hour)

    def _load_daily_stats(self):
        """加载今日统计"""
        stats_file = self._get_daily_stats_file()
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    data = json.load(f)
                for model_name, stats in data.get("models", {}).items():
                    self.model_stats[model_name] = UsageStats(**stats)
                self.daily_stats["total"] = UsageStats(**data.get("total", {}))

                # 加载每小时数据
                for slot, slot_data in data.get("hourly", {}).items():
                    for model_name, stats in slot_data.items():
                        self.hourly_stats[slot][model_name] = UsageStats(**stats)

                logger.info(f"已加载今日统计: {stats_file}")
            except Exception as e:
                logger.warning(f"加载统计文件失败: {e}")

    def _save_daily_stats(self):
        """保存今日统计"""
        stats_file = self._get_daily_stats_file()
        try:
            # 构建每小时数据
            hourly_data = {}
            for slot, models in self.hourly_stats.items():
                hourly_data[slot] = {name: asdict(stats) for name, stats in models.items()}

            data = {
                "date": datetime.now().strftime("%Y-%m-%d"),
                "total": asdict(self.daily_stats.get("total", UsageStats())),
                "models": {name: asdict(stats) for name, stats in self.model_stats.items()},
                "hourly": hourly_data,
            }
            with open(stats_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"保存统计文件失败: {e}")

    def check_budget(self, model_name: str) -> bool:
        """检查是否还有预算

        Returns:
            True 表示有预算，可以继续使用
        """
        # 检查每日预算
        total_stats = self.daily_stats.get("total", UsageStats())
        if total_stats.cost >= self.daily_budget:
            logger.warning(f"每日预算已用完: {total_stats.cost:.2f} / {self.daily_budget:.2f}")
            return False

        # 检查每月预算
        monthly_total = self.monthly_stats.get("total", UsageStats())
        if monthly_total.cost >= self.monthly_budget:
            logger.warning(f"每月预算已用完: {monthly_total.cost:.2f} / {self.monthly_budget:.2f}")
            return False

        # 检查每日 Token 限制
        if total_stats.tokens >= self.max_tokens_per_day:
            logger.warning(f"每日 Token 限制已达到: {total_stats.tokens} / {self.max_tokens_per_day}")
            return False

        return True

    def check_rate_limit(self, model_name: str) -> bool:
        """检查是否触发速率限制

        Returns:
            True 表示触发了限制，应该等待或切换模型
        """
        limits = self.per_model_limits.get(model_name, {})
        if not limits:
            return False

        now = time.time()
        state = self.rate_limit_states[model_name]

        # 清理过期记录 (保留最近1分钟)
        state.requests = [t for t in state.requests if now - t < 60]
        state.tokens = [t for t in state.tokens if now - t < 60]

        # 检查请求次数限制
        max_rpm = limits.get("max_requests_per_minute", 0)
        if max_rpm > 0 and len(state.requests) >= max_rpm:
            logger.warning(f"模型 {model_name} 请求次数限制: {len(state.requests)} / {max_rpm}")
            return True

        return False

    def check_token_limit(self, token_count: int) -> bool:
        """检查单次请求 Token 是否超限

        Args:
            token_count: 请求的 Token 数量

        Returns:
            True 表示在限制内
        """
        if token_count > self.max_tokens_per_request:
            logger.warning(f"单次请求 Token 超限: {token_count} > {self.max_tokens_per_request}")
            return False
        return True

    def record_usage(self, model_name: str, usage: dict):
        """记录使用量

        Args:
            model_name: 模型名称
            usage: 使用量数据，包含 prompt_tokens, completion_tokens, total_tokens, cost
        """
        input_tokens = usage.get("prompt_tokens", 0) or 0
        output_tokens = usage.get("completion_tokens", 0) or 0
        total_tokens = usage.get("total_tokens", 0) or 0
        cost = usage.get("cost", 0.0) or 0.0

        # 如果没有 total_tokens，计算一下
        if total_tokens == 0:
            total_tokens = input_tokens + output_tokens

        # 更新每日统计
        total_stats = self.daily_stats.setdefault("total", UsageStats())
        total_stats.tokens += total_tokens
        total_stats.cost += cost
        total_stats.requests += 1
        total_stats.input_tokens += input_tokens
        total_stats.output_tokens += output_tokens

        # 更新每月统计
        monthly_total = self.monthly_stats.setdefault("total", UsageStats())
        monthly_total.tokens += total_tokens
        monthly_total.cost += cost
        monthly_total.requests += 1
        monthly_total.input_tokens += input_tokens
        monthly_total.output_tokens += output_tokens

        # 更新模型统计
        model_stat = self.model_stats.setdefault(model_name, UsageStats())
        model_stat.tokens += total_tokens
        model_stat.cost += cost
        model_stat.requests += 1
        model_stat.input_tokens += input_tokens
        model_stat.output_tokens += output_tokens

        # 更新4小时时段统计
        hour_slot = self._get_hour_slot()
        slot_total = self.hourly_stats[hour_slot].setdefault("total", UsageStats())
        slot_total.tokens += total_tokens
        slot_total.cost += cost
        slot_total.requests += 1
        slot_total.input_tokens += input_tokens
        slot_total.output_tokens += output_tokens

        slot_model = self.hourly_stats[hour_slot].setdefault(model_name, UsageStats())
        slot_model.tokens += total_tokens
        slot_model.cost += cost
        slot_model.requests += 1
        slot_model.input_tokens += input_tokens
        slot_model.output_tokens += output_tokens

        # 更新速率限制状态
        now = time.time()
        state = self.rate_limit_states[model_name]
        state.requests.append(now)
        state.tokens.append(total_tokens)

        # 定期保存统计
        if total_stats.requests % 10 == 0:
            self._save_daily_stats()

        logger.debug(
            f"记录使用量: {model_name} | tokens={total_tokens} | cost=${cost:.4f} | "
            f"total_today={total_stats.tokens} tokens, ${total_stats.cost:.4f}"
        )

    def get_usage_report(self) -> dict:
        """返回使用报告"""
        total_stats = self.daily_stats.get("total", UsageStats())
        monthly_total = self.monthly_stats.get("total", UsageStats())

        return {
            "daily": {
                "tokens": total_stats.tokens,
                "cost": round(total_stats.cost, 4),
                "requests": total_stats.requests,
                "input_tokens": total_stats.input_tokens,
                "output_tokens": total_stats.output_tokens,
                "budget_limit": self.daily_budget,
                "budget_remaining": round(self.daily_budget - total_stats.cost, 4),
                "token_limit": self.max_tokens_per_day,
                "tokens_remaining": self.max_tokens_per_day - total_stats.tokens,
            },
            "monthly": {
                "tokens": monthly_total.tokens,
                "cost": round(monthly_total.cost, 4),
                "requests": monthly_total.requests,
                "budget_limit": self.monthly_budget,
                "budget_remaining": round(self.monthly_budget - monthly_total.cost, 4),
            },
            "per_model": {
                name: {
                    "tokens": stats.tokens,
                    "cost": round(stats.cost, 4),
                    "requests": stats.requests,
                }
                for name, stats in self.model_stats.items()
            },
        }

    def reset_daily_stats(self):
        """重置每日统计"""
        # 保存当前统计到历史文件
        self._save_daily_stats()

        # 重置
        self.daily_stats.clear()
        self.model_stats.clear()
        self.rate_limit_states.clear()

        logger.info("每日统计已重置")

    def get_status(self) -> dict:
        """返回用量控制状态"""
        total_stats = self.daily_stats.get("total", UsageStats())

        return {
            "daily_budget": self.daily_budget,
            "daily_cost": round(total_stats.cost, 4),
            "daily_budget_remaining": round(self.daily_budget - total_stats.cost, 4),
            "daily_tokens": total_stats.tokens,
            "daily_requests": total_stats.requests,
            "max_tokens_per_request": self.max_tokens_per_request,
            "max_tokens_per_day": self.max_tokens_per_day,
            "monthly_budget": self.monthly_budget,
        }

    def _load_historical_stats(self, days: int = 30) -> Dict[str, dict]:
        """加载历史统计数据

        Args:
            days: 加载最近几天的数据

        Returns:
            日期 -> 数据 的字典
        """
        result = {}
        today = datetime.now()

        for i in range(days):
            date = today - timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            stats_file = self.stats_dir / f"usage_{date_str}.json"

            if stats_file.exists():
                try:
                    with open(stats_file, "r") as f:
                        result[date_str] = json.load(f)
                except Exception as e:
                    logger.warning(f"加载历史统计失败 {date_str}: {e}")

        return result

    def get_trend_data(self, granularity: str = "4h", model: str = None) -> dict:
        """获取趋势数据

        Args:
            granularity: 时间粒度，"day" 或 "4h"
            model: 模型名称，None 表示全部

        Returns:
            趋势数据
        """
        if granularity == "day":
            return self._get_daily_trend(model)
        else:
            return self._get_hourly_trend(model)

    def _get_hourly_trend(self, model: str = None) -> dict:
        """获取4小时粒度趋势数据

        Args:
            model: 模型名称，None 表示全部

        Returns:
            4小时趋势数据
        """
        labels = self.HOUR_SLOTS
        datasets = []

        # 收集所有模型名称
        all_models = set()
        for slot_data in self.hourly_stats.values():
            all_models.update(slot_data.keys())
        all_models.discard("total")

        # 确定要显示的模型
        if model:
            models_to_show = [model] if model in all_models else []
        else:
            models_to_show = sorted(all_models)

        # 构建数据集
        for model_name in models_to_show:
            tokens_data = []
            input_data = []
            output_data = []
            requests_data = []

            for slot in labels:
                slot_stats = self.hourly_stats.get(slot, {}).get(model_name, UsageStats())
                tokens_data.append(slot_stats.tokens)
                input_data.append(slot_stats.input_tokens)
                output_data.append(slot_stats.output_tokens)
                requests_data.append(slot_stats.requests)

            datasets.append({
                "model": model_name,
                "tokens": tokens_data,
                "input_tokens": input_data,
                "output_tokens": output_data,
                "requests": requests_data,
            })

        return {
            "granularity": "4h",
            "labels": labels,
            "datasets": datasets,
        }

    def _get_daily_trend(self, model: str = None) -> dict:
        """获取天粒度趋势数据

        Args:
            model: 模型名称，None 表示全部

        Returns:
            天趋势数据
        """
        # 加载历史数据
        historical = self._load_historical_stats(30)

        # 按日期排序
        dates = sorted(historical.keys())

        # 收集所有模型名称
        all_models = set()
        for data in historical.values():
            all_models.update(data.get("models", {}).keys())

        # 确定要显示的模型
        if model:
            models_to_show = [model] if model in all_models else []
        else:
            models_to_show = sorted(all_models)

        # 构建数据集
        datasets = []
        for model_name in models_to_show:
            tokens_data = []
            input_data = []
            output_data = []
            requests_data = []

            for date in dates:
                model_stats = historical[date].get("models", {}).get(model_name, {})
                tokens_data.append(model_stats.get("tokens", 0))
                input_data.append(model_stats.get("input_tokens", 0))
                output_data.append(model_stats.get("output_tokens", 0))
                requests_data.append(model_stats.get("requests", 0))

            datasets.append({
                "model": model_name,
                "tokens": tokens_data,
                "input_tokens": input_data,
                "output_tokens": output_data,
                "requests": requests_data,
            })

        return {
            "granularity": "day",
            "labels": dates,
            "datasets": datasets,
        }
