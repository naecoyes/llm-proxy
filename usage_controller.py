"""用量控制器 - 管理模型使用量和费用"""

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict
from functools import wraps

logger = logging.getLogger(__name__)


def synchronized_usage(method):
    """Serialize mutable usage and concurrency counters."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._state_lock:
            return method(self, *args, **kwargs)
    return wrapper

DEFAULT_INPUT_COST_PER_1M = 0.14
DEFAULT_OUTPUT_COST_PER_1M = 0.28
ZERO_COST_BILLING_MODES = {"free", "subscription", "prepaid", "token_plan", "token-plan"}


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
    active_requests: int = 0  # 当前正在处理的请求数

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
        self._state_lock = threading.RLock()

        # 使用量统计
        self.daily_stats: Dict[str, UsageStats] = defaultdict(UsageStats)
        self.monthly_stats: Dict[str, UsageStats] = defaultdict(UsageStats)
        self.model_stats: Dict[str, UsageStats] = defaultdict(UsageStats)

        # 4小时时段统计: {"0-3": {"total": UsageStats, "model_name": UsageStats}}
        self.hourly_stats: Dict[str, Dict[str, UsageStats]] = defaultdict(
            lambda: defaultdict(UsageStats)
        )

        # 速率限制状态 (每模型)
        self.rate_limit_states: Dict[str, RateLimitState] = defaultdict(RateLimitState)

        # 加载配置
        self._update_config(config)

        # 加载今日统计
        self.current_date = datetime.now().astimezone().strftime("%Y-%m-%d")
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
        self.model_configs = (config.get("models", {}) or {}).get("available", {}) or {}

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._update_config(config)
        logger.info("用量控制器配置已更新")

    def _get_daily_stats_file(self) -> Path:
        """获取今日统计文件路径"""
        return self.stats_dir / f"usage_{self.current_date}.json"

    def _get_monthly_stats_file(self) -> Path:
        """获取本月统计文件路径"""
        month = datetime.now().astimezone().strftime("%Y-%m")
        return self.stats_dir / f"usage_monthly_{month}.json"

    def _get_hour_slot(self, hour: int = None) -> str:
        """获取小时时段标签

        Args:
            hour: 小时数 (0-23)，默认为当前小时

        Returns:
            时段标签，如 "0", "1", "2", ..., "23"
        """
        if hour is None:
            hour = datetime.now().astimezone().hour
        return str(hour)

    def _load_daily_stats(self):
        """加载今日统计"""
        stats_file = self._get_daily_stats_file()
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    data = json.load(f)

                # 检查日期是否是今天
                file_date = data.get("date", "")
                today = self.current_date
                if file_date != today:
                    logger.info(
                        f"统计文件日期 ({file_date}) 不是今天 ({today})，跳过加载"
                    )
                    return

                for model_name, stats in data.get("models", {}).items():
                    self.model_stats[model_name] = UsageStats(**stats)
                self.daily_stats["total"] = UsageStats(**data.get("total", {}))

                # Keep the current hour too. Skipping it loses persisted usage
                # after a service restart and later saves a partial bucket.
                current_hour = datetime.now().astimezone().hour
                for slot, slot_data in data.get("hourly", {}).items():
                    slot_hour = int(slot)
                    if slot_hour <= current_hour:
                        for model_name, stats in slot_data.items():
                            self.hourly_stats[slot][model_name] = UsageStats(**stats)

                logger.info(f"已加载今日统计: {stats_file}")
            except Exception as e:
                logger.warning(f"加载统计文件失败: {e}")

    @synchronized_usage
    def _save_daily_stats(self):
        """保存今日统计"""
        stats_file = self._get_daily_stats_file()
        try:
            # 构建每小时数据
            hourly_data = {}
            for slot, models in self.hourly_stats.items():
                hourly_data[slot] = {
                    name: asdict(stats) for name, stats in models.items()
                }

            data = {
                "date": self.current_date,
                "total": asdict(self.daily_stats.get("total", UsageStats())),
                "models": {
                    name: asdict(stats) for name, stats in self.model_stats.items()
                },
                "hourly": hourly_data,
            }
            tmp_file = stats_file.with_suffix(".json.tmp")
            tmp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_file.replace(stats_file)
            try:
                from asset_database import get_asset_database

                get_asset_database().sync_usage_snapshot(data)
            except Exception as exc:
                logger.warning("SQLite usage mirror failed: %s", exc)
        except Exception as e:
            logger.warning(f"保存统计文件失败: {e}")

    def _ensure_current_day(self):
        """Roll in-memory daily limits and counters at local midnight."""
        today = datetime.now().astimezone().strftime("%Y-%m-%d")
        if today == self.current_date:
            return

        self._save_daily_stats()
        self.current_date = today
        self.daily_stats.clear()
        self.model_stats.clear()
        self.hourly_stats.clear()
        self.rate_limit_states.clear()
        self._load_daily_stats()
        logger.info(f"用量统计已切换到新日期: {today}")

    def check_budget(self, model_name: str) -> bool:
        """检查是否还有预算

        Returns:
            True 表示有预算，可以继续使用
        """
        self._ensure_current_day()

        # 检查每日预算
        total_stats = self.daily_stats.get("total", UsageStats())
        if total_stats.cost >= self.daily_budget:
            logger.warning(
                f"每日预算已用完: {total_stats.cost:.2f} / {self.daily_budget:.2f}"
            )
            return False

        # 检查每月预算
        monthly_total = self.monthly_stats.get("total", UsageStats())
        if monthly_total.cost >= self.monthly_budget:
            logger.warning(
                f"每月预算已用完: {monthly_total.cost:.2f} / {self.monthly_budget:.2f}"
            )
            return False

        # 检查每日 Token 限制
        if total_stats.tokens >= self.max_tokens_per_day:
            logger.warning(
                f"每日 Token 限制已达到: {total_stats.tokens} / {self.max_tokens_per_day}"
            )
            return False

        model_limits = self.per_model_limits.get(model_name, {})
        model_stats = self.model_stats.get(model_name, UsageStats())

        max_requests_per_day = int(model_limits.get("max_requests_per_day", 0) or 0)
        if (
            max_requests_per_day > 0
            and model_stats.requests >= max_requests_per_day
        ):
            logger.warning(
                f"模型 {model_name} 每日请求限制已达到: "
                f"{model_stats.requests} / {max_requests_per_day}"
            )
            return False

        max_tokens_per_day = int(model_limits.get("max_tokens_per_day", 0) or 0)
        if max_tokens_per_day > 0 and model_stats.tokens >= max_tokens_per_day:
            logger.warning(
                f"模型 {model_name} 每日 Token 限制已达到: "
                f"{model_stats.tokens} / {max_tokens_per_day}"
            )
            return False

        max_cost_per_day = float(model_limits.get("max_cost_per_day", 0) or 0)
        if max_cost_per_day > 0 and model_stats.cost >= max_cost_per_day:
            logger.warning(
                f"模型 {model_name} 每日费用限制已达到: "
                f"{model_stats.cost:.4f} / {max_cost_per_day:.4f}"
            )
            return False

        return True

    @synchronized_usage
    def check_rate_limit(self, model_name: str, *, log: bool = True) -> bool:
        """检查是否触发速率限制或并发限制

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
            if log:
                logger.warning(
                    f"模型 {model_name} 请求次数限制: {len(state.requests)} / {max_rpm}"
                )
            return True

        # 检查并发限制（当前正在处理的请求数）
        max_concurrent = limits.get("max_concurrent", 0)
        if max_concurrent > 0 and state.active_requests >= max_concurrent:
            if log:
                logger.warning(
                    f"模型 {model_name} 并发限制: {state.active_requests} / {max_concurrent}"
                )
            return True

        return False

    @synchronized_usage
    def acquire_model(self, model_name: str, force: bool = False) -> bool:
        """获取模型并发锁（请求开始时调用）

        Returns:
            True 获取成功，False 并发已满
        """
        limits = self.per_model_limits.get(model_name, {})
        max_concurrent = limits.get("max_concurrent", 0)
        state = self.rate_limit_states[model_name]

        if not force and max_concurrent > 0 and state.active_requests >= max_concurrent:
            logger.warning(
                f"模型 {model_name} 并发已满: {state.active_requests}/{max_concurrent}"
            )
            return False

        state.active_requests += 1
        logger.debug(f"模型 {model_name} 获取锁: {state.active_requests} 个活跃请求")
        return True

    @synchronized_usage
    def release_model(self, model_name: str):
        """释放模型并发锁（请求完成时调用）"""
        state = self.rate_limit_states[model_name]
        state.active_requests = max(0, state.active_requests - 1)
        logger.debug(f"模型 {model_name} 释放锁: {state.active_requests} 个活跃请求")

    @synchronized_usage
    def reset_active_requests(self, model_name: str | None = None) -> dict:
        """Reset runtime-only active request counters.

        These counters are intentionally in-memory. If a request is cancelled,
        the proxy process restarts mid-request, or a legacy retry path leaks a
        fallback slot, the counter can remain non-zero even when there is no
        active LLM process. This method is for operational recovery only and
        does not change token/cost usage statistics.
        """
        if model_name:
            state = self.rate_limit_states[model_name]
            previous = state.active_requests
            state.active_requests = 0
            logger.warning("重置模型活跃请求计数: %s %s -> 0", model_name, previous)
            return {"models": {model_name: previous}, "total_reset": previous}

        reset: dict[str, int] = {}
        total = 0
        for name, state in self.rate_limit_states.items():
            if state.active_requests:
                reset[name] = state.active_requests
                total += state.active_requests
                state.active_requests = 0
        if reset:
            logger.warning("重置全部模型活跃请求计数: %s", reset)
        return {"models": reset, "total_reset": total}

    def check_token_limit(self, token_count: int) -> bool:
        """检查单次请求 Token 是否超限

        Args:
            token_count: 请求的 Token 数量

        Returns:
            True 表示在限制内
        """
        if token_count > self.max_tokens_per_request:
            logger.warning(
                f"单次请求 Token 超限: {token_count} > {self.max_tokens_per_request}"
            )
            return False
        return True

    @synchronized_usage
    def record_usage(self, model_name: str, usage: dict):
        """记录使用量

        Args:
            model_name: 模型名称
            usage: 使用量数据，包含 prompt_tokens, completion_tokens, total_tokens, cost
        """
        self._ensure_current_day()

        input_tokens = usage.get("prompt_tokens", 0) or 0
        output_tokens = usage.get("completion_tokens", 0) or 0
        total_tokens = usage.get("total_tokens", 0) or 0
        cost = usage.get("cost", 0.0) or 0.0

        # 如果没有 total_tokens，计算一下
        if total_tokens == 0:
            total_tokens = input_tokens + output_tokens

        # Prefer per-model pricing when configured; otherwise use the default
        # DeepSeek V4 Flash-compatible estimate.
        if cost == 0.0:
            cost = self.estimate_cost(model_name, input_tokens, output_tokens)

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

    @synchronized_usage
    def get_usage_report(self) -> dict:
        """返回使用报告"""
        self._ensure_current_day()
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
            "history": {
                "7d": self._summarize_historical_stats(7),
                "30d": self._summarize_historical_stats(30),
                "total": self._summarize_all_historical_stats(),
            },
            "per_model": {
                name: {
                    "tokens": stats.tokens,
                    "cost": round(stats.cost, 4),
                    "requests": stats.requests,
                    "input_tokens": stats.input_tokens,
                    "output_tokens": stats.output_tokens,
                    "limits": self.per_model_limits.get(name, {}),
                    "budget_available": self.check_budget(name),
                }
                for name, stats in self.model_stats.items()
            },
        }

    def _summarize_historical_stats(self, days: int) -> dict:
        """Summarize saved usage files, with current in-memory day as source of truth."""
        historical = self._load_historical_stats(days)
        return self._summarize_usage_payload(historical, days=days)

    def _summarize_all_historical_stats(self) -> dict:
        """Summarize every saved daily usage file plus the current in-memory counters."""
        historical = {}
        for stats_file in self.stats_dir.glob("usage_*.json"):
            date_part = stats_file.stem.removeprefix("usage_")
            if len(date_part) != 10:
                continue
            try:
                date.fromisoformat(date_part)
                with open(stats_file, "r") as f:
                    historical[date_part] = json.load(f)
            except Exception as e:
                logger.warning(f"加载历史统计失败 {date_part}: {e}")
        return self._summarize_usage_payload(historical, days=None)

    def _summarize_usage_payload(self, historical: Dict[str, dict], days: int | None) -> dict:
        """Aggregate total usage from a date keyed usage payload."""
        today = self.current_date
        historical[today] = {
            "date": today,
            "total": asdict(self.daily_stats.get("total", UsageStats())),
            "models": {
                name: asdict(stats) for name, stats in self.model_stats.items()
            },
        }

        total = UsageStats()
        per_model: Dict[str, UsageStats] = defaultdict(UsageStats)
        dates = sorted(historical.keys())
        for data in historical.values():
            stats = data.get("total", {})
            total.tokens += int(stats.get("tokens") or 0)
            total.cost += float(stats.get("cost") or 0)
            total.requests += int(stats.get("requests") or 0)
            total.input_tokens += int(stats.get("input_tokens") or 0)
            total.output_tokens += int(stats.get("output_tokens") or 0)
            for model_name, model_payload in data.get("models", {}).items():
                model_stats = per_model[model_name]
                model_stats.tokens += int(model_payload.get("tokens") or 0)
                model_stats.cost += float(model_payload.get("cost") or 0)
                model_stats.requests += int(model_payload.get("requests") or 0)
                model_stats.input_tokens += int(model_payload.get("input_tokens") or 0)
                model_stats.output_tokens += int(model_payload.get("output_tokens") or 0)

        return {
            "days": days or len(dates),
            "days_with_data": len(dates),
            "start_date": dates[0] if dates else "",
            "end_date": dates[-1] if dates else "",
            "tokens": total.tokens,
            "input_tokens": total.input_tokens,
            "output_tokens": total.output_tokens,
            "requests": total.requests,
            "cost": round(total.cost, 4),
            "per_model": {
                name: {
                    "tokens": stats.tokens,
                    "input_tokens": stats.input_tokens,
                    "output_tokens": stats.output_tokens,
                    "requests": stats.requests,
                    "cost": round(stats.cost, 4),
                }
                for name, stats in per_model.items()
            },
        }

    def estimate_cost(self, model_name: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate marginal request cost from model billing metadata and token counts."""
        model_limits = self.per_model_limits.get(model_name, {}) or {}
        model_config = self.model_configs.get(model_name, {}) or {}
        if self._is_zero_marginal_cost(model_limits, model_config):
            return 0.0
        input_cost_per_1m = self._configured_price(
            model_limits,
            model_config,
            ("input_cost_per_1m", "prompt_cost_per_1m", "input_price", "prompt_price"),
            DEFAULT_INPUT_COST_PER_1M,
        )
        output_cost_per_1m = self._configured_price(
            model_limits,
            model_config,
            ("output_cost_per_1m", "completion_cost_per_1m", "output_price", "completion_price"),
            DEFAULT_OUTPUT_COST_PER_1M,
        )
        return (input_tokens * input_cost_per_1m / 1_000_000) + (
            output_tokens * output_cost_per_1m / 1_000_000
        )

    def _is_zero_marginal_cost(self, model_limits: dict, model_config: dict) -> bool:
        if bool(model_limits.get("free") or model_config.get("free")):
            return True
        billing_mode = str(
            model_limits.get("billing_mode")
            or model_limits.get("billing")
            or model_config.get("billing_mode")
            or model_config.get("billing")
            or ""
        ).strip().lower()
        return billing_mode in ZERO_COST_BILLING_MODES

    @staticmethod
    def _configured_price(model_limits: dict, model_config: dict, keys: tuple[str, ...], default: float) -> float:
        for source in (model_limits, model_config):
            for key in keys:
                value = source.get(key)
                if value is not None and value != "":
                    return float(value)
        return default

    @synchronized_usage
    def reset_daily_stats(self):
        """重置每日统计"""
        self._ensure_current_day()
        # 保存当前统计到历史文件
        self._save_daily_stats()

        # 重置
        self.daily_stats.clear()
        self.model_stats.clear()
        self.rate_limit_states.clear()

        logger.info("每日统计已重置")

    def get_status(self) -> dict:
        """返回用量控制状态"""
        self._ensure_current_day()
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
        today = datetime.now().astimezone()

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

    def get_trend_data(self, granularity: str = "4h", model: str = None, group_by: str = "provider") -> dict:
        """获取趋势数据

        Args:
            granularity: 时间粒度，"day" 或 "4h"
            model: 模型名称，None 表示全部
            group_by: "provider" aggregates configured providers, "model" keeps each model separate

        Returns:
            趋势数据
        """
        if granularity == "day":
            return self._get_daily_trend(model, group_by)
        else:
            return self._get_hourly_trend(model, group_by)

    def _get_hourly_trend(self, model: str = None, group_by: str = "provider") -> dict:
        hourly = {
            slot: {
                name: {
                    "requests": stats.requests,
                    "input_tokens": stats.input_tokens,
                    "output_tokens": stats.output_tokens,
                    "tokens": stats.tokens,
                }
                for name, stats in models.items()
            }
            for slot, models in self.hourly_stats.items()
        }
        return self.hourly_trend_from_history(hourly, model, group_by)

    def hourly_trend_from_history(
        self,
        hourly: dict[str, dict[str, dict]],
        model: str = None,
        group_by: str = "provider",
        *,
        current_hour: int | None = None,
    ) -> dict:
        """获取4小时粒度趋势数据（按 provider 聚合）

        Args:
            model: 模型名称，None 表示全部

        Returns:
            4小时趋势数据
        """
        # A future hour is not a zero-usage hour. Returning 12–23 as zero
        # caused the line to fall to zero after the current hour and made the
        # Activity chart look like a broken counter. Only expose hours that
        # have started in the server's local accounting day.
        if current_hour is None:
            current_hour = datetime.now().astimezone().hour
        current_hour = max(0, min(23, int(current_hour)))
        labels = self.HOUR_SLOTS[: current_hour + 1]
        datasets = []

        # 收集所有模型名称
        all_models = set()
        for slot_data in hourly.values():
            all_models.update(slot_data.keys())
        all_models.discard("total")

        # 确定要显示的模型
        if model:
            models_to_show = [model] if model in all_models else []
        else:
            models_to_show = sorted(all_models)

        series_data = {}  # series -> {provider, models, tokens, input, output, requests}

        for model_name in models_to_show:
            provider = self._get_provider_from_model(model_name)
            series_name = model_name if group_by == "model" else provider

            if series_name not in series_data:
                series_data[series_name] = {
                    "provider": provider,
                    "models": set(),
                    "tokens": [0] * len(labels),
                    "input_tokens": [0] * len(labels),
                    "output_tokens": [0] * len(labels),
                    "requests": [0] * len(labels),
                }
            series_data[series_name]["models"].add(model_name)

            for i, slot in enumerate(labels):
                slot_stats = (hourly.get(slot, {}) or {}).get(model_name, {})
                series_data[series_name]["tokens"][i] += int(slot_stats.get("tokens") or 0)
                series_data[series_name]["input_tokens"][i] += int(slot_stats.get("input_tokens") or 0)
                series_data[series_name]["output_tokens"][i] += int(slot_stats.get("output_tokens") or 0)
                series_data[series_name]["requests"][i] += int(slot_stats.get("requests") or 0)

        # 构建数据集
        for series_name, data in sorted(series_data.items()):
            datasets.append(
                {
                    "model": series_name,
                    "provider": data["provider"],
                    "models": sorted(data["models"]),
                    "tokens": data["tokens"],
                    "input_tokens": data["input_tokens"],
                    "output_tokens": data["output_tokens"],
                    "requests": data["requests"],
                }
            )

        return {
            "granularity": "4h",
            "group_by": group_by,
            "window": "today_to_current_hour",
            "current_hour": current_hour,
            "labels": labels,
            "datasets": datasets,
        }

    def _get_provider_from_model(self, model_name: str) -> str:
        """Return the provider for a model.

        Prefer the configured provider because newly added routes often have
        arbitrary display names. The keyword fallback keeps older persisted
        usage files readable even if the model was removed from config.
        """
        configured = (
            self.model_configs.get(model_name, {}).get("provider")
            or self.per_model_limits.get(model_name, {}).get("provider")
        )
        if configured:
            return str(configured).strip().lower()

        model_lower = model_name.lower()
        if "mimo" in model_lower or "xiaomi" in model_lower or "token-plan" in model_lower:
            return "xiaomi"
        elif "nvidia" in model_lower:
            return "nvidia"
        elif "openrouter" in model_lower or "or-" in model_lower:
            return "openrouter"
        elif "volcengine" in model_lower or "ark-code" in model_lower or "huoshan" in model_lower or "doubao" in model_lower:
            return "volcengine"
        elif "minimax" in model_lower:
            return "minimax"
        elif "siliconflow" in model_lower:
            return "siliconflow"
        elif "opencode" in model_lower:
            return "opencode-go"
        elif "deepseek" in model_lower:
            return "deepseek"
        elif "gpt" in model_lower or "openai-proxy" in model_lower:
            return "openai-proxy"
        elif "anyrouter" in model_lower:
            return "anyrouter"
        elif "hy3" in model_lower or "hunyuan" in model_lower or "tencent" in model_lower:
            return "hy3"
        else:
            return "other"

    def _get_daily_trend(self, model: str = None, group_by: str = "provider") -> dict:
        """获取天粒度趋势数据

        Args:
            model: 模型名称，None 表示全部

        Returns:
            天趋势数据
        """
        return self.daily_trend_from_history(self._load_historical_stats(30), model, group_by)

    def daily_trend_from_history(
        self,
        historical: dict[str, dict],
        model: str = None,
        group_by: str = "provider",
    ) -> dict:
        """Aggregate daily trend from SQLite or legacy JSON history."""

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

        series_data = {}  # series -> {provider, models, tokens, input, output, requests}

        for model_name in models_to_show:
            provider = self._get_provider_from_model(model_name)
            series_name = model_name if group_by == "model" else provider

            if series_name not in series_data:
                series_data[series_name] = {
                    "provider": provider,
                    "models": set(),
                    "tokens": [0] * len(dates),
                    "input_tokens": [0] * len(dates),
                    "output_tokens": [0] * len(dates),
                    "requests": [0] * len(dates),
                }
            series_data[series_name]["models"].add(model_name)

            for i, day_key in enumerate(dates):
                model_stats = historical[day_key].get("models", {}).get(model_name, {})
                series_data[series_name]["tokens"][i] += model_stats.get("tokens", 0)
                series_data[series_name]["input_tokens"][i] += model_stats.get(
                    "input_tokens", 0
                )
                series_data[series_name]["output_tokens"][i] += model_stats.get(
                    "output_tokens", 0
                )
                series_data[series_name]["requests"][i] += model_stats.get("requests", 0)

        # 构建数据集
        datasets = []
        for series_name, data in sorted(series_data.items()):
            datasets.append(
                {
                    "model": series_name,
                    "provider": data["provider"],
                    "models": sorted(data["models"]),
                    "tokens": data["tokens"],
                    "input_tokens": data["input_tokens"],
                    "output_tokens": data["output_tokens"],
                    "requests": data["requests"],
                }
            )

        return {
            "granularity": "day",
            "group_by": group_by,
            "labels": dates,
            "datasets": datasets,
        }
