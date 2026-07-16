"""模型管理器 - 模型选择和路由"""

import logging
import os
import random
import tempfile
import time
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from health_checker import HealthChecker
from time_controller import TimeController
from usage_controller import UsageController

logger = logging.getLogger(__name__)


def supports_native_reasoning(provider: str, model: str) -> bool:
    """Return known native reasoning support without guessing for every model."""
    normalized_provider = str(provider or "").strip().lower()
    normalized_model = str(model or "").strip().lower()
    if normalized_provider == "deepseek":
        return True
    if normalized_provider != "openrouter":
        return False

    # Keep this intentionally narrow. Unknown OpenRouter models must be opted
    # in by an operator after their provider contract is confirmed.
    return normalized_model.removeprefix("openrouter/") == "tencent/hy3:free"


def supports_vision_assist(provider: str, model: str) -> bool:
    """Return known image-input support without guessing for every model."""
    normalized_provider = str(provider or "").strip().lower()
    normalized_model = str(model or "").strip().lower().removeprefix("openrouter/")
    return normalized_provider == "openrouter" and normalized_model == "tencent/hy3:free"


def default_reasoning_api(provider: str, model: str, supported: bool) -> str:
    """Select the request contract for a model that has native reasoning."""
    if not supported:
        return "none"
    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider == "deepseek":
        return "deepseek"
    if normalized_provider == "openrouter":
        return "openrouter"
    return "openai"


@dataclass
class ModelConfig:
    """模型配置"""

    name: str
    model: str
    api_key: str
    api_base: str
    provider: str = ""
    priority: int = 100
    enabled: bool = True
    peak_only: bool = False
    free: bool = False
    label: str = ""
    api_format: str = "openai"  # openai 或 anthropic
    is_exact_url: bool = False
    custom_headers: dict = field(default_factory=dict)
    strip_provider_prefix: bool = True
    no_auto_disable: bool = False
    routing_tier: str = "standard"
    allowed_scan_modes: list = field(default_factory=list)
    quota_policy: dict = field(default_factory=dict)
    max_context_tokens: int = 0
    reasoning_supported: bool = False
    reasoning_api: str = "none"
    thinking_enabled: bool = False
    reasoning_effort: str = "high"
    vision_supported: bool = False
    vision_assist_enabled: bool = False


class NoAvailableModelError(Exception):
    """没有可用的模型"""

    pass


class ModelManager:
    """模型选择和路由"""

    AUTO_REENABLE_SECONDS = 1800  # 30 分钟后自动重新启用
    ROUTING_MODES = {"balanced_all", "priority"}

    def __init__(self, config: dict, stats_dir: str = "stats"):
        self.config = config
        self.config_path: Optional[str] = None
        self.models: Dict[str, ModelConfig] = {}
        self.disabled_models: set = set()
        self.disabled_until: Dict[str, float] = {}  # model_name -> re-enable timestamp
        self.providers: Dict[str, dict] = {}
        self._round_robin_counter = 0  # 轮询计数器
        self._active_models: set = set()  # 当前正在使用的模型
        self._active_models_lock = __import__("threading").Lock()
        self._slot_model_map: Dict[int, str] = {}  # slot -> model_name 固定分配
        self._slot_model_lock = __import__("threading").Lock()
        self._select_lock = __import__("threading").Lock()  # 选择+获取锁的原子操作

        self._available_cache: Optional[List[str]] = None
        self._available_cache_ts: float = 0

        # 初始化子控制器
        self.time_controller = TimeController(config)
        self.usage_controller = UsageController(config, stats_dir)
        self.health_checker = HealthChecker(config, stats_dir, self)

        # 加载配置
        self._load_providers(config)
        self._load_models(config)

    def _load_providers(self, config: dict):
        """加载 provider 分组配置"""
        self.providers = config.get("providers", {})
        logger.info(f"加载 provider 配置: {list(self.providers.keys())}")

    def _load_models(self, config: dict):
        """加载模型配置"""
        models_config = config.get("models", {}).get("available", {})

        # 清除不在配置中的模型
        models_to_remove = [name for name in self.models if name not in models_config]
        for name in models_to_remove:
            del self.models[name]
            logger.info(f"移除模型: {name}")

        self.disabled_models.clear()

        for name, model_conf in models_config.items():
            enabled = model_conf.get("enabled", True)
            provider = str(model_conf.get("provider") or "")
            configured_support = model_conf.get("reasoning_supported")
            reasoning_supported = (
                bool(configured_support)
                if configured_support is not None
                else supports_native_reasoning(provider, model_conf.get("model", ""))
            )
            configured_vision = model_conf.get("vision_supported")
            vision_supported = (
                bool(configured_vision)
                if configured_vision is not None
                else supports_vision_assist(provider, model_conf.get("model", ""))
            )

            model = ModelConfig(
                name=name,
                model=model_conf.get("model", ""),
                api_key=model_conf.get("api_key", ""),
                api_base=model_conf.get("api_base", ""),
                provider=provider,
                priority=model_conf.get("priority", 100),
                enabled=enabled,
                peak_only=model_conf.get("peak_only", False),
                free=model_conf.get("free", False),
                label=model_conf.get("label", ""),
                api_format=model_conf.get("api_format", "openai"),
                is_exact_url=model_conf.get("is_exact_url", False),
                custom_headers=model_conf.get("custom_headers", {}),
                strip_provider_prefix=model_conf.get("strip_provider_prefix", True),
                no_auto_disable=model_conf.get("no_auto_disable", False),
                routing_tier=model_conf.get("routing_tier", "standard"),
                allowed_scan_modes=model_conf.get("allowed_scan_modes", []),
                quota_policy=model_conf.get("quota_policy", {}),
                max_context_tokens=int(
                    model_conf.get("max_context_tokens")
                    or model_conf.get("context_window")
                    or 0
                ),
                reasoning_supported=reasoning_supported,
                reasoning_api=str(
                    model_conf.get("reasoning_api")
                    or default_reasoning_api(
                        provider, model_conf.get("model", ""), reasoning_supported
                    )
                ).lower(),
                # Native-capable models default to high reasoning. Unknown
                # providers remain opt-in until an operator confirms support.
                thinking_enabled=bool(
                    model_conf.get(
                        "thinking_enabled",
                        reasoning_supported,
                    )
                ),
                reasoning_effort=str(model_conf.get("reasoning_effort") or "high").lower(),
                vision_supported=vision_supported,
                vision_assist_enabled=bool(
                    model_conf.get("vision_assist_enabled", False)
                ),
            )

            self.models[name] = model
            self.health_checker.initialize_model(name)

            # 如果配置中enabled为false，添加到disabled_models
            if not enabled:
                self.disabled_models.add(name)

            logger.info(
                f"加载模型: {name} | {model.model} | provider: {model.provider} | 优先级: {model.priority} | {'启用' if enabled else '禁用'}"
            )

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._available_cache = None
        self._available_cache_ts = 0
        self._load_providers(config)
        self._load_models(config)
        self.time_controller.update_config(config)
        self.usage_controller.update_config(config)
        self.health_checker.update_config(config)
        # 清除 slot 分配缓存，强制重新分配
        with self._select_lock:
            self._slot_model_map.clear()
        logger.info("模型管理器配置已更新，slot 分配已重置")

    def _get_available_models(self) -> List[str]:
        """获取所有可用模型名称（自动重试已过冷却期的模型，自动禁用低成功率模型，带30秒缓存）"""
        import time as _time

        now = _time.time()
        
        # 检查缓存（30秒刷新一次）
        if self._available_cache is not None and (now - self._available_cache_ts < 30):
            return self._available_cache

        # 检查是否有模型需要自动重新启用
        to_reenable = [
            name
            for name, until in self.disabled_until.items()
            if until and now >= until
        ]
        for name in to_reenable:
            logger.info(f"模型 {name} 冷却期已过，自动重新启用")
            self.enable_model(name)

        # 检查成功率过低的模型，自动禁用
        for name, model in list(self.models.items()):
            if name in self.disabled_models or not model.enabled:
                continue
            if model.no_auto_disable:
                continue
            if self.health_checker.should_auto_disable(
                name, min_requests=20, min_rate=0.5
            ):
                rate = self.health_checker.get_success_rate(name)
                logger.warning(f"模型 {name} 成功率过低 ({rate:.1%})，自动禁用")
                self.disable_model(name)

        result = [
            name
            for name, model in self.models.items()
            if name not in self.disabled_models and model.enabled
        ]
        
        self._available_cache = result
        self._available_cache_ts = now
        return result

    def get_model_routing_status(
        self, model_name: str, routing_context: Optional[dict] = None
    ) -> dict[str, Any]:
        """Return whether a model may participate in automatic routing."""
        model = self.models.get(model_name)
        if not model:
            return {"eligible": False, "reason": "model_not_found"}

        health_state = self.health_checker.health_state.get(model_name)
        health_reason = health_state.reason if health_state else ""
        health_next_probe_at = health_state.next_probe_at if health_state else 0.0
        if not model.enabled or model_name in self.disabled_models:
            return {
                "eligible": False,
                "reason": "disabled",
                "health_reason": health_reason,
                "health_next_probe_at": health_next_probe_at,
            }
        if model.vision_assist_enabled and not bool(
            (routing_context or {}).get("vision_assist")
        ):
            return {
                "eligible": False,
                "reason": "vision_assist_only",
                "vision_supported": model.vision_supported,
            }
        if not self.health_checker.is_healthy(model_name):
            circuit_state = health_state.circuit_state if health_state else ""
            return {
                "eligible": False,
                "reason": "network_cooldown" if circuit_state == "open" else "unhealthy",
                "health_reason": health_reason,
                "health_next_probe_at": health_next_probe_at,
                "circuit_state": circuit_state,
                "cooldown_until": health_state.cooldown_until if health_state else 0.0,
            }
        if not self.usage_controller.check_budget(model_name):
            return {
                "eligible": False,
                "reason": "budget_limit_reached",
                "health_reason": health_reason,
            }
        if self.usage_controller.check_rate_limit(model_name, log=False):
            return {
                "eligible": False,
                "reason": "rate_or_concurrency_limited",
                "health_reason": health_reason,
            }

        is_vision_assist = bool((routing_context or {}).get("vision_assist"))
        scan_mode = str((routing_context or {}).get("scan_mode") or "").lower()
        allowed_modes = [str(mode).lower() for mode in model.allowed_scan_modes]
        if model.routing_tier == "reserve" and not scan_mode and not is_vision_assist:
            return {
                "eligible": False,
                "reason": "scan_mode_required",
                "scan_mode": scan_mode,
                "allowed_scan_modes": allowed_modes,
            }
        if allowed_modes and scan_mode not in allowed_modes and not is_vision_assist:
            reason = "scan_mode_not_allowed" if scan_mode else "scan_mode_required"
            return {
                "eligible": False,
                "reason": reason,
                "scan_mode": scan_mode,
                "allowed_scan_modes": allowed_modes,
            }

        required_context = int(
            (routing_context or {}).get("required_context_tokens")
            or (32768 if scan_mode == "redteam" else 0)
            or 0
        )
        if model.max_context_tokens and required_context and model.max_context_tokens < required_context:
            return {
                "eligible": False,
                "reason": "context_window_too_small",
                "scan_mode": scan_mode,
                "allowed_scan_modes": allowed_modes,
                "required_context_tokens": required_context,
                "max_context_tokens": model.max_context_tokens,
                "thinking_enabled": model.thinking_enabled,
                "reasoning_effort": model.reasoning_effort,
                "reasoning_supported": model.reasoning_supported,
                "reasoning_api": model.reasoning_api,
            }

        quota_policy = model.quota_policy or {}
        auto_disable_at = float(quota_policy.get("auto_disable_at_percent", 100))
        usage_values = [
            float(quota_policy.get(key, 0) or 0)
            for key in (
                "current_period_percent",
                "weekly_percent",
                "monthly_percent",
            )
        ]
        highest_usage = max(usage_values, default=0.0)
        if quota_policy.get("limited", False) and highest_usage >= auto_disable_at:
            return {
                "eligible": False,
                "reason": "quota_soft_limit_reached",
                "usage_percent": highest_usage,
                "auto_disable_at_percent": auto_disable_at,
                "allowed_scan_modes": allowed_modes,
            }

        return {
            "eligible": True,
            "reason": "",
            "scan_mode": scan_mode,
            "allowed_scan_modes": allowed_modes,
            "health_reason": health_reason,
            "health_next_probe_at": health_next_probe_at,
            "usage_percent": highest_usage,
            "auto_disable_at_percent": auto_disable_at,
            "max_context_tokens": model.max_context_tokens,
            "required_context_tokens": required_context,
        }

    def _filter_by_routing_policy(
        self, model_names: List[str], routing_context: Optional[dict]
    ) -> List[str]:
        """Filter automatic candidates by scan mode and plan quota policy."""
        return [
            name
            for name in model_names
            if self.get_model_routing_status(name, routing_context)["eligible"]
        ]

    def get_vision_assist_candidates(self) -> list[dict[str, Any]]:
        """Return dedicated image assistants available to the dashboard."""
        candidates: list[dict[str, Any]] = []
        for name, model in self.models.items():
            if not model.vision_supported or not model.vision_assist_enabled:
                continue
            health = self.health_checker.health_state.get(name)
            enabled = model.enabled and name not in self.disabled_models
            healthy = enabled and self.health_checker.is_healthy(name)
            candidates.append(
                {
                    "name": name,
                    "model": model.model,
                    "provider": model.provider,
                    "enabled": enabled,
                    "healthy": healthy,
                    "reason": "" if healthy else (health.reason if health else "disabled"),
                }
            )
        return sorted(candidates, key=lambda item: item["name"])

    def select_vision_assist_model(
        self, requested_model: str
    ) -> tuple[str, ModelConfig]:
        """Reserve one configured image assistant without automatic fallback."""
        with self._select_lock:
            model = self.models.get(requested_model)
            if not model:
                raise NoAvailableModelError(
                    "Configured vision assist model was not found"
                )
            if not model.vision_supported or not model.vision_assist_enabled:
                raise NoAvailableModelError(
                    "Configured vision assist model is not enabled"
                )
            status = self.get_model_routing_status(
                requested_model, {"vision_assist": True}
            )
            if not status.get("eligible"):
                raise NoAvailableModelError(
                    f"Vision assist model unavailable: {status.get('reason', 'unknown')}"
                )
            if not self.usage_controller.acquire_model(requested_model):
                raise NoAvailableModelError(
                    "Vision assist model concurrency is full"
                )
            return requested_model, model

    def _get_provider_models(self, provider: str) -> List[str]:
        """获取指定 provider 的所有模型名称"""
        return [
            name
            for name, model in self.models.items()
            if model.provider == provider
            and name not in self.disabled_models
            and model.enabled
        ]

    def _get_same_provider_fallbacks(self, model_name: str) -> List[str]:
        """获取同 provider 的备用模型列表

        Args:
            model_name: 当前模型名称

        Returns:
            同 provider 的其他可用模型列表（按优先级排序）
        """
        model = self.models.get(model_name)
        if not model or not model.provider:
            return []

        # 从 providers 配置获取 fallback 列表
        provider_config = self.providers.get(model.provider, {})
        fallback_models = provider_config.get("fallback_models", [])

        # 过滤掉当前模型和不可用的模型
        available_fallbacks = [
            name
            for name in fallback_models
            if name != model_name
            and name in self.models
            and name not in self.disabled_models
            and self.models[name].enabled
        ]

        # 按优先级排序
        return self._sort_by_priority(available_fallbacks)

    def _get_free_models(self) -> List[str]:
        """获取所有免费模型列表"""
        return [
            name
            for name, model in self.models.items()
            if model.free and name not in self.disabled_models and model.enabled
        ]

    def _filter_by_time(self, model_names: List[str]) -> List[str]:
        """根据时间策略过滤模型"""
        now = self.time_controller.get_current_time()
        strategy = self.time_controller.get_current_strategy()

        result = []
        for name in model_names:
            model = self.models.get(name)
            if not model:
                continue

            # 检查是否应该跳过该模型
            if self.time_controller.should_skip_model(
                name, {"peak_only": model.peak_only}, now
            ):
                logger.debug(f"跳过模型 {name}: peak_only 模型在非高峰期")
                continue

            result.append(name)

        # 如果是高峰期，优先使用 peak_strategy 模型
        if strategy == "peak":
            peak_model = self.time_controller.peak_strategy
            if peak_model in result:
                result = [peak_model] + [n for n in result if n != peak_model]

        # 如果是 mimo 优先时段，优先使用 mimo 模型
        if strategy == "mimo_priority":
            mimo_models = [n for n in result if "mimo" in n.lower()]
            if mimo_models:
                result = mimo_models + [n for n in result if n not in mimo_models]

        return result

    def _filter_by_health(self, model_names: List[str]) -> Tuple[List[str], List[str]]:
        """根据健康状态过滤模型"""
        healthy = []
        probe_ready = []

        for name in model_names:
            if self.health_checker.is_healthy(name):
                healthy.append(name)
            elif self.health_checker.should_probe(name):
                probe_ready.append(name)

        return healthy, probe_ready

    def _filter_by_budget(self, model_names: List[str]) -> List[str]:
        """根据预算过滤模型"""
        return [
            name for name in model_names if self.usage_controller.check_budget(name)
        ]

    def _filter_by_rate_limit(self, model_names: List[str]) -> List[str]:
        """过滤掉触发速率限制的模型"""
        return [
            name
            for name in model_names
            if not self.usage_controller.check_rate_limit(name)
        ]

    def _sort_by_priority(self, model_names: List[str]) -> List[str]:
        """按优先级排序（考虑 off-peak 时段动态优先级）"""

        def get_priority(name: str) -> int:
            model = self.models.get(name)
            if not model:
                return 999
            # 使用 time_controller 获取动态优先级
            return self.time_controller.get_model_priority(name, model.priority)

        return sorted(model_names, key=get_priority)

    def get_routing_mode(self) -> str:
        """Return the configured automatic routing mode."""
        mode = str(self.config.get("models", {}).get("routing_mode", "balanced_all"))
        return mode if mode in self.ROUTING_MODES else "balanced_all"

    def set_routing_mode(self, mode: str):
        """Update automatic routing without changing individual model switches."""
        if mode not in self.ROUTING_MODES:
            raise ValueError(f"Unsupported routing mode: {mode}")
        self.config.setdefault("models", {})["routing_mode"] = mode
        with self._select_lock:
            self._slot_model_map.clear()
        logger.info("模型路由模式已更新: %s", mode)

    def select_model(
        self, requested_model: str = None, routing_context: Optional[dict] = None
    ) -> Tuple[str, ModelConfig]:
        """选择最优模型

        Args:
            requested_model: 请求的模型名称（可选）
                - "auto": round-robin 轮询
                - "auto1", "auto2", "auto3": 固定分配到对应序号的模型
                - 具体模型名: 直接使用该模型

        Returns:
            (模型名称, 模型配置)

        Raises:
            NoAvailableModelError: 没有可用的模型
        """
        with self._select_lock:
            return self._do_select_model(requested_model, routing_context)

    def _do_select_model(
        self, requested_model: str = None, routing_context: Optional[dict] = None
    ) -> Tuple[str, ModelConfig]:
        """内部模型选择逻辑（需在 _select_lock 下调用）"""
        # 支持 auto1, auto2, auto3 等固定分配
        if (
            requested_model
            and requested_model.startswith("auto")
            and requested_model != "auto"
        ):
            try:
                slot = int(requested_model[4:])  # 提取 auto 后面的数字
                name, config = self._select_by_slot(slot, routing_context)
                if not self.usage_controller.acquire_model(name):
                    self._slot_model_map.pop(slot, None)
                    raise NoAvailableModelError(f"模型 {name} 并发已满，请稍后重试")
                return name, config
            except (ValueError, IndexError):
                pass

        # 如果指定了模型，尝试使用它
        if requested_model and requested_model != "auto":
            # 直接匹配配置名称
            if (
                requested_model in self.models
                and requested_model not in self.disabled_models
            ):
                model = self.models[requested_model]
                if model.enabled and self.get_model_routing_status(
                    requested_model, routing_context
                )["eligible"]:
                    if not self.usage_controller.acquire_model(requested_model):
                        raise NoAvailableModelError(f"模型 {requested_model} 并发已满，请稍后重试")
                    return requested_model, model

            # 尝试匹配模型ID
            for name, model in self.models.items():
                if (
                    model.model == requested_model
                    and name not in self.disabled_models
                    and model.enabled
                    and self.get_model_routing_status(name, routing_context)["eligible"]
                ):
                    if not self.usage_controller.acquire_model(name):
                        raise NoAvailableModelError(f"模型 {name} 并发已满，请稍后重试")
                    return name, model

            logger.warning(f"指定的模型 {requested_model} 不可用，使用自动选择")

        # 1. 获取所有可用模型
        available = self._get_available_models()
        available = self._filter_by_routing_policy(available, routing_context)
        if not available:
            raise NoAvailableModelError("没有符合当前扫描模式和额度策略的可用模型")

        # 2. 根据时间策略过滤
        time_filtered = self._filter_by_time(available)
        if not time_filtered:
            time_filtered = available

        # 3. 根据健康状态过滤
        healthy, probe_ready = self._filter_by_health(time_filtered)

        # 如果有需要探测的模型，随机选择一个进行探测
        if probe_ready and random.random() < 0.3:  # 30% 概率进行探测
            probe_model = random.choice(probe_ready)
            if self.usage_controller.acquire_model(probe_model):
                self.health_checker.start_probe(probe_model)
                logger.info(f"选择探测模型: {probe_model}")
                return probe_model, self.models[probe_model]
            logger.info(f"探测模型并发已满，跳过: {probe_model}")

        # 如果没有健康模型，尝试使用需要探测的模型
        if not healthy:
            if probe_ready:
                probe_model = random.choice(probe_ready)
                if self.usage_controller.acquire_model(probe_model):
                    self.health_checker.start_probe(probe_model)
                    return probe_model, self.models[probe_model]
                logger.info(f"探测模型并发已满，跳过: {probe_model}")

            # 尝试免费模型
            free_models = self._get_free_models()
            if free_models:
                free_healthy, _ = self._filter_by_health(free_models)
                if free_healthy:
                    selected = random.choice(free_healthy)
                    if self.usage_controller.acquire_model(selected):
                        logger.warning(f"所有付费模型不可用，使用免费模型: {selected}")
                        return selected, self.models[selected]
                    logger.info(f"免费模型并发已满，跳过: {selected}")

            raise NoAvailableModelError("没有健康可用的模型")

        # 4. 根据预算过滤
        affordable = self._filter_by_budget(healthy)
        if not affordable:
            logger.warning("所有健康模型都超出预算，使用第一个健康模型")
            affordable = healthy[:1]

        # 4.5 过滤近期成功率低于 70% 的模型
        rate_ok = self.health_checker.filter_by_success_rate(affordable, min_rate=0.7)
        if not rate_ok:
            logger.warning("所有模型近期成功率都低于 70%，使用原始列表")
            rate_ok = affordable
        elif len(rate_ok) < len(affordable):
            skipped = [n for n in affordable if n not in rate_ok]
            logger.info(f"跳过低成功率模型: {skipped}")

        # 5. 按优先级排序
        prioritized = self._sort_by_priority(rate_ok)

        # 6. Priority mode only routes within the highest-priority group.
        # balanced_all keeps every eligible enabled model in the rotation.
        def get_dynamic_priority(name: str) -> int:
            model = self.models.get(name)
            if not model:
                return 999
            return self.time_controller.get_model_priority(name, model.priority)

        candidates = prioritized
        if self.get_routing_mode() == "priority":
            highest_priority = get_dynamic_priority(prioritized[0])
            candidates = [
                name
                for name in prioritized
                if get_dynamic_priority(name) == highest_priority
            ]

        # 8. 轮询分发（优先未触发速率限制的模型）
        rate_ok = self._filter_by_rate_limit(candidates)
        if not rate_ok:
            # 所有模型都触发速率限制，使用全部（排队等待）
            rate_ok = candidates
            logger.warning(f"所有模型触发速率限制，排队等待: {rate_ok}")
        elif len(rate_ok) < len(candidates):
            skipped = [n for n in candidates if n not in rate_ok]
            logger.debug(f"跳过速率限制模型: {skipped}")

        # 尝试获取并发锁，失败则尝试下一个
        self._round_robin_counter += 1
        start_idx = self._round_robin_counter % len(rate_ok)
        for i in range(len(rate_ok)):
            idx = (start_idx + i) % len(rate_ok)
            candidate = rate_ok[idx]
            if self.usage_controller.acquire_model(candidate):
                logger.debug(
                    f"选择模型: {candidate} | 策略: {self.time_controller.get_current_strategy()} | 轮询: {self._round_robin_counter}"
                )
                return candidate, self.models[candidate]
            logger.debug(f"模型 {candidate} 并发已满，尝试下一个")

        # 所有候选模型都满了，强制获取第一个
        raise NoAvailableModelError("所有候选模型并发已满，请稍后重试")

    def _select_by_slot(
        self, slot: int, routing_context: Optional[dict] = None
    ) -> Tuple[str, ModelConfig]:
        """根据固定序号选择模型（auto1, auto2, auto3...）

        每个序号固定映射到一个模型，失败时自动切换到下一个可用模型。
        同一个 slot 每次请求都返回同一个模型（除非模型不健康或成功率过低）。
        模型分配时优先负载均衡，避免同一模型服务多个 slot。

        Args:
            slot: 序号（从1开始）

        Returns:
            (模型名称, 模型配置)
        """
        # 检查该 slot 是否已有分配且模型健康且成功率达标
        if slot in self._slot_model_map:
            assigned = self._slot_model_map[slot]
            if (
                assigned in self.models
                and assigned not in self.disabled_models
                and self.health_checker.is_healthy(assigned)
                and self.get_model_routing_status(assigned, routing_context)["eligible"]
                and self.usage_controller.check_budget(assigned)
                and not self.usage_controller.check_rate_limit(assigned)
            ):
                # 检查近期成功率
                success_rate = self.health_checker.get_success_rate(assigned)
                if success_rate >= 0.7:
                    logger.debug(f"固定分配模型: auto{slot} -> {assigned} (复用)")
                    return assigned, self.models[assigned]
                else:
                    logger.info(
                        f"模型 {assigned} 近期成功率过低 ({success_rate:.1%})，重新分配"
                    )
                    # 成功率过低，自动禁用
                    if self.health_checker.should_auto_disable(
                        assigned, min_requests=20, min_rate=0.5
                    ):
                        logger.warning(
                            f"模型 {assigned} 成功率过低 ({success_rate:.1%})，自动禁用"
                        )
                        self.disable_model(assigned)

        # 需要重新分配
        available = self._get_available_models()
        available = self._filter_by_routing_policy(available, routing_context)
        available = self._filter_by_budget(available)
        if not available:
            raise NoAvailableModelError("没有符合当前扫描模式和额度策略的可用模型")

        # 按优先级排序
        prioritized = self._sort_by_priority(available)

        # 获取最高优先级的模型组（使用动态优先级）
        def get_dynamic_priority(name: str) -> int:
            model = self.models.get(name)
            if not model:
                return 999
            return self.time_controller.get_model_priority(name, model.priority)

        # 负载均衡选择：统计每个模型当前服务的 slot 数量
        model_slot_count: Dict[str, int] = {m: 0 for m in available}
        for s, m in self._slot_model_map.items():
            if m in model_slot_count:
                model_slot_count[m] += 1

        # 按优先级分组
        priority_groups = {}
        for m in prioritized:
            p = get_dynamic_priority(m)
            if p not in priority_groups:
                priority_groups[p] = []
            priority_groups[p].append(m)

        sorted_priorities = sorted(priority_groups.keys())

        selected = None
        if self.get_routing_mode() == "balanced_all":
            candidate_groups = [
                sorted(
                    prioritized,
                    key=lambda m: (
                        model_slot_count[m],
                        get_dynamic_priority(m),
                        m,
                    ),
                )
            ]
        else:
            candidate_groups = [priority_groups[p] for p in sorted_priorities]

        for group in candidate_groups:
            # Balanced mode distributes slots across all eligible models first.
            candidates = sorted(
                group,
                key=lambda m: (model_slot_count[m], get_dynamic_priority(m), m),
            )

            for candidate in candidates:
                if not self.health_checker.is_healthy(candidate):
                    continue
                if self.usage_controller.check_rate_limit(candidate):
                    continue

                # 检查是否达到并发限制
                limits = self.usage_controller.per_model_limits.get(candidate, {})
                max_concurrent = limits.get("max_concurrent", 0)
                if (
                    max_concurrent > 0
                    and model_slot_count[candidate] >= max_concurrent
                ):
                    logger.debug(
                        f"模型 {candidate} 槽位并发已满 ({model_slot_count[candidate]}/{max_concurrent})，跳过"
                    )
                    continue

                selected = candidate
                break

            if selected:
                break

        if not selected:
            # 所有健康模型都达到并发限制时，不再强制路由到不健康模型。
            # Smart Batch 会看到暂无容量并按退避/重试处理，避免 provider 500/429 被反复放大。
            healthy_models = [
                m
                for m in prioritized
                if self.health_checker.is_healthy(m)
                and self.get_model_routing_status(m, routing_context)["eligible"]
            ]
            if healthy_models:
                raise NoAvailableModelError("所有健康模型槽位并发已满，请稍后重试")
            else:
                raise NoAvailableModelError("没有健康且可自动路由的模型")

        # 记录分配并更新活跃状态
        self._slot_model_map[slot] = selected
        self._active_models.add(selected)

        logger.info(f"分配固定模型: auto{slot} -> {selected} (已服务 {model_slot_count.get(selected, 0)} 个 slot)")
        return selected, self.models[selected]

    def select_fallback_model(
        self, failed_model: str, routing_context: Optional[dict] = None
    ) -> Optional[Tuple[str, ModelConfig]]:
        """选择备用模型（同 provider 优先，排除正在使用的模型）

        Args:
            failed_model: 失败的模型名称

        Returns:
            (模型名称, 模型配置) 或 None
        """
        with self._select_lock:
            return self._do_select_fallback_model(failed_model, routing_context)

    def _do_select_fallback_model(
        self, failed_model: str, routing_context: Optional[dict] = None
    ) -> Optional[Tuple[str, ModelConfig]]:
        """内部备用模型选择逻辑（需在 _select_lock 下调用）"""
        active_models = self._get_active_models()

        # 1. 先尝试同 provider 的备用模型
        same_provider = self._get_same_provider_fallbacks(failed_model)
        same_provider = self._filter_by_routing_policy(
            same_provider, routing_context
        )
        same_provider = self._filter_by_budget(same_provider)
        same_provider = self._filter_by_rate_limit(same_provider)
        # 排除失败的模型和正在使用的模型
        same_provider = [m for m in same_provider if m not in active_models]
        if same_provider:
            healthy, _ = self._filter_by_health(same_provider)
            if healthy:
                for candidate in healthy:
                    if self.usage_controller.acquire_model(candidate):
                        logger.info(
                            f"切换到同 provider 备用模型: {failed_model} -> {candidate}"
                        )
                        return candidate, self.models[candidate]
                logger.info(f"同 provider 备用模型都满，暂不强制切换: {failed_model}")

        # 2. 尝试其他 provider 的模型
        available = self._get_available_models()
        other_models = [
            name
            for name in available
            if name != failed_model
            and name not in same_provider
            and name not in active_models
        ]
        other_models = self._filter_by_routing_policy(other_models, routing_context)
        other_models = self._filter_by_budget(other_models)
        other_models = self._filter_by_rate_limit(other_models)

        if other_models:
            healthy, _ = self._filter_by_health(other_models)
            if healthy:
                # 按优先级排序
                prioritized = self._sort_by_priority(healthy)
                for candidate in prioritized:
                    if self.usage_controller.acquire_model(candidate):
                        logger.info(
                            f"切换到其他 provider 模型: {failed_model} -> {candidate}"
                        )
                        return candidate, self.models[candidate]
                logger.info(f"其他 provider 模型都满，暂不强制切换: {failed_model}")

        # 3. 尝试免费模型（也排除正在使用的）
        failover_config = self.config.get("failover", {})
        if failover_config.get("fallback_to_free", True):
            free_models = self._get_free_models()
            free_models = [
                m for m in free_models if m != failed_model and m not in active_models
            ]
            free_models = self._filter_by_routing_policy(
                free_models, routing_context
            )
            free_models = self._filter_by_budget(free_models)
            free_models = self._filter_by_rate_limit(free_models)
            if free_models:
                healthy_free, _ = self._filter_by_health(free_models)
                if healthy_free:
                    selected = random.choice(healthy_free)
                    if self.usage_controller.acquire_model(selected):
                        logger.warning(f"切换到免费模型: {failed_model} -> {selected}")
                        return selected, self.models[selected]
                    logger.info(f"免费备用模型也已满，暂不强制切换: {failed_model}")

        return None

    def mark_model_active(self, model_name: str):
        """标记模型正在使用中"""
        with self._active_models_lock:
            self._active_models.add(model_name)

    def mark_model_inactive(self, model_name: str):
        """标记模型使用完毕"""
        with self._active_models_lock:
            self._active_models.discard(model_name)

    def _get_active_models(self) -> set:
        """获取当前正在使用的模型集合"""
        with self._active_models_lock:
            return self._active_models.copy()

    def handle_success(self, model_name: str):
        """处理成功请求"""
        self.health_checker.mark_healthy(model_name)

    def handle_error(self, model_name: str, error: Exception) -> bool:
        """处理错误请求 - 失败立即切换"""
        error_str = str(error)

        cfg = self.get_model_config(model_name)
        if cfg and getattr(cfg, "provider", "") == "mimo-free" and "403" in error_str:
            logger.info(f"💡 模型 {model_name} (mimo-free) 遇到 403 错误，系统已准备好重新获取 Token，不影响健康度")
            return True

        # An occasional HTTP 200 with an empty SSE body is an upstream
        # transient, not proof of a 429 or a dead credential.
        if any(
            marker in error_str.lower()
            for marker in ("empty response", "empty upstream response")
        ):
            self.health_checker.record_transient_failure(model_name, error_str)
            return True

        # A single DNS/TCP/stream interruption is common on long-running
        # scans. HealthChecker opens a short, jittered circuit only after the
        # configured number of consecutive transient failures.
        transient_markers = (
            "all connection attempts failed",
            "temporary failure in name resolution",
            "name or service not known",
            "connection reset",
            "connection aborted",
            "connection refused",
            "server disconnected",
            "network is unreachable",
            "connect timeout",
            "read timeout",
        )
        normalized_error = error_str.lower()
        if any(marker in normalized_error for marker in transient_markers):
            self.health_checker.record_transient_failure(model_name, error_str)
            return True

        # 分类错误
        error_type = self.health_checker.classify_error(error_str)

        if error_type == "rate_limit":
            # 速率限制错误：临时标记不健康，清除 slot 缓存，切换到其他模型
            logger.info(f"⏳ 模型 {model_name} 触发速率限制，切换到其他模型重试")
            # 记录失败（用于成功率计算）
            self.health_checker.mark_unhealthy(model_name, error_str)
            # 强制标记不健康（让 slot 缓存失效）
            state = self.health_checker.health_state.get(model_name)
            if state:
                state.healthy = False
                state.reason = "rate_limit"
                quota_policy = (cfg.quota_policy or {}) if cfg else {}
                cooldown = int(quota_policy.get("rate_limit_cooldown_seconds") or 60)
                state.next_probe_at = time.time() + max(60, cooldown)
                self.health_checker.health_state[model_name] = state
                self.health_checker._save_health_state()
            # 清除使用该模型的 slot 缓存
            with self._select_lock:
                slots_to_clear = [
                    s for s, m in self._slot_model_map.items() if m == model_name
                ]
                for s in slots_to_clear:
                    del self._slot_model_map[s]
                if slots_to_clear:
                    logger.info(f"清除 slot 缓存: {slots_to_clear}")
            return True

        if error_type == "quota_error":
            quota_policy = (cfg.quota_policy or {}) if cfg else {}
            delete_markers = (
                "insufficient_quota",
                "quota exceeded",
                "resource_exhausted",
                "usage limit exceeded",
                "invalid_api_key",
                "authentication",
                "unauthorized",
                "401",
                "403",
            )
            if quota_policy.get("delete_on_quota_exhausted", False) and any(
                marker in error_str.lower() for marker in delete_markers
            ):
                logger.warning(f"🗑️ 模型 {model_name} 额度耗尽，按策略直接删除")
                self.delete_model(model_name)
                return True

            # 检查是否有重置时间（如 minimax 的 5 小时限制）
            reset_time = self.health_checker.parse_reset_time_from_error(error_str)
            if reset_time:
                # 有重置时间，设置定时重新启用
                from datetime import datetime

                reset_time_str = datetime.fromtimestamp(reset_time, timezone.utc).astimezone().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                logger.warning(
                    f"⏰ 模型 {model_name} 额度用尽，将在 {reset_time_str} 自动重新启用"
                )
                self.health_checker.handle_quota_error_with_reset(
                    model_name, error_str, self
                )
                return True

            # 没有重置时间，minimax 等待 5 小时，其他模型 30 分钟
            import time as _time

            if model_name == "minimax":
                cooldown = 5 * 3600  # 5 小时
            else:
                cooldown = self.AUTO_REENABLE_SECONDS
            self.disabled_until[model_name] = _time.time() + cooldown
            logger.warning(
                f"🚫 模型 {model_name} 额度用尽，{cooldown // 3600}小时{cooldown % 3600 // 60}分钟后自动重试"
            )
            self.health_checker.mark_unhealthy(model_name, error_str)
            return True

        if error_type == "api_error":
            # API 错误，标记不健康并切换
            self.health_checker.mark_unhealthy(model_name, error_str)
            return True

        # 如果是 400/422 (如内容安全拦截/参数错误) 等客户端请求造成的异常，不应将模型标记为不健康
        if "422" in error_str or "Unprocessable Entity" in error_str or "400" in error_str or "Bad Request" in error_str:
            logger.info(f"模型 {model_name} 遇到请求参数或内容策略错误 ({error_str[:100]})，不标记为不健康")
            return True

        # 404/500 等错误也切换
        if "404" in error_str or "Not Found" in error_str or "500" in error_str:
            self.health_checker.mark_unhealthy(model_name, error_str)
            return True

        # 其他错误，标记不健康并切换
        self.health_checker.mark_unhealthy(model_name, error_str[:100])
        return True

    def handle_probe_result(self, model_name: str, success: bool):
        """处理探测结果"""
        self.health_checker.end_probe(model_name, success)

    def record_usage(self, model_name: str, usage: dict):
        """记录使用量"""
        self.usage_controller.record_usage(model_name, usage)

    def disable_model(self, model_name: str, cooldown: bool = True):
        """Disable a model temporarily after faults or persistently by operator action."""
        import time as _time

        self.disabled_models.add(model_name)
        model = self.models.get(model_name)
        if model:
            model.enabled = False
        if cooldown:
            self.disabled_until[model_name] = _time.time() + self.AUTO_REENABLE_SECONDS
        else:
            self.disabled_until.pop(model_name, None)
        # 持久化到配置文件
        if "models" in self.config and "available" in self.config["models"]:
            if model_name in self.config["models"]["available"]:
                self.config["models"]["available"][model_name]["enabled"] = False
        suffix = f"（{self.AUTO_REENABLE_SECONDS // 60}分钟后自动重试）" if cooldown else "（手动关闭）"
        logger.info(f"模型已禁用: {model_name}{suffix}")

    def enable_model(self, model_name: str):
        """启用模型"""
        self.disabled_models.discard(model_name)
        self.disabled_until.pop(model_name, None)
        model = self.models.get(model_name)
        if model:
            model.enabled = True
        # 重置健康状态
        self.health_checker.mark_healthy(model_name)
        # 持久化到配置文件
        if "models" in self.config and "available" in self.config["models"]:
            if model_name in self.config["models"]["available"]:
                self.config["models"]["available"][model_name]["enabled"] = True
        logger.info(f"模型已启用: {model_name}")

    def delete_model(self, model_name: str):
        """Remove a model from runtime and persistent config."""
        available = self.config.get("models", {}).get("available", {})
        available.pop(model_name, None)
        for provider_config in self.config.get("providers", {}).values():
            fallbacks = provider_config.get("fallback_models")
            if isinstance(fallbacks, list) and model_name in fallbacks:
                provider_config["fallback_models"] = [name for name in fallbacks if name != model_name]
        self.config.get("usage", {}).get("per_model_limits", {}).pop(model_name, None)
        self.models.pop(model_name, None)
        self.disabled_models.discard(model_name)
        self.disabled_until.pop(model_name, None)
        with self._select_lock:
            self._slot_model_map = {
                slot: name for slot, name in self._slot_model_map.items() if name != model_name
            }
        self._available_cache = None
        self.health_checker.health_state.pop(model_name, None)
        self.health_checker._save_health_state()
        if self.config_path:
            self.save_config(self.config_path)
        logger.info(f"模型已删除: {model_name}")

    def save_config(self, config_path: str):
        """保存配置到文件"""
        import yaml

        try:
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            rendered = yaml.dump(
                self.config,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
            fd, temp_path = tempfile.mkstemp(
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(rendered)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_path, path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            logger.info(f"配置已保存到: {config_path}")
        except Exception as e:
            logger.error(f"保存配置失败: {e}")

    def reset_model_health(self, model_name: str):
        """重置模型健康状态"""
        self.health_checker.mark_healthy(model_name)
        logger.info(f"模型健康状态已重置: {model_name}")

    def get_model_config(self, model_name: str) -> Optional[ModelConfig]:
        """获取模型配置"""
        return self.models.get(model_name)

    def get_all_models_status(
        self, routing_context: Optional[dict] = None
    ) -> dict:
        """返回所有模型状态"""
        health_report = self.health_checker.get_health_report()

        return {
            name: {
                "model": model.model,
                "api_base": model.api_base,
                "provider": model.provider,
                "priority": model.priority,
                "enabled": model.enabled and name not in self.disabled_models,
                "peak_only": model.peak_only,
                "free": model.free,
                "label": model.label,
                "api_format": model.api_format,
                "is_exact_url": model.is_exact_url,
                "custom_headers": model.custom_headers,
                "strip_provider_prefix": model.strip_provider_prefix,
                "routing_tier": model.routing_tier,
                "allowed_scan_modes": model.allowed_scan_modes,
                "quota_policy": model.quota_policy,
                "max_context_tokens": model.max_context_tokens,
                "reasoning_supported": model.reasoning_supported,
                "reasoning_api": model.reasoning_api,
                "vision_supported": model.vision_supported,
                "vision_assist_enabled": model.vision_assist_enabled,
                "thinking_enabled": model.thinking_enabled,
                "reasoning_effort": model.reasoning_effort,
                "request_overrides": self.config.get("models", {})
                .get("available", {})
                .get(name, {})
                .get("request_overrides", {}),
                "auto_routing": self.get_model_routing_status(name, routing_context),
                "api_key_hint": model.api_key[-5:] if model.api_key else "",
                "health": health_report.get(name, {}),
            }
            for name, model in self.models.items()
        }

    def get_status(self) -> dict:
        """返回模型管理器状态"""
        return {
            "total_models": len(self.models),
            "enabled_models": len(self._get_available_models()),
            "disabled_models": len(self.disabled_models),
            "current_strategy": self.time_controller.get_current_strategy(),
            "routing_mode": self.get_routing_mode(),
            "providers": list(self.providers.keys()),
            "time_controller": self.time_controller.get_status(),
            "usage_controller": self.usage_controller.get_status(),
            "health_checker": self.health_checker.get_status(),
        }
