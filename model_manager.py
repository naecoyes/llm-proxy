"""模型管理器 - 模型选择和路由"""

import logging
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .health_checker import HealthChecker
from .time_controller import TimeController
from .usage_controller import UsageController

logger = logging.getLogger(__name__)


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


class NoAvailableModelError(Exception):
    """没有可用的模型"""
    pass


class ModelManager:
    """模型选择和路由"""

    def __init__(self, config: dict, stats_dir: str = "stats"):
        self.config = config
        self.models: Dict[str, ModelConfig] = {}
        self.disabled_models: set = set()
        self.providers: Dict[str, dict] = {}
        self._round_robin_counter = 0  # 轮询计数器
        self._active_models: set = set()  # 当前正在使用的模型
        self._active_models_lock = __import__('threading').Lock()
        self._slot_model_map: Dict[int, str] = {}  # slot -> model_name 固定分配
        self._slot_model_lock = __import__('threading').Lock()

        # 初始化子控制器
        self.time_controller = TimeController(config)
        self.usage_controller = UsageController(config, stats_dir)
        self.health_checker = HealthChecker(config, stats_dir)

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
        self.disabled_models.clear()

        for name, model_conf in models_config.items():
            enabled = model_conf.get("enabled", True)

            model = ModelConfig(
                name=name,
                model=model_conf.get("model", ""),
                api_key=model_conf.get("api_key", ""),
                api_base=model_conf.get("api_base", ""),
                provider=model_conf.get("provider", ""),
                priority=model_conf.get("priority", 100),
                enabled=enabled,
                peak_only=model_conf.get("peak_only", False),
                free=model_conf.get("free", False),
                label=model_conf.get("label", ""),
            )

            self.models[name] = model
            self.health_checker.initialize_model(name)

            # 如果配置中enabled为false，添加到disabled_models
            if not enabled:
                self.disabled_models.add(name)

            logger.info(f"加载模型: {name} | {model.model} | provider: {model.provider} | 优先级: {model.priority} | {'启用' if enabled else '禁用'}")

    def update_config(self, config: dict):
        """热更新配置"""
        self.config = config
        self._load_providers(config)
        self._load_models(config)
        self.time_controller.update_config(config)
        self.usage_controller.update_config(config)
        self.health_checker.update_config(config)
        logger.info("模型管理器配置已更新")

    def _get_available_models(self) -> List[str]:
        """获取所有可用模型名称"""
        return [
            name for name, model in self.models.items()
            if name not in self.disabled_models and model.enabled
        ]

    def _get_provider_models(self, provider: str) -> List[str]:
        """获取指定 provider 的所有模型名称"""
        return [
            name for name, model in self.models.items()
            if model.provider == provider and name not in self.disabled_models and model.enabled
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
            name for name in fallback_models
            if name != model_name and name in self.models
            and name not in self.disabled_models
            and self.models[name].enabled
        ]

        # 按优先级排序
        return self._sort_by_priority(available_fallbacks)

    def _get_free_models(self) -> List[str]:
        """获取所有免费模型列表"""
        return [
            name for name, model in self.models.items()
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
            if self.time_controller.should_skip_model(name, {
                "peak_only": model.peak_only
            }, now):
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
            name for name in model_names
            if self.usage_controller.check_budget(name)
        ]

    def _sort_by_priority(self, model_names: List[str]) -> List[str]:
        """按优先级排序"""
        return sorted(
            model_names,
            key=lambda name: self.models.get(name, ModelConfig(name="", model="", api_key="", api_base="")).priority
        )

    def select_model(self, requested_model: str = None) -> Tuple[str, ModelConfig]:
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
        # 支持 auto1, auto2, auto3 等固定分配
        if requested_model and requested_model.startswith("auto") and requested_model != "auto":
            try:
                slot = int(requested_model[4:])  # 提取 auto 后面的数字
                return self._select_by_slot(slot)
            except (ValueError, IndexError):
                pass

        # 如果指定了模型，尝试使用它
        if requested_model and requested_model != "auto":
            # 直接匹配配置名称
            if requested_model in self.models and requested_model not in self.disabled_models:
                model = self.models[requested_model]
                if model.enabled:
                    return requested_model, model

            # 尝试匹配模型ID
            for name, model in self.models.items():
                if model.model == requested_model and name not in self.disabled_models and model.enabled:
                    return name, model

            logger.warning(f"指定的模型 {requested_model} 不可用，使用自动选择")

        # 1. 获取所有可用模型
        available = self._get_available_models()
        if not available:
            raise NoAvailableModelError("没有可用的模型")

        # 2. 根据时间策略过滤
        time_filtered = self._filter_by_time(available)
        if not time_filtered:
            time_filtered = available

        # 3. 根据健康状态过滤
        healthy, probe_ready = self._filter_by_health(time_filtered)

        # 如果有需要探测的模型，随机选择一个进行探测
        if probe_ready and random.random() < 0.3:  # 30% 概率进行探测
            probe_model = random.choice(probe_ready)
            self.health_checker.start_probe(probe_model)
            logger.info(f"选择探测模型: {probe_model}")
            return probe_model, self.models[probe_model]

        # 如果没有健康模型，尝试使用需要探测的模型
        if not healthy:
            if probe_ready:
                probe_model = random.choice(probe_ready)
                self.health_checker.start_probe(probe_model)
                return probe_model, self.models[probe_model]

            # 尝试免费模型
            free_models = self._get_free_models()
            if free_models:
                free_healthy, _ = self._filter_by_health(free_models)
                if free_healthy:
                    selected = random.choice(free_healthy)
                    logger.warning(f"所有付费模型不可用，使用免费模型: {selected}")
                    return selected, self.models[selected]

            raise NoAvailableModelError("没有健康可用的模型")

        # 4. 根据预算过滤
        affordable = self._filter_by_budget(healthy)
        if not affordable:
            logger.warning("所有健康模型都超出预算，使用第一个健康模型")
            affordable = healthy[:1]

        # 5. 按优先级排序
        prioritized = self._sort_by_priority(affordable)

        # 6. 获取最高优先级
        highest_priority = self.models.get(prioritized[0], ModelConfig(name="", model="", api_key="", api_base="")).priority

        # 7. 筛选同优先级的模型
        same_priority = [
            name for name in prioritized
            if self.models.get(name, ModelConfig(name="", model="", api_key="", api_base="")).priority == highest_priority
        ]

        # 8. 轮询选择（避免所有请求都用同一个 key）
        self._round_robin_counter += 1
        selected = same_priority[self._round_robin_counter % len(same_priority)]

        logger.debug(f"选择模型: {selected} | 策略: {self.time_controller.get_current_strategy()} | 轮询: {self._round_robin_counter}")
        return selected, self.models[selected]

    def _select_by_slot(self, slot: int) -> Tuple[str, ModelConfig]:
        """根据固定序号选择模型（auto1, auto2, auto3...）

        每个序号固定映射到一个模型，失败时自动切换到下一个可用模型。
        同一个 slot 每次请求都返回同一个模型（除非模型不健康）。

        Args:
            slot: 序号（从1开始）

        Returns:
            (模型名称, 模型配置)
        """
        with self._slot_model_lock:
            # 检查该 slot 是否已有分配且模型健康
            if slot in self._slot_model_map:
                assigned = self._slot_model_map[slot]
                if assigned in self.models and self.health_checker.is_healthy(assigned):
                    logger.debug(f"固定分配模型: auto{slot} -> {assigned} (复用)")
                    return assigned, self.models[assigned]

        # 需要重新分配
        available = self._get_available_models()
        if not available:
            raise NoAvailableModelError("没有可用的模型")

        # 按优先级排序
        prioritized = self._sort_by_priority(available)

        # 获取最高优先级的模型组
        highest_priority = self.models.get(prioritized[0], ModelConfig(name="", model="", api_key="", api_base="")).priority
        same_priority = [
            name for name in prioritized
            if self.models.get(name, ModelConfig(name="", model="", api_key="", api_base="")).priority == highest_priority
        ]

        # 排除已分配给其他 slot 的模型
        with self._slot_model_lock:
            assigned_models = set(self._slot_model_map.values())
            available_for_slot = [m for m in same_priority if m not in assigned_models or m == self._slot_model_map.get(slot)]

        # 如果没有可用模型，使用原始列表
        if not available_for_slot:
            available_for_slot = same_priority

        # 根据序号选择固定模型
        idx = (slot - 1) % len(available_for_slot)
        selected = available_for_slot[idx]

        # 如果选中的模型不健康，尝试下一个
        if not self.health_checker.is_healthy(selected):
            for i in range(1, len(available_for_slot)):
                next_idx = (idx + i) % len(available_for_slot)
                candidate = available_for_slot[next_idx]
                if self.health_checker.is_healthy(candidate):
                    selected = candidate
                    break

        # 记录分配
        with self._slot_model_lock:
            self._slot_model_map[slot] = selected

        logger.debug(f"固定分配模型: auto{slot} -> {selected}")
        return selected, self.models[selected]

    def select_fallback_model(self, failed_model: str) -> Optional[Tuple[str, ModelConfig]]:
        """选择备用模型（同 provider 优先，排除正在使用的模型）

        Args:
            failed_model: 失败的模型名称

        Returns:
            (模型名称, 模型配置) 或 None
        """
        active_models = self._get_active_models()

        # 1. 先尝试同 provider 的备用模型
        same_provider = self._get_same_provider_fallbacks(failed_model)
        # 排除失败的模型和正在使用的模型
        same_provider = [m for m in same_provider if m not in active_models]
        if same_provider:
            healthy, _ = self._filter_by_health(same_provider)
            if healthy:
                selected = healthy[0]
                logger.info(f"切换到同 provider 备用模型: {failed_model} -> {selected}")
                return selected, self.models[selected]

        # 2. 尝试其他 provider 的模型
        available = self._get_available_models()
        other_models = [
            name for name in available
            if name != failed_model and name not in same_provider and name not in active_models
        ]

        if other_models:
            healthy, _ = self._filter_by_health(other_models)
            if healthy:
                # 按优先级排序
                prioritized = self._sort_by_priority(healthy)
                selected = prioritized[0]
                logger.info(f"切换到其他 provider 模型: {failed_model} -> {selected}")
                return selected, self.models[selected]

        # 3. 尝试免费模型（也排除正在使用的）
        failover_config = self.config.get("failover", {})
        if failover_config.get("fallback_to_free", True):
            free_models = self._get_free_models()
            free_models = [m for m in free_models if m != failed_model and m not in active_models]
            if free_models:
                healthy_free, _ = self._filter_by_health(free_models)
                if healthy_free:
                    selected = random.choice(healthy_free)
                    logger.warning(f"切换到免费模型: {failed_model} -> {selected}")
                    return selected, self.models[selected]

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

        # 分类错误
        error_type = self.health_checker.classify_error(error_str)

        if error_type == "rate_limit":
            # 速率限制错误，标记不健康，需要切换
            self.health_checker.mark_unhealthy(model_name, "Rate limit")
            return True

        if error_type == "api_error":
            # API 错误，立即标记不健康并切换
            self.health_checker.mark_unhealthy(model_name, error_str)
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

    def disable_model(self, model_name: str):
        """禁用模型"""
        self.disabled_models.add(model_name)
        # 持久化到配置文件
        if "models" in self.config and "available" in self.config["models"]:
            if model_name in self.config["models"]["available"]:
                self.config["models"]["available"][model_name]["enabled"] = False
        logger.info(f"模型已禁用: {model_name}")

    def enable_model(self, model_name: str):
        """启用模型"""
        self.disabled_models.discard(model_name)
        # 持久化到配置文件
        if "models" in self.config and "available" in self.config["models"]:
            if model_name in self.config["models"]["available"]:
                self.config["models"]["available"][model_name]["enabled"] = True
        logger.info(f"模型已启用: {model_name}")

    def save_config(self, config_path: str):
        """保存配置到文件"""
        import yaml
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False)
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

    def get_all_models_status(self) -> dict:
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
            "providers": list(self.providers.keys()),
            "time_controller": self.time_controller.get_status(),
            "usage_controller": self.usage_controller.get_status(),
            "health_checker": self.health_checker.get_status(),
        }
