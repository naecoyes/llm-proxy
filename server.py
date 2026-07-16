"""Nscan Proxy Server - FastAPI HTTP 服务器"""

import asyncio
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import shutil
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from zoneinfo import ZoneInfo

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from config_watcher import ConfigWatcher
from model_manager import (
    ModelManager,
    NoAvailableModelError,
    default_reasoning_api,
    supports_native_reasoning,
    supports_vision_assist,
)
from request_logger import (
    SCAN_CONTEXT_FIELD_HEADERS,
    request_logger,
    sanitize_scan_context_value,
)
from smart_batch_monitor import (
    delete_smart_batch,
    get_system_resources,
    read_smart_batch_detail,
    read_smart_batch_status,
    set_smart_batch_paused,
    set_smart_batch_parallel,
    terminate_smart_batch,
)
from strix_runtime_monitor import (
    delete_strix_egress_node,
    get_strix_runtime_status,
    restart_strix_egress,
    set_strix_egress_enabled,
    set_strix_egress_node_enabled,
    set_strix_egress_startup_enabled,
    test_strix_egress_node,
    upsert_strix_egress_node,
)
from egress_usage_monitor import get_egress_usage
from chelmon_runtime import get_chelmon_runtime_status
from asset_database import get_asset_database, normalize_target
from findings import FindingsService, create_findings_router
from smart_batch_jobs import SmartBatchJobManager, analyze_targets
from target_policy import load_scope_catalog, save_scope_catalog

logger = logging.getLogger(__name__)

DASHBOARD_SESSION_COOKIE = "nscan_admin_session"
DEFAULT_RESPONSE_TOKEN_BUDGET = 16_384
CONTEXT_COMPACT_RECENT_MESSAGES = 12
DEFAULT_SCAN_CONTAINER_SUBNETS = ("172.29.0.0/24",)
SCAN_CONTAINER_ALLOWED_PATHS = frozenset(
    {
        "/v1/chat/completions",
        "/v1/models",
    }
)
ASSET_IMPORT_MAX_TARGETS = 10_000
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"


def normalize_openrouter_reasoning_capability(model_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize OpenRouter's optional per-model reasoning metadata."""
    reasoning = model_data.get("reasoning")
    if not isinstance(reasoning, dict):
        return {"supported": False}

    valid_efforts = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
    efforts = [
        str(value).lower()
        for value in reasoning.get("supported_efforts", []) or []
        if str(value).lower() in valid_efforts
    ]
    return {
        "supported": True,
        "supported_efforts": efforts,
        "default_effort": str(reasoning.get("default_effort") or "").lower(),
        "default_enabled": bool(reasoning.get("default_enabled", False)),
        "mandatory": bool(reasoning.get("mandatory", False)),
        "supports_max_tokens": bool(reasoning.get("supports_max_tokens", False)),
    }


def asset_import_target_values(raw: Any) -> list[str]:
    """Return submitted values for a bounded, inventory-only import."""
    if isinstance(raw, list):
        return [str(value).strip() for value in raw if str(value).strip()]
    return [line.strip() for line in str(raw or "").splitlines() if line.strip()]


def asset_import_cursor(payload: dict[str, Any]) -> str:
    # ``0`` is a valid upstream cursor, so do not use a truthiness fallback.
    value = payload.get("sync_cursor") if "sync_cursor" in payload else payload.get("cursor")
    return str(value).strip() if value is not None else ""


def deep_merge_config(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge config updates while preserving unspecified sections."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if (
            isinstance(value, dict)
            and isinstance(merged.get(key), dict)
        ):
            merged[key] = deep_merge_config(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def parse_scan_container_subnets(config: dict[str, Any]) -> list[ipaddress._BaseNetwork]:
    configured = (
        os.environ.get("NSCAN_SCAN_CONTAINER_SUBNETS")
        or config.get("server", {}).get("scan_container_subnets")
        or DEFAULT_SCAN_CONTAINER_SUBNETS
    )
    if isinstance(configured, str):
        candidates = [item.strip() for item in configured.split(",") if item.strip()]
    elif isinstance(configured, (list, tuple, set)):
        candidates = [str(item).strip() for item in configured if str(item).strip()]
    else:
        candidates = list(DEFAULT_SCAN_CONTAINER_SUBNETS)

    networks: list[ipaddress._BaseNetwork] = []
    for candidate in candidates:
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid scan container subnet: %s", candidate)
    return networks


def is_scan_container_peer(
    peer_ip: str,
    scan_container_subnets: list[ipaddress._BaseNetwork],
) -> bool:
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(address in network for network in scan_container_subnets)


def validate_proxy_config(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("Config payload must be a JSON object")

    for section in ("admin", "server", "usage", "models", "providers"):
        section_value = candidate.get(section)
        if section_value is not None and not isinstance(section_value, dict):
            raise ValueError(f"Config section '{section}' must be an object")

    models = candidate.get("models", {})
    available_models = models.get("available") if isinstance(models, dict) else None
    if not isinstance(available_models, dict) or not available_models:
        raise ValueError("Config must include at least one model under models.available")

    providers = candidate.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("Config must include at least one provider")

    for model_name, model_config in available_models.items():
        if not isinstance(model_config, dict):
            raise ValueError(f"Model '{model_name}' config must be an object")
        for required_field in ("model", "api_base", "provider"):
            if not str(model_config.get(required_field) or "").strip():
                raise ValueError(
                    f"Model '{model_name}' is missing required field '{required_field}'"
                )
        provider_name = str(model_config.get("provider") or "").strip()
        if provider_name not in providers:
            raise ValueError(
                f"Model '{model_name}' references unknown provider '{provider_name}'"
            )

    return candidate


def _rough_token_count(value: Any) -> int:
    """Fast, dependency-free token estimate for routing safety.

    This intentionally over-estimates JSON/tool payloads a little. The value is
    only used to skip models whose configured context windows are too small,
    avoiding provider-side 400s after a large redteam context has accumulated.
    """
    if value is None:
        return 0
    if isinstance(value, str):
        return max(1, len(value) // 4) if value else 0
    try:
        rendered = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        rendered = str(value)
    return max(1, len(rendered) // 4) if rendered else 0


def estimate_request_context_tokens(body: dict[str, Any]) -> int:
    """Estimate prompt + expected output tokens for model context routing."""
    prompt_tokens = _rough_token_count(body.get("messages") or body.get("input") or [])
    prompt_tokens += _rough_token_count(body.get("tools") or [])
    prompt_tokens += _rough_token_count(body.get("response_format") or {})
    max_output = (
        body.get("max_completion_tokens")
        or body.get("max_output_tokens")
        or body.get("max_tokens")
        or DEFAULT_RESPONSE_TOKEN_BUDGET
    )
    try:
        output_tokens = int(max_output or 0)
    except (TypeError, ValueError):
        output_tokens = DEFAULT_RESPONSE_TOKEN_BUDGET
    return prompt_tokens + max(0, output_tokens)


def _message_preview(message: dict[str, Any], max_chars: int = 900) -> str:
    role = str(message.get("role") or "unknown")
    content = message.get("content", "")
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                parts.append(str(item.get("text") or ""))
            elif item.get("type") == "image_url":
                parts.append("[image omitted]")
        text = "\n".join(parts)
    else:
        text = str(content or "")
    text = text.replace("\r", " ").strip()
    if len(text) > max_chars:
        text = f"{text[:max_chars].rstrip()} …[truncated]"
    return f"{role}: {text}" if text else f"{role}: [empty]"


def compact_request_context(body: dict[str, Any], token_budget: int) -> tuple[dict[str, Any], bool]:
    """Compact old chat history while preserving system and recent messages."""
    messages = body.get("messages")
    if not isinstance(messages, list) or len(messages) <= CONTEXT_COMPACT_RECENT_MESSAGES + 2:
        return body, False

    system_messages = [
        msg for msg in messages if isinstance(msg, dict) and msg.get("role") == "system"
    ]
    regular_messages = [
        msg for msg in messages if isinstance(msg, dict) and msg.get("role") != "system"
    ]
    if len(regular_messages) <= CONTEXT_COMPACT_RECENT_MESSAGES:
        return body, False

    recent_messages = regular_messages[-CONTEXT_COMPACT_RECENT_MESSAGES:]
    old_messages = regular_messages[:-CONTEXT_COMPACT_RECENT_MESSAGES]
    summary_lines = [
        "== Nscan compacted earlier agent context ==",
        f"Compacted {len(old_messages)} older messages to stay within the model context window.",
        "Preserve this as background only; the most recent messages below are authoritative.",
    ]
    # Keep enough breadcrumbs for security continuity without replaying huge
    # tool outputs. The final budget enforcement below will trim further if
    # needed.
    for idx, msg in enumerate(old_messages[-80:], start=max(1, len(old_messages) - 79)):
        if isinstance(msg, dict):
            summary_lines.append(f"[{idx}] {_message_preview(msg)}")

    compacted_messages = [
        *system_messages,
        {"role": "user", "content": "\n".join(summary_lines)},
        *recent_messages,
    ]
    compacted_body = {**body, "messages": compacted_messages}

    # If the recent tail is still too large, progressively keep fewer recent
    # messages before finally shortening the synthetic summary.
    keep = CONTEXT_COMPACT_RECENT_MESSAGES
    while keep > 3 and estimate_request_context_tokens(compacted_body) > token_budget:
        keep -= 1
        compacted_body["messages"] = [
            *system_messages,
            {"role": "user", "content": "\n".join(summary_lines[:20])},
            *regular_messages[-keep:],
        ]

    if estimate_request_context_tokens(compacted_body) > token_budget:
        compacted_body["messages"] = [
            *system_messages,
            {
                "role": "user",
                "content": "\n".join(summary_lines[:8]) + "\n[Older detailed context omitted]",
            },
            *regular_messages[-3:],
        ]

    return compacted_body, True


def _asset_change_key(item: dict[str, Any]) -> tuple[str, int]:
    return (str(item.get("last_seen") or item.get("first_seen") or ""), int(item.get("id") or 0))


def _encode_asset_cursor(key: tuple[str, int]) -> str:
    return f"{key[0]}|{key[1]}" if key[0] else ""


def _decode_asset_cursor(value: str) -> tuple[str, int]:
    if not value or "|" not in value:
        return ("", 0)
    timestamp, asset_id = value.rsplit("|", 1)
    try:
        return (timestamp, int(asset_id))
    except ValueError:
        return ("", 0)


def list_asset_changes(cursor: str = "", limit: int = 500) -> dict[str, Any]:
    db = get_asset_database()
    after = _decode_asset_cursor(cursor)
    collected: list[dict[str, Any]] = []
    page = 1
    pages = 1
    high_watermark = after
    while page <= pages:
        payload = db.list_assets(sort="last_seen", page=page, page_size=200)
        pages = max(1, int(payload.get("pages") or 1))
        items = payload.get("items") or []
        if not items:
            break
        reached_cursor = False
        for item in items:
            if not isinstance(item, dict):
                continue
            key = _asset_change_key(item)
            if key > high_watermark:
                high_watermark = key
            if key > after:
                collected.append(item)
            elif after != ("", 0):
                reached_cursor = True
        if reached_cursor:
            break
        page += 1
    collected.sort(key=_asset_change_key)
    selected = collected[: max(1, min(int(limit or 500), 1000))]
    next_key = _asset_change_key(selected[-1]) if selected else after
    return {
        "cursor": cursor, "next_cursor": _encode_asset_cursor(next_key),
        "high_watermark": _encode_asset_cursor(high_watermark),
        "has_more": len(collected) > len(selected), "items": selected,
    }


def normalize_openai_sse_chunk(
    chunk: bytes | str, *, preserve_reasoning_content: bool = False
) -> tuple[bytes | str, dict[str, Any]]:
    """Normalize one OpenAI-compatible SSE chunk and collect stream diagnostics.

    Some providers, notably DeepSeek-compatible streams, may omit final usage
    accounting even when they emit valid assistant content. Health checks must
    therefore be based on observed content / finish events, not only token usage.
    """
    was_bytes = isinstance(chunk, bytes)
    try:
        text = chunk.decode() if was_bytes else str(chunk)
    except Exception:
        return chunk, {}

    diagnostics: dict[str, Any] = {
        "has_content": False,
        "usage": None,
        "finish_reason": None,
        "error": None,
    }
    output_lines: list[str] = []
    changed = False

    for line in text.splitlines(keepends=True):
        line_body = line.rstrip("\r\n")
        line_end = line[len(line_body):]
        stripped = line_body.lstrip()
        if not stripped.startswith("data:"):
            output_lines.append(line)
            continue

        payload = stripped[5:].strip()
        if not payload or payload == "[DONE]":
            output_lines.append(line)
            continue

        try:
            data = json.loads(payload)
        except Exception:
            output_lines.append(line)
            continue

        if data.get("error"):
            diagnostics["error"] = json.dumps(data["error"], ensure_ascii=False)

        usage = data.get("usage")
        if usage:
            diagnostics["usage"] = usage

        choices = data.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                finish_reason = choice.get("finish_reason")
                if finish_reason:
                    diagnostics["finish_reason"] = finish_reason
                delta = choice.get("delta") or {}
                if isinstance(delta, dict):
                    if "reasoning_content" in delta and not preserve_reasoning_content:
                        delta.pop("reasoning_content", None)
                        changed = True
                    if str(delta.get("content") or "").strip():
                        diagnostics["has_content"] = True
                message = choice.get("message") or {}
                if isinstance(message, dict):
                    if "reasoning_content" in message and not preserve_reasoning_content:
                        message.pop("reasoning_content", None)
                        changed = True
                    if str(message.get("content") or "").strip():
                        diagnostics["has_content"] = True

        output_lines.append(f"data: {json.dumps(data, ensure_ascii=False)}{line_end}")
        changed = True

    normalized = "".join(output_lines)
    if not changed:
        return chunk, diagnostics
    return (normalized.encode() if was_bytes else normalized), diagnostics


def classify_stream_completion(
    *,
    is_success: bool,
    client_cancelled: bool,
    client_closed_after_output: bool,
    server_shutting_down: bool,
    total_tokens: int,
    stream_error: str | None,
) -> tuple[str, str | None]:
    """Classify a stream without allowing missing usage to look fully healthy."""
    zero_usage_partial = is_success and total_tokens == 0
    if zero_usage_partial:
        status = "partial"
    elif client_closed_after_output:
        status = "success"
    elif client_cancelled:
        status = "interrupted" if server_shutting_down else "cancelled"
    else:
        status = "success" if is_success else "failed"

    if zero_usage_partial:
        error = "suspicious_empty_usage"
    elif is_success:
        error = None
    else:
        error = stream_error or "Empty upstream response"
    return status, error


def _cached_input_tokens(usage: dict[str, Any] | None) -> int:
    """Extract explicit upstream cache-read tokens; never estimate cache usage."""
    payload = usage or {}
    details = payload.get("prompt_tokens_details") or payload.get("input_tokens_details") or {}
    for value in (
        payload.get("cached_input_tokens"),
        payload.get("cache_read_input_tokens"),
        details.get("cached_tokens") if isinstance(details, dict) else None,
    ):
        try:
            if value is not None:
                return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _deepseek_v4_pro_cost_cny(model_config: Any, usage: dict[str, Any]) -> dict[str, Any]:
    """Calculate DeepSeek V4 Pro marginal cost using its BJT time bands."""
    provider = str(getattr(model_config, "provider", "") or "").lower()
    model = str(getattr(model_config, "model", "") or "").lower()
    if provider != "deepseek" or "deepseek-v4-pro" not in model:
        return {}
    now_bjt = datetime.now(ZoneInfo("Asia/Shanghai"))
    is_peak = (9 <= now_bjt.hour < 12) or (14 <= now_bjt.hour < 18)
    cache_hit_rate, cache_miss_rate, output_rate = (
        (0.05, 6.0, 12.0) if is_peak else (0.025, 3.0, 6.0)
    )
    prompt = max(0, int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0))
    cached = min(prompt, _cached_input_tokens(usage))
    output = max(0, int(usage.get("completion_tokens") or usage.get("output_tokens") or 0))
    amount = (
        (cached * cache_hit_rate)
        + ((prompt - cached) * cache_miss_rate)
        + (output * output_rate)
    ) / 1_000_000
    return {
        "estimated_cost_cny": round(amount, 8),
        "pricing_period": "peak" if is_peak else "off_peak",
    }


def _usage_with_billing(server: Any, model_name: str, model_config: Any, usage: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize provider usage and attach per-request configured pricing."""
    payload = dict(usage or {})
    prompt = int(payload.get("prompt_tokens") or payload.get("input_tokens") or 0)
    completion = int(payload.get("completion_tokens") or payload.get("output_tokens") or 0)
    payload["prompt_tokens"] = prompt
    payload["completion_tokens"] = completion
    payload["total_tokens"] = int(payload.get("total_tokens") or (prompt + completion))
    payload["cached_input_tokens"] = _cached_input_tokens(payload)
    if payload.get("cost") is None:
        payload["cost"] = round(
            server.model_manager.usage_controller.estimate_cost(
                model_name, prompt, completion
            ),
            8,
        )
    payload.update(_deepseek_v4_pro_cost_cny(model_config, payload))
    return payload


_DEEPSEEK_REASONING_EFFORTS = {
    "none": "high",
    "minimal": "high",
    "low": "high",
    "medium": "high",
    "high": "high",
    "xhigh": "max",
    "max": "max",
}


def _reasoning_api(model_config: Any) -> str:
    """Resolve a configured reasoning transport without guessing upstream support."""
    provider = str(getattr(model_config, "provider", "") or "").lower()
    model = str(getattr(model_config, "model", "") or "")
    supported = bool(
        getattr(model_config, "reasoning_supported", supports_native_reasoning(provider, model))
    )
    configured = str(getattr(model_config, "reasoning_api", "") or "").lower()
    return configured if configured and configured != "auto" else default_reasoning_api(provider, model, supported)


def _uses_native_reasoning(model_config: Any) -> bool:
    return bool(getattr(model_config, "thinking_enabled", False)) and _reasoning_api(model_config) != "none"


def _uses_deepseek_thinking(model_config: Any) -> bool:
    return _uses_native_reasoning(model_config) and _reasoning_api(model_config) == "deepseek"


def _sanitize_reasoning_messages(
    messages: list[Any], *, preserve_tool_reasoning: bool
) -> list[Any]:
    """Keep native tool-turn reasoning, without retaining ordinary turn CoT."""
    cleaned = copy.deepcopy(messages)
    for message in cleaned:
        if not isinstance(message, dict):
            continue
        should_preserve = (
            preserve_tool_reasoning
            and message.get("role") == "assistant"
            and bool(message.get("tool_calls"))
        )
        if should_preserve:
            continue
        for field in ("reasoning", "reasoning_content", "reasoning_details"):
            message.pop(field, None)
    return cleaned


def _prepare_openai_request_body(model_config: Any, request_body: dict) -> dict:
    """Build a provider-safe body while preserving native tool-call continuity."""
    body = copy.deepcopy(request_body)
    deepseek_thinking = _uses_deepseek_thinking(model_config)
    native_reasoning = _uses_native_reasoning(model_config)
    body["messages"] = _sanitize_reasoning_messages(
        body.get("messages") or [],
        preserve_tool_reasoning=native_reasoning,
    )

    if deepseek_thinking:
        effort = _DEEPSEEK_REASONING_EFFORTS.get(
            str(getattr(model_config, "reasoning_effort", "high") or "high").lower(),
            "high",
        )
        # DeepSeek thinking ignores these sampling options. Removing them
        # makes the effective request explicit and reproducible.
        for field in ("temperature", "top_p", "presence_penalty", "frequency_penalty"):
            body.pop(field, None)
        body["thinking"] = {"type": "enabled"}
        body["reasoning_effort"] = effort
    elif str(getattr(model_config, "provider", "")).lower() == "deepseek":
        body.pop("thinking", None)
        body.pop("reasoning_effort", None)
        body["thinking"] = {"type": "disabled"}
    elif _reasoning_api(model_config) == "openrouter":
        # OpenRouter normalizes provider-native thinking behind this request
        # shape. High is the Nscan default for explicitly capable models.
        effort = str(getattr(model_config, "reasoning_effort", "high") or "high").lower()
        if effort not in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}:
            effort = "high"
        body["reasoning"] = {"effort": effort}
    elif _reasoning_api(model_config) == "openai" and native_reasoning:
        body["reasoning_effort"] = str(
            getattr(model_config, "reasoning_effort", "high") or "high"
        ).lower()
    return body


class IPWhitelist:
    """IP 白名单管理"""

    def __init__(self, allowed_ips: List[str]):
        self.allowed_ips: Set[str] = set(allowed_ips)
        self._update_config(allowed_ips)

    def _update_config(self, allowed_ips: List[str]):
        """更新配置"""
        self.allowed_ips = set(allowed_ips)

    def is_allowed(self, ip: str) -> bool:
        """检查 IP 是否允许访问"""
        # 如果白名单为空，允许所有访问
        if not self.allowed_ips:
            return True

        # 检查 IP 是否在白名单中
        return ip in self.allowed_ips

    def get_allowed_ips(self) -> List[str]:
        """获取允许的 IP 列表"""
        return list(self.allowed_ips)

    def add_ip(self, ip: str):
        """添加 IP 到白名单"""
        self.allowed_ips.add(ip)

    def remove_ip(self, ip: str):
        """从白名单中移除 IP"""
        self.allowed_ips.discard(ip)


class LLMProxyServer:
    """Nscan Proxy Server"""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.stats_dir = self.config_path.parent / "stats"
        self.stats_dir.mkdir(parents=True, exist_ok=True)

        # 加载初始配置
        self.config = self._load_config()

        # 初始化 IP 白名单
        server_config = self.config.get("server", {})
        allowed_ips = server_config.get("allowed_ips", [])
        self.ip_whitelist = IPWhitelist(allowed_ips)
        self.scan_container_subnets = parse_scan_container_subnets(self.config)

        # 初始化模型管理器
        self.model_manager = ModelManager(self.config, str(self.stats_dir))

        # 初始化配置监控
        self.config_watcher = ConfigWatcher(
            str(self.config_path), self._on_config_change
        )

        # HTTP 客户端
        self.http_client: Optional[httpx.AsyncClient] = None

        # Mimo Free Token
        self._mimo_free_token: Optional[str] = None
        self._mimo_free_token_expiry: float = 0.0
        self._mimo_token_lock: asyncio.Lock = asyncio.Lock()
        self._provider_balance_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._provider_balance_lock: asyncio.Lock = asyncio.Lock()
        self._openrouter_reasoning_capabilities: dict[str, dict[str, Any]] = {}
        self._openrouter_capabilities_updated_at: float = 0.0
        self._openrouter_capabilities_error: str = ""
        self._openrouter_capabilities_lock: asyncio.Lock = asyncio.Lock()
        self.is_shutting_down = False

    def _load_config(self) -> dict:
        """加载配置文件"""
        with open(self.config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        return validate_proxy_config(config)

    def _save_config(self, config: Optional[dict] = None, *, create_backup: bool = False):
        """保存配置文件，使用原子替换防止写入中断损坏。"""
        target_config = validate_proxy_config(config if config is not None else self.config)
        rendered = yaml.dump(
            target_config,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            dir=str(self.config_path.parent),
            prefix=f".{self.config_path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(rendered)
                f.flush()
                os.fsync(f.fileno())
            if create_backup and self.config_path.exists():
                backup_dir = self.config_path.parent / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_name = (
                    f"{self.config_path.stem}-"
                    f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
                    f"{self.config_path.suffix}"
                )
                shutil.copy2(self.config_path, backup_dir / backup_name)
            os.replace(temp_path, self.config_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _apply_runtime_config(self, new_config: dict):
        """Apply a validated config snapshot to in-memory runtime state."""
        validated = validate_proxy_config(new_config)
        self.config = validated
        self.model_manager.update_config(validated)
        self._provider_balance_cache.clear()

        server_config = validated.get("server", {})
        allowed_ips = server_config.get("allowed_ips", [])
        self.ip_whitelist._update_config(allowed_ips)
        self.scan_container_subnets = parse_scan_container_subnets(validated)
        self._apply_openrouter_reasoning_capabilities()

    def _on_config_change(self, new_config: dict):
        """配置变化回调"""
        self._apply_runtime_config(new_config)
        logger.info("配置已热更新")

    def _official_deepseek_model(self):
        fallback_order = (
            self.config.get("providers", {})
            .get("deepseek", {})
            .get("fallback_models", [])
        )
        for name in fallback_order:
            model = self.model_manager.models.get(name)
            if (
                model
                and model.provider == "deepseek"
                and model.api_key
                and model.api_base.rstrip("/") == "https://api.deepseek.com"
            ):
                return model
        for model in self.model_manager.models.values():
            if (
                model.provider == "deepseek"
                and model.api_key
                and model.api_base.rstrip("/") == "https://api.deepseek.com"
            ):
                return model
        return None

    async def get_provider_balances(self) -> dict[str, dict[str, Any]]:
        """Return provider account balances without exposing credentials."""
        balances: dict[str, dict[str, Any]] = {}
        deepseek = await self._get_deepseek_balance()
        if deepseek:
            balances["deepseek"] = deepseek
        return balances

    async def _get_deepseek_balance(self) -> dict[str, Any] | None:
        cache_key = "deepseek"
        now = time.time()
        cached = self._provider_balance_cache.get(cache_key)
        if cached and now - cached[0] < 300:
            return cached[1]

        model = self._official_deepseek_model()
        if not model:
            return None

        async with self._provider_balance_lock:
            cached = self._provider_balance_cache.get(cache_key)
            now = time.time()
            if cached and now - cached[0] < 300:
                return cached[1]

            payload: dict[str, Any] = {
                "provider": "deepseek",
                "available": False,
                "error": "",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                client = self.http_client or httpx.AsyncClient(timeout=10.0)
                close_client = self.http_client is None
                try:
                    response = await client.get(
                        "https://api.deepseek.com/user/balance",
                        headers={"Authorization": f"Bearer {model.api_key}"},
                        timeout=10,
                    )
                finally:
                    if close_client:
                        await client.aclose()
                if response.status_code != 200:
                    payload["error"] = f"HTTP {response.status_code}"
                else:
                    data = response.json()
                    balance_infos = data.get("balance_infos") or []
                    primary = balance_infos[0] if balance_infos else {}
                    payload.update(
                        {
                            "available": bool(data.get("is_available")),
                            "currency": primary.get("currency") or "",
                            "total_balance": primary.get("total_balance") or "0",
                            "granted_balance": primary.get("granted_balance") or "0",
                            "topped_up_balance": primary.get("topped_up_balance") or "0",
                        }
                    )
            except Exception as exc:
                payload["error"] = str(exc)[:120]

            self._provider_balance_cache[cache_key] = (time.time(), payload)
            return payload

    async def start(self):
        """启动服务"""
        self.is_shutting_down = False
        # 启动配置监控
        self.config_watcher.start()

        # 创建 HTTP 客户端
        self.http_client = httpx.AsyncClient(timeout=300.0)

        # 启动定时健康检查
        self.health_check_task = asyncio.create_task(self._health_check_loop())

        logger.info("Nscan Proxy Server 已启动")

    async def stop(self):
        """停止服务"""
        self.is_shutting_down = True
        self.config_watcher.stop()

        # 停止健康检查
        if hasattr(self, "health_check_task"):
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass

        if self.http_client:
            await self.http_client.aclose()

        logger.info("Nscan Proxy Server 已停止")

    def _configured_openrouter_models(self) -> dict[str, Any]:
        return {
            name: model
            for name, model in self.model_manager.models.items()
            if str(model.provider or "").lower() == "openrouter"
        }

    def _apply_openrouter_reasoning_capabilities(self) -> None:
        """Apply cached discovery without overwriting explicit operator choices."""
        stored = self.config.get("models", {}).get("available", {}) or {}
        for name, model in self._configured_openrouter_models().items():
            capability = self._openrouter_reasoning_capabilities.get(name) or {}
            if not capability.get("supported"):
                continue
            configured = stored.get(name, {}) or {}
            if "reasoning_supported" not in configured:
                model.reasoning_supported = True
            if "reasoning_api" not in configured or configured.get("reasoning_api") == "auto":
                model.reasoning_api = "openrouter"
            if "thinking_enabled" not in configured:
                model.thinking_enabled = True
            if "reasoning_effort" not in configured:
                # High is Nscan's default. OpenRouter maps it to the nearest
                # model-supported level when an exact high tier is unavailable.
                model.reasoning_effort = "high"

    async def refresh_openrouter_reasoning_capabilities(
        self, *, force: bool = False
    ) -> dict[str, Any]:
        """Refresh reasoning support for configured OpenRouter models only."""
        configured = self._configured_openrouter_models()
        if not configured:
            return self.get_openrouter_reasoning_status()

        async with self._openrouter_capabilities_lock:
            try:
                client = self.http_client or httpx.AsyncClient(timeout=15.0)
                close_client = self.http_client is None
                try:
                    response = await client.get(OPENROUTER_MODELS_URL, timeout=15.0)
                finally:
                    if close_client:
                        await client.aclose()
                response.raise_for_status()
                records = response.json().get("data", [])
                by_id = {
                    str(record.get("id") or "").lower(): record
                    for record in records
                    if isinstance(record, dict)
                }
                discovered: dict[str, dict[str, Any]] = {}
                for name, model in configured.items():
                    record = by_id.get(str(model.model or "").lower())
                    capability = normalize_openrouter_reasoning_capability(record or {})
                    capability["model_id"] = model.model
                    discovered[name] = capability
                self._openrouter_reasoning_capabilities = discovered
                self._openrouter_capabilities_updated_at = time.time()
                self._openrouter_capabilities_error = ""
                self._apply_openrouter_reasoning_capabilities()
                logger.info(
                    "Refreshed OpenRouter reasoning metadata for %s configured models",
                    len(discovered),
                )
            except Exception as exc:
                self._openrouter_capabilities_error = str(exc)[:200]
                logger.warning("OpenRouter reasoning metadata refresh failed: %s", exc)
            return self.get_openrouter_reasoning_status()

    def get_openrouter_reasoning_status(self) -> dict[str, Any]:
        return {
            "updated_at": (
                datetime.fromtimestamp(
                    self._openrouter_capabilities_updated_at, timezone.utc
                ).isoformat()
                if self._openrouter_capabilities_updated_at
                else None
            ),
            "refresh_trigger": "model_change_or_manual",
            "error": self._openrouter_capabilities_error,
            "models": copy.deepcopy(self._openrouter_reasoning_capabilities),
        }

    async def _health_check_loop(self):
        """定时健康检查循环"""
        while True:
            try:
                await asyncio.sleep(1800)  # 30 分钟

                # 检查并重新启用已到期的模型
                re_enabled = (
                    self.model_manager.health_checker.check_and_re_enable_models(
                        self.model_manager
                    )
                )
                if re_enabled:
                    logger.info(f"自动重新启用模型: {re_enabled}")

                # 检查所有 unhealthy 模型
                await self._check_unhealthy_models()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"健康检查循环错误: {e}")
                await asyncio.sleep(60)

    async def _check_unhealthy_models(self):
        """Probe unhealthy models without discarding operator-managed configuration."""
        health_report = self.model_manager.health_checker.get_health_report()
        models_to_disable = []
        models_to_reset = []

        for name, health in health_report.items():
            if health.get("healthy", True):
                continue
            if name not in self.model_manager.models:
                continue

            model_config = self.model_manager.models[name]
            reason = health.get("reason", "")

            # An invalid or expired credential is actionable, but it is not a
            # reason to destroy the model definition. Keep it for the operator
            # to update and explicitly re-enable.
            if (
                "401" in reason
                or "Invalid API Key" in reason.lower()
                or "authentication" in reason.lower()
            ):
                models_to_disable.append(name)
                logger.warning(f"模型 {name} 认证失败，已禁用并保留配置: {reason}")
                continue

            # 其他错误尝试探测
            try:
                model_id = model_config.model
                if "/" in model_id:
                    parts = model_id.split("/", 1)
                    if parts[0] in [
                        "nvidia",
                        "openai",
                        "openrouter",
                        "minimax",
                        "anthropic",
                        "xiaomi",
                    ]:
                        model_id = parts[1]

                test_body = {
                    "model": model_id,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_completion_tokens": 1,
                }
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {model_config.api_key}",
                }
                url = f"{model_config.api_base}/chat/completions"

                response = await self.http_client.post(
                    url, json=test_body, headers=headers, timeout=15
                )

                if response.status_code == 200:
                    models_to_reset.append(name)
                    logger.info(f"🟢 模型 {name} 探测成功，重置健康状态")
                elif response.status_code == 401:
                    models_to_disable.append(name)
                    logger.warning(f"模型 {name} 探测返回 401，已禁用并保留配置")
                else:
                    logger.debug(
                        f"模型 {name} 探测返回 {response.status_code}，保持状态"
                    )

            except httpx.TimeoutException:
                logger.debug(f"模型 {name} 探测超时")
            except Exception as e:
                logger.debug(f"模型 {name} 探测异常: {e}")

        # 重置恢复的模型
        for name in models_to_reset:
            self.model_manager.health_checker.mark_healthy(name)

        # Persist a disabled model instead of deleting it. This preserves its
        # provider mapping, limits, and credentials for an operator fix.
        for name in dict.fromkeys(models_to_disable):
            self.model_manager.disable_model(name, cooldown=False)
        if models_to_disable:
            self.model_manager.save_config(str(self.config_path))

    def _delete_model(self, model_name: str):
        """从配置中删除模型"""
        if model_name in self.config.get("models", {}).get("available", {}):
            del self.config["models"]["available"][model_name]

        # 从 fallback_models 中移除
        for provider, provider_config in self.config.get("providers", {}).items():
            if "fallback_models" in provider_config:
                if model_name in provider_config["fallback_models"]:
                    provider_config["fallback_models"].remove(model_name)

        # 从 per_model_limits 中移除
        if "usage" in self.config and "per_model_limits" in self.config["usage"]:
            if model_name in self.config["usage"]["per_model_limits"]:
                del self.config["usage"]["per_model_limits"][model_name]

        # 更新模型管理器
        self.model_manager.update_config(self.config)
        self._save_config()
        logger.info(f"🗑️ 模型 {model_name} 已从配置中删除")

    async def check_all_models(self) -> Dict[str, dict]:
        """检查所有模型的连接状态"""
        logger.info("开始检查所有模型连接状态...")
        results = {}

        for model_name, model_config in self.model_manager.models.items():
            if not model_config.enabled:
                results[model_name] = {
                    "status": "disabled",
                    "message": "Model is disabled",
                }
                continue

            try:
                start_time = time.time()

                # 构建测试请求
                model_id = model_config.model
                if "/" in model_id:
                    parts = model_id.split("/", 1)
                    if parts[0] in [
                        "nvidia",
                        "openai",
                        "openrouter",
                        "minimax",
                        "anthropic",
                    ]:
                        model_id = parts[1]

                test_body = {
                    "model": model_id,
                    "messages": [{"role": "user", "content": "Hi"}],
                    "max_completion_tokens": 5,
                }

                url = (
                    model_config.api_base
                    if model_config.is_exact_url
                    else f"{model_config.api_base}/chat/completions"
                )

                api_key = model_config.api_key
                headers = {
                    "Content-Type": "application/json",
                }

                if getattr(model_config, "provider", "") == "mimo-free":
                    api_key = await self._get_mimo_free_token()
                    headers["X-Mimo-Source"] = "mimocode-cli-free"

                headers["Authorization"] = f"Bearer {api_key}"

                if (
                    hasattr(model_config, "custom_headers")
                    and model_config.custom_headers
                ):
                    headers.update(model_config.custom_headers)

                response = await self.http_client.post(
                    url, json=test_body, headers=headers, timeout=30
                )

                duration = time.time() - start_time

                if response.status_code == 200:
                    results[model_name] = {
                        "status": "healthy",
                        "latency": round(duration, 3),
                        "message": "OK",
                    }
                    self.model_manager.handle_success(model_name)
                else:
                    results[model_name] = {
                        "status": "unhealthy",
                        "latency": round(duration, 3),
                        "message": f"HTTP {response.status_code}",
                        "error": response.text[:200],
                    }
                    self.model_manager.health_checker.mark_unhealthy(
                        model_name, f"HTTP {response.status_code}"
                    )

            except httpx.TimeoutException:
                results[model_name] = {
                    "status": "timeout",
                    "message": "Request timeout (30s)",
                }
                self.model_manager.health_checker.mark_unhealthy(model_name, "Timeout")
            except Exception as e:
                results[model_name] = {"status": "error", "message": str(e)[:200]}
                self.model_manager.health_checker.mark_unhealthy(
                    model_name, str(e)[:100]
                )

        # 记录结果
        healthy_count = sum(1 for r in results.values() if r["status"] == "healthy")
        total_count = len(results)
        logger.info(f"健康检查完成: {healthy_count}/{total_count} 模型可用")

        return results

    async def test_model(self, model_name: str) -> dict:
        """测试单个模型连接（支持禁用模型）"""
        if model_name not in self.model_manager.models:
            return {"status": "error", "message": f"Model {model_name} not found"}

        model_config = self.model_manager.models[model_name]

        try:
            start_time = time.time()

            # 判断是否使用 Anthropic 格式
            use_anthropic = getattr(model_config, "api_format", "openai") == "anthropic"

            if use_anthropic:
                # Anthropic 格式测试
                url = f"{model_config.api_base}/v1/messages"
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": model_config.api_key,
                    "anthropic-version": "2023-06-01",
                }
                test_body = {
                    "model": model_config.model,
                    "messages": [
                        {"role": "user", "content": "Hello, respond with one word."}
                    ],
                    "max_completion_tokens": 10,
                }

                response = await self.http_client.post(
                    url, json=test_body, headers=headers, timeout=30
                )
                duration = time.time() - start_time

                if response.status_code == 200:
                    data = response.json()
                    content = ""
                    if "content" in data and len(data["content"]) > 0:
                        content = data["content"][0].get("text", "")

                    usage = data.get("usage", {})
                    self.model_manager.handle_success(model_name)

                    return {
                        "status": "success",
                        "latency": round(duration, 3),
                        "model": model_config.model,
                        "provider": model_config.provider,
                        "response_preview": content[:100],
                        "usage": {
                            "input_tokens": usage.get("input_tokens", 0),
                            "output_tokens": usage.get("output_tokens", 0),
                        },
                        "message": "Connection successful",
                    }
                else:
                    error_text = response.text[:500]
                    self._on_provider_error(model_config, response.status_code, f"[{model_name}]")
                    self.model_manager.health_checker.mark_unhealthy(
                        model_name, f"HTTP {response.status_code}"
                    )
                    return {
                        "status": "error",
                        "latency": round(duration, 3),
                        "message": f"HTTP {response.status_code}",
                        "error": error_text,
                    }
            else:
                # OpenAI 格式测试
                model_id = model_config.model
                if "/" in model_id:
                    parts = model_id.split("/", 1)
                    if parts[0] in [
                        "nvidia",
                        "openai",
                        "openrouter",
                        "minimax",
                        "anthropic",
                        "xiaomi",
                    ]:
                        model_id = parts[1]

                test_body = {
                    "model": model_id,
                    "messages": [
                        {"role": "user", "content": "Hello, respond with one word."}
                    ],
                    "max_completion_tokens": 10,
                }

                url = (
                    model_config.api_base
                    if model_config.is_exact_url
                    else f"{model_config.api_base}/chat/completions"
                )

                retry_mimo = 0
                while True:
                    api_key = model_config.api_key
                    headers = {
                        "Content-Type": "application/json",
                    }

                    if getattr(model_config, "provider", "") == "mimo-free":
                        api_key = await self._get_mimo_free_token()
                        headers["X-Mimo-Source"] = "mimocode-cli-free"

                    headers["Authorization"] = f"Bearer {api_key}"

                    if (
                        hasattr(model_config, "custom_headers")
                        and model_config.custom_headers
                    ):
                        headers.update(model_config.custom_headers)

                    response = await self.http_client.post(
                        url, json=test_body, headers=headers, timeout=30
                    )
                    duration = time.time() - start_time
                    
                    if response.status_code == 403 and getattr(model_config, "provider", "") == "mimo-free" and retry_mimo == 0:
                        self._mimo_free_token = None
                        self._mimo_free_token_expiry = 0
                        retry_mimo += 1
                        continue

                    if response.status_code == 200:
                        data = response.json()
                        content = ""
                        if "choices" in data and len(data["choices"]) > 0:
                            message = data["choices"][0].get("message", {})
                            content = message.get("content") or message.get("reasoning") or ""

                        self.model_manager.handle_success(model_name)

                        return {
                            "status": "success",
                            "latency": round(duration, 3),
                            "model": model_config.model,
                            "provider": model_config.provider,
                            "response_preview": content[:100],
                            "message": "Connection successful",
                        }
                    else:
                        error_text = response.text[:500]
                        self._on_provider_error(model_config, response.status_code, f"[{model_name}]")
                        self.model_manager.health_checker.mark_unhealthy(
                            model_name, f"HTTP {response.status_code}"
                        )
                        return {
                            "status": "error",
                            "latency": round(duration, 3),
                            "message": f"HTTP {response.status_code}",
                            "error": error_text,
                        }

        except httpx.TimeoutException:
            self.model_manager.health_checker.mark_unhealthy(model_name, "Timeout")
            return {"status": "timeout", "message": "Request timeout (30s)"}
        except Exception as e:
            self.model_manager.health_checker.mark_unhealthy(model_name, str(e)[:100])
            return {"status": "error", "message": str(e)[:300]}

    def _on_provider_error(self, model_config, status_code: int, request_id: str = ""):
        """统一处理 Provider 返回的特定错误码"""
        if status_code == 403 and getattr(model_config, "provider", "") == "mimo-free":
            self._mimo_free_token = None
            self._mimo_free_token_expiry = 0
            prefix = f"{request_id} " if request_id else ""
            logger.info(f"{prefix}检测到 mimo-free 403 错误，已清理缓存的 Token")

    async def _get_mimo_free_token(self) -> str:
        """动态获取 Mimo Free API 的 JWT Token"""
        import time
        import uuid

        async with self._mimo_token_lock:
            if self._mimo_free_token and time.time() < self._mimo_free_token_expiry:
                return self._mimo_free_token

            url = "https://api.xiaomimimo.com/api/free-ai/bootstrap"
            client_id = f"proxy-{uuid.uuid4().hex[:8]}"
            try:
                response = await self.http_client.post(
                    url, json={"client": client_id}
                )
                if response.status_code == 200:
                    data = response.json()
                    self._mimo_free_token = data.get("jwt")
                    # 缩短缓存时间为 5 分钟 (300秒) 以防止意外过期
                    self._mimo_free_token_expiry = time.time() + 300
                    logger.info(f"成功获取 Mimo Free JWT Token (Client: {client_id})")
                    return self._mimo_free_token
                else:
                    logger.error(f"获取 Mimo Free Token 失败: HTTP {response.status_code}")
                    return ""
            except Exception as e:
                logger.error(f"获取 Mimo Free Token 异常: {e}")
                return ""

    def _handle_request_error(
        self,
        request_id: str,
        model_name: str,
        model_config,
        e: Exception,
        attempt: int,
        max_retries: int,
        start_time: float,
        scan_context: Optional[dict] = None,
    ):
        """处理请求异常并决定是否重试/切换模型"""
        # 释放模型并发锁
        self.model_manager.usage_controller.release_model(model_name)
        # 释放模型活跃状态
        self.model_manager.mark_model_inactive(model_name)

        status_code = getattr(e, "status_code", None)
        if status_code:
            self._on_provider_error(model_config, status_code, request_id)

        should_switch = self.model_manager.handle_error(model_name, e)

        if should_switch and attempt < max_retries:
            old_model = model_name
            # 尝试选择备用模型（跨 provider）
            fallback = self.model_manager.select_fallback_model(
                model_name, scan_context
            )
            
            reason_str = f"HTTP {status_code}" if status_code else str(e)
            from request_logger import request_logger
            error_detail = getattr(e, "detail", str(e)) if isinstance(e, HTTPException) else str(e)
            request_logger.log_response(
                request_id=request_id,
                model_name=model_name,
                duration=time.time() - start_time,
                status="failed",
                error=error_detail,
                scan_context=scan_context,
            )
            
            if fallback:
                new_model_name, new_model_config = fallback
                # select_fallback_model() reserves a concurrency slot while
                # checking candidates. The next loop iteration calls
                # select_model() again and will reserve the real request slot.
                # Without this release, every fallback switch leaks one active
                # request and redteam capacity eventually reaches 0 despite no
                # active LLM process.
                self.model_manager.usage_controller.release_model(new_model_name)
                logger.warning(
                    f"[{request_id}] 模型 {model_name} 请求失败 ({reason_str})，"
                    f"切换到备用模型: {new_model_name} ({attempt + 1}/{max_retries})"
                )
                request_logger.log_model_switch(
                    request_id=request_id,
                    from_model=old_model,
                    to_model=new_model_name,
                    reason=reason_str,
                    scan_context=scan_context,
                )
                return new_model_name, new_model_config
            else:
                # 没有备用模型，使用自动选择
                logger.warning(
                    f"[{request_id}] 模型 {model_name} 请求失败 ({reason_str})，"
                    f"切换模型重试 ({attempt + 1}/{max_retries})"
                )
                request_logger.log_model_switch(
                    request_id=request_id,
                    from_model=old_model,
                    to_model="auto",
                    reason=reason_str,
                    scan_context=scan_context,
                )
                return None, None
        else:
            # 记录失败
            from request_logger import request_logger
            error_detail = getattr(e, "detail", str(e)) if isinstance(e, HTTPException) else str(e)
            request_logger.log_response(
                request_id=request_id,
                model_name=model_name,
                duration=time.time() - start_time,
                status="failed",
                error=error_detail,
                scan_context=scan_context,
            )
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail=str(e))

    async def forward_request(
        self, model_name: str, model_config, request_body: dict, stream: bool = False
    ):
        """转发请求到后端 LLM API，内部自动适配 OpenAI/Anthropic 格式"""

        # 判断是否使用 Anthropic 格式
        use_anthropic = getattr(model_config, "api_format", "openai") == "anthropic"

        if use_anthropic:
            return await self._forward_anthropic(
                model_name, model_config, request_body, stream
            )
        else:
            return await self._forward_openai(
                model_name, model_config, request_body, stream
            )

    async def _forward_openai(
        self, model_name: str, model_config, request_body: dict, stream: bool
    ):
        """转发到 OpenAI 兼容 API"""
        url = (
            model_config.api_base
            if model_config.is_exact_url
            else f"{model_config.api_base}/chat/completions"
        )

        api_key = model_config.api_key
        headers = {
            "Content-Type": "application/json",
        }
        
        # Add custom headers
        if hasattr(model_config, "custom_headers") and model_config.custom_headers:
            headers.update(model_config.custom_headers)

        body = _prepare_openai_request_body(model_config, request_body)

        model_id = model_config.model
        if getattr(model_config, "strip_provider_prefix", True) and "/" in model_id:
            model_id = model_id.split("/", 1)[1]
        body["model"] = model_id

        retry_mimo = 0
        while True:
            if getattr(model_config, "provider", "") == "mimo-free":
                api_key = await self._get_mimo_free_token()
                headers["X-Mimo-Source"] = "mimocode-cli-free"

            headers["Authorization"] = f"Bearer {api_key}"

            if stream:
                req = self.http_client.build_request("POST", url, json=body, headers=headers)
                response = await self.http_client.send(req, stream=True)
                
                if response.status_code == 403 and getattr(model_config, "provider", "") == "mimo-free" and retry_mimo == 0:
                    await response.aclose()
                    self._mimo_free_token = None
                    self._mimo_free_token_expiry = 0
                    retry_mimo += 1
                    continue
                    
                if response.status_code != 200:
                    error_body = await response.aread()
                    await response.aclose()
                    raise HTTPException(
                        status_code=response.status_code, detail=error_body.decode()
                    )

                async def stream_generator(res) -> AsyncGenerator[bytes, None]:
                    try:
                        async for chunk in res.aiter_bytes():
                            yield chunk
                    finally:
                        await res.aclose()

                return StreamingResponse(stream_generator(response), media_type="text/event-stream")
            else:
                response = await self.http_client.post(url, json=body, headers=headers)
                
                if response.status_code == 403 and getattr(model_config, "provider", "") == "mimo-free" and retry_mimo == 0:
                    self._mimo_free_token = None
                    self._mimo_free_token_expiry = 0
                    retry_mimo += 1
                    continue
                    
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=response.status_code, detail=response.text
                    )
                return response.json()

    async def _forward_anthropic(
        self, model_name: str, model_config, request_body: dict, stream: bool
    ):
        """转发到 Anthropic API，自动转换 OpenAI 格式"""
        url = f"{model_config.api_base}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": model_config.api_key,
            "anthropic-version": "2023-06-01",
        }

        # OpenAI -> Anthropic 格式转换
        body = request_body.copy()
        model_id = model_config.model

        # 构建 Anthropic 请求
        anthropic_body = {
            "model": model_id,
            "max_tokens": body.get("max_tokens", 4096),
            "messages": body.get("messages", []),
        }

        # 添加 system prompt（如果有）
        if "system" in body:
            anthropic_body["system"] = body["system"]
        else:
            # 从 messages 中提取 system message
            messages = body.get("messages", [])
            if messages and messages[0].get("role") == "system":
                anthropic_body["system"] = messages[0].get("content", "")
                anthropic_body["messages"] = messages[1:]

        # 添加可选参数
        if "temperature" in body:
            anthropic_body["temperature"] = body["temperature"]
        if "top_p" in body:
            anthropic_body["top_p"] = body["top_p"]

        if stream:
            anthropic_body["stream"] = True

            async def stream_generator() -> AsyncGenerator[bytes, None]:
                async with self.http_client.stream(
                    "POST", url, json=anthropic_body, headers=headers
                ) as response:
                    if response.status_code != 200:
                        error_body = await response.aread()
                        raise HTTPException(
                            status_code=response.status_code, detail=error_body.decode()
                        )

                    # 转换 Anthropic SSE 到 OpenAI SSE
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                yield "data: [DONE]\n\n"
                                continue
                            try:
                                event = json.loads(data_str)
                                openai_chunk = self._anthropic_stream_to_openai(
                                    event, model_id
                                )
                                if openai_chunk:
                                    yield f"data: {json.dumps(openai_chunk)}\n\n"
                            except json.JSONDecodeError:
                                pass

            return StreamingResponse(stream_generator(), media_type="text/event-stream")
        else:
            response = await self.http_client.post(
                url, json=anthropic_body, headers=headers
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code, detail=response.text
                )

            # Anthropic -> OpenAI 格式转换
            anthropic_resp = response.json()
            return self._anthropic_to_openai(anthropic_resp, model_id)

    def _anthropic_to_openai(self, anthropic_resp: dict, model_id: str) -> dict:
        """将 Anthropic 响应转换为 OpenAI 格式"""
        content = ""
        for block in anthropic_resp.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        usage = anthropic_resp.get("usage", {})

        return {
            "id": anthropic_resp.get("id", ""),
            "object": "chat.completion",
            "created": int(datetime.now(timezone.utc).timestamp()),
            "model": model_id,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": anthropic_resp.get("stop_reason", "stop"),
                }
            ],
            "usage": {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("input_tokens", 0)
                + usage.get("output_tokens", 0),
            },
        }

    def _anthropic_stream_to_openai(self, event: dict, model_id: str) -> dict:
        """将 Anthropic 流式事件转换为 OpenAI 格式"""
        event_type = event.get("type", "")

        if event_type == "message_start":
            # message_start 包含 input_tokens
            message = event.get("message", {})
            usage = message.get("usage", {})
            if usage:
                return {
                    "id": f"chatcmpl-{int(datetime.now(timezone.utc).timestamp())}",
                    "object": "chat.completion.chunk",
                    "created": int(datetime.now(timezone.utc).timestamp()),
                    "model": model_id,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": ""},
                            "finish_reason": None,
                        }
                    ],
                    "usage": {
                        "prompt_tokens": usage.get("input_tokens", 0),
                        "completion_tokens": 0,
                        "total_tokens": usage.get("input_tokens", 0),
                    },
                }
            return None

        elif event_type == "content_block_delta":
            delta = event.get("delta", {})
            if delta.get("type") == "text_delta":
                return {
                    "id": f"chatcmpl-{int(datetime.now(timezone.utc).timestamp())}",
                    "object": "chat.completion.chunk",
                    "created": int(datetime.now(timezone.utc).timestamp()),
                    "model": model_id,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": delta.get("text", "")},
                            "finish_reason": None,
                        }
                    ],
                }

        elif event_type == "message_delta":
            # message_delta 包含 output_tokens
            delta = event.get("delta", {})
            usage = event.get("usage", {})
            return {
                "id": f"chatcmpl-{int(datetime.now(timezone.utc).timestamp())}",
                "object": "chat.completion.chunk",
                "created": int(datetime.now(timezone.utc).timestamp()),
                "model": model_id,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": delta.get("stop_reason", "stop"),
                    }
                ],
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": usage.get("output_tokens", 0),
                    "total_tokens": usage.get("output_tokens", 0),
                },
            }

        return None


def create_app(config_path: str) -> FastAPI:
    """创建 FastAPI 应用"""
    server = LLMProxyServer(config_path)

    # FindingsService 单例 — 提前实例化以便在 lifespan 中预热
    _findings_service = FindingsService()
    # Smart Batch Job Manager 单例
    _job_manager = SmartBatchJobManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await server.start()
        await _findings_service.start()   # 启动时预热 Findings 索引
        yield
        await _findings_service.stop()
        await server.stop()

    app = FastAPI(
        title="Nscan Runtime Dashboard",
        description="Nscan 扫描运行、模型代理与 Docker egress 观测面板",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS 中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 挂载静态文件
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def get_client_ip(request: Request) -> str:
        """获取客户端 IP"""
        # 检查 X-Forwarded-For 头
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        # 检查 X-Real-IP 头
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        # 直接连接
        return request.client.host if request.client else "unknown"

    def get_peer_ip(request: Request) -> str:
        """Return the TCP peer address for access control; never trust forwarded headers."""
        return request.client.host if request.client else "unknown"

    def get_scan_context(request: Request) -> dict:
        """读取 smart batch 注入的本地扫描上下文。"""
        context = {}
        for key, header_name in SCAN_CONTEXT_FIELD_HEADERS.items():
            value = sanitize_scan_context_value(request.headers.get(header_name) or "")
            if value:
                context[key] = value
        if not context.get("scan_mode"):
            context["scan_mode"] = "redteam"
        return context

    def get_dashboard_pin() -> tuple[str, str]:
        """Return configured dashboard PIN and its source, without exposing it."""
        env_pin = (os.environ.get("NSCAN_DASHBOARD_PIN") or "").strip()
        if env_pin:
            return env_pin, "env:NSCAN_DASHBOARD_PIN"
        admin_config = server.config.get("admin") or {}
        pin = str(admin_config.get("pin_code") or "").strip()
        if pin:
            return pin, "config:admin.pin_code"
        legacy_pin = str(admin_config.get("api_key") or "").strip()
        if legacy_pin:
            return legacy_pin, "config:admin.api_key"
        return "", ""

    def get_dashboard_session_days() -> int:
        raw = os.environ.get("NSCAN_DASHBOARD_SESSION_DAYS") or (
            server.config.get("admin") or {}
        ).get("session_days", 30)
        try:
            return max(1, min(int(raw), 365))
        except (TypeError, ValueError):
            return 30

    def get_dashboard_session_secret() -> bytes:
        configured = (os.environ.get("NSCAN_DASHBOARD_SESSION_SECRET") or "").strip()
        if configured:
            return configured.encode("utf-8")
        secret_path = server.config_path.parent / "runtime" / "dashboard_session_secret"
        secret_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            secret = secret_path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            secret = secrets.token_urlsafe(48)
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(secret)
        return secret.encode("ascii")

    dashboard_session_secret = get_dashboard_session_secret()

    def create_dashboard_session(pin: str) -> tuple[str, int]:
        max_age = get_dashboard_session_days() * 86400
        expires_at = int(time.time()) + max_age
        nonce = secrets.token_urlsafe(16)
        payload = f"{expires_at}.{nonce}"
        key = hmac.new(dashboard_session_secret, pin.encode("utf-8"), hashlib.sha256).digest()
        signature = hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"{payload}.{encoded}", max_age

    def dashboard_session_is_valid(token: str, pin: str) -> bool:
        try:
            expires_text, nonce, encoded = token.split(".", 2)
            expires_at = int(expires_text)
        except (TypeError, ValueError):
            return False
        if expires_at < int(time.time()) or not nonce or not encoded:
            return False
        payload = f"{expires_at}.{nonce}"
        key = hmac.new(dashboard_session_secret, pin.encode("utf-8"), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(
            hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")
        return hmac.compare_digest(encoded, expected)

    def get_security_status(request: Request | None = None) -> dict:
        """Return dashboard access-control status without secrets."""
        allowed_ips = server.ip_whitelist.get_allowed_ips()
        pin, pin_source = get_dashboard_pin()
        warnings = []
        if not allowed_ips:
            warnings.append("IP whitelist is empty; remote clients are allowed unless blocked upstream.")
        if not pin:
            warnings.append("Dashboard PIN is not configured; write APIs are not PIN-protected.")
        return {
            "ip_whitelist": {
                "configured": bool(allowed_ips),
                "count": len(allowed_ips),
                "allowed_ips": allowed_ips,
            },
            "pin": {
                "configured": bool(pin),
                "source": pin_source or None,
                "header": "X-Nscan-Pin",
                "session_valid": bool(
                    pin
                    and request
                    and dashboard_session_is_valid(
                        request.cookies.get(DASHBOARD_SESSION_COOKIE, ""), pin
                    )
                ),
                "session_days": get_dashboard_session_days(),
            },
            "write_methods_pin_protected": bool(pin),
            "warnings": warnings,
        }

    def request_has_valid_pin(request: Request) -> bool:
        pin, _source = get_dashboard_pin()
        if not pin:
            return True
        session_token = request.cookies.get(DASHBOARD_SESSION_COOKIE, "")
        if session_token and dashboard_session_is_valid(session_token, pin):
            return True
        provided = (
            request.headers.get("X-Nscan-Pin")
            or request.headers.get("X-Strix-Pin")
            or request.query_params.get("pin")
            or ""
        ).strip()
        return bool(provided) and hmac.compare_digest(provided, pin)

    def _build_login_gate_html() -> str:
        """Return a minimal full-screen PIN login page served before the SPA loads."""
        return '''<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nscan Dashboard — 登录</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 50%,#0f0f1a 100%);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#e2e8f0}
  .card{background:rgba(30,30,60,.85);border:1px solid rgba(99,102,241,.3);
    border-radius:16px;padding:2.5rem;width:360px;box-shadow:0 25px 50px rgba(0,0,0,.5);
    backdrop-filter:blur(12px)}
  .logo{text-align:center;margin-bottom:1.8rem}
  .logo svg{width:48px;height:48px;fill:none;stroke:#6366f1;stroke-width:1.5}
  h1{font-size:1.25rem;font-weight:600;text-align:center;margin-bottom:.25rem}
  .subtitle{font-size:.8rem;color:#94a3b8;text-align:center;margin-bottom:1.8rem}
  label{font-size:.8rem;font-weight:500;color:#94a3b8;display:block;margin-bottom:.4rem}
  input[type=password]{width:100%;padding:.65rem .9rem;background:rgba(15,15,30,.8);
    border:1px solid rgba(99,102,241,.4);border-radius:8px;color:#e2e8f0;font-size:1rem;
    letter-spacing:.2em;outline:none;transition:border .2s}
  input[type=password]:focus{border-color:#6366f1}
  button{margin-top:1.2rem;width:100%;padding:.75rem;background:linear-gradient(135deg,#6366f1,#818cf8);
    color:#fff;border:none;border-radius:8px;font-size:.95rem;font-weight:600;
    cursor:pointer;transition:opacity .2s}
  button:hover{opacity:.88}
  .err{margin-top:.9rem;font-size:.8rem;color:#f87171;text-align:center;min-height:1.1em}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
  </div>
  <h1>Nscan Dashboard</h1>
  <p class="subtitle">请输入管理 PIN 码以继续</p>
  <form id="f">
    <label for="pin">管理 PIN</label>
    <input id="pin" type="password" placeholder="••••••" autocomplete="current-password" autofocus>
    <button type="submit">解锁面板</button>
  </form>
  <div class="err" id="err"></div>
</div>
<script>
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();
  const pin=document.getElementById("pin").value.trim();
  const err=document.getElementById("err");
  if(!pin){err.textContent="请输入 PIN 码";return;}
  err.textContent="验证中…";
  const res=await fetch("/proxy/security/verify",{
    method:"POST",
    headers:{"Content-Type":"application/json","X-Nscan-Pin":pin},
    body:JSON.stringify({pin})
  });
  if(res.ok){location.reload();}
  else{err.textContent="PIN 错误，请重试";document.getElementById("pin").value="";}
});
</script>
</body>
</html>'''

    def request_needs_pin(request: Request) -> bool:
        """Return True when a valid PIN (or session cookie) must be present."""
        path = request.url.path
        # Bootstrap endpoints: always free so the login gate JS can call them
        if path in {"/proxy/security/status", "/proxy/security/verify"}:
            return False
        # LLM inference: loopback-only via IP whitelist; no PIN needed
        if path.startswith("/v1/"):
            return False
        # All dashboard pages and management APIs require auth
        if path in {"/", "/settings"} or path.startswith("/proxy/") or path.startswith("/static/"):
            return True
        return False

    @app.middleware("http")
    async def ip_whitelist_middleware(request: Request, call_next):
        """IP 白名单和全局 dashboard PIN 中间件"""
        client_ip = get_client_ip(request)
        peer_ip = get_peer_ip(request)
        is_local_client = peer_ip in ["127.0.0.1", "::1", "localhost"]
        path = request.url.path

        if is_scan_container_peer(peer_ip, server.scan_container_subnets):
            if path not in SCAN_CONTAINER_ALLOWED_PATHS:
                logger.warning("拒绝扫描容器访问管理面: %s - %s", peer_ip, path)
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Scan containers may only access inference endpoints"},
                )
            return await call_next(request)

        # Enforce IP whitelist (TCP peer address, not spoofable forwarded headers)
        if not is_local_client and not server.ip_whitelist.is_allowed(peer_ip):
            logger.warning(f"拒绝访问: {peer_ip} - {request.url.path}")
            return JSONResponse(
                status_code=403, content={"detail": f"IP {peer_ip} not allowed"}
            )

        if request_needs_pin(request) and not request_has_valid_pin(request):
            accept = request.headers.get("accept", "")
            # Browser page request: return a full-screen PIN login gate HTML
            if "text/html" in accept and path in {"/", "/settings"}:
                return HTMLResponse(content=_build_login_gate_html(), status_code=401)
            logger.warning(f"Dashboard PIN required: {client_ip} - {request.url.path}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Dashboard PIN required", "header": "X-Nscan-Pin"},
            )

        response = await call_next(request)
        return response

    # ==================== Web 面板路由 ====================

    @app.get("/", response_class=HTMLResponse)
    async def index():
        """Web 面板首页"""
        html_file = static_dir / "index.html"
        if html_file.exists():
            return HTMLResponse(
                content=html_file.read_text(encoding="utf-8"),
                headers={"Cache-Control": "no-store, max-age=0"},
            )
        return HTMLResponse(content="<h1>Nscan Runtime Dashboard</h1><p>Web 面板未找到</p>")

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page():
        """设置页面"""
        html_file = static_dir / "settings.html"
        if html_file.exists():
            return HTMLResponse(
                content=html_file.read_text(encoding="utf-8"),
                headers={"Cache-Control": "no-store, max-age=0"},
            )
        return HTMLResponse(content="<h1>Settings</h1><p>设置页面未找到</p>")

    # ==================== LLM API 代理路由 ====================

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        """代理 LLM 请求"""
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip(request)
        scan_context = get_scan_context(request)

        try:
            body = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request body: {e}") from e

        stream = body.get("stream", False)
        requested_model = body.get("model", None)
        messages = body.get("messages", [])
        max_configured_context = max(
            (
                model.max_context_tokens
                for model in server.model_manager.models.values()
                if model.enabled
                and model.name not in server.model_manager.disabled_models
                and model.max_context_tokens
            ),
            default=0,
        )
        if max_configured_context:
            estimated_context = estimate_request_context_tokens(body)
            if estimated_context > max_configured_context:
                compact_budget = max(32_768, int(max_configured_context * 0.95))
                body, compacted = compact_request_context(body, compact_budget)
                if compacted:
                    logger.info(
                        "[%s] compacted LLM context because it exceeds the configured model context window: estimated=%s budget=%s new_estimated=%s",
                        request_id,
                        estimated_context,
                        compact_budget,
                        estimate_request_context_tokens(body),
                    )
                    messages = body.get("messages", [])
        routing_context = dict(scan_context or {})
        routing_context["required_context_tokens"] = estimate_request_context_tokens(body)
        max_retries = server.model_manager.health_checker.max_retries
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                model_name, model_config = server.model_manager.select_model(
                    requested_model, routing_context
                )
            except NoAvailableModelError as e:
                raise HTTPException(status_code=503, detail=str(e)) from e

            # 检查模型是否被禁用（禁用后自动切换）
            if model_name in server.model_manager.disabled_models:
                logger.info(f"[{request_id}] 模型 {model_name} 已禁用，重新选择")
                server.model_manager.usage_controller.release_model(model_name)
                continue

            try:
                start_time = time.time()

                # 标记模型为活跃状态（避免 fallback 时选中正在使用的模型）
                server.model_manager.mark_model_active(model_name)
                # 并发锁已在 select_model 中原子获取

                # 记录请求开始
                request_logger.log_request(
                    request_id=request_id,
                    client_ip=client_ip,
                    requested_model=requested_model or "auto",
                    actual_model=model_name,
                    provider=model_config.provider,
                    messages=_sanitize_reasoning_messages(
                        messages, preserve_tool_reasoning=False
                    ),
                    stream=stream,
                    model_id=model_config.model,
                    scan_context=scan_context,
                )

                if stream:
                    response = await server.forward_request(
                        model_name, model_config, body, stream=True
                    )

                    async def stream_with_logging():
                        total_tokens = 0
                        input_tokens = 0
                        output_tokens = 0
                        cached_input_tokens = 0
                        model_switched = False
                        valid_chunk_count = 0
                        finish_reason_stop = False
                        has_content_in_delta = False
                        stream_error: Optional[str] = None
                        client_cancelled = False
                        final_usage: dict = {}
                        try:
                            async for chunk in response.body_iterator:
                                if (
                                    model_name in server.model_manager.disabled_models
                                    and not model_switched
                                ):
                                    logger.warning(
                                        f"[{request_id}] 流式中检测到模型 {model_name} 被禁用，中断切换"
                                    )
                                    model_switched = True
                                    error_event = json.dumps(
                                        {
                                            "error": {
                                                "message": f"Model {model_name} was disabled, please retry",
                                                "type": "model_disabled",
                                                "code": "model_switched",
                                            }
                                        }
                                    )
                                    yield f"data: {error_event}\n\n"
                                    break

                                # Preserve native tool-turn reasoning for the
                                # agent SDK, but never persist it in Nscan logs.
                                # Collect diagnostics from every
                                # SSE data line. A single network chunk may
                                # contain multiple data events, and some
                                # providers omit usage while still streaming
                                # valid assistant content.
                                chunk, stream_diag = normalize_openai_sse_chunk(
                                    chunk,
                                    preserve_reasoning_content=_uses_native_reasoning(model_config),
                                )
                                if stream_diag.get("has_content"):
                                    has_content_in_delta = True
                                usage = stream_diag.get("usage")
                                if usage:
                                    total_tokens = usage.get("total_tokens", 0)
                                    input_tokens = usage.get("prompt_tokens", 0)
                                    output_tokens = usage.get("completion_tokens", 0)
                                    cached_input_tokens = _cached_input_tokens(usage)
                                    final_usage = usage
                                if stream_diag.get("finish_reason") in ("stop", "length"):
                                    finish_reason_stop = True
                                if stream_diag.get("error"):
                                    stream_error = stream_diag["error"]

                                yield chunk
                                try:
                                    chunk_str = chunk.decode() if isinstance(chunk, bytes) else chunk
                                    if chunk_str.strip():
                                        valid_chunk_count += 1
                                except (UnicodeDecodeError, AttributeError) as exc:
                                    logger.debug("Unable to inspect streaming chunk: %s", exc)
                        except (asyncio.CancelledError, GeneratorExit):
                            # Starlette closes the async generator when the
                            # caller disconnects or abandons a stream. On
                            # modern Python CancelledError is not an Exception,
                            # so it previously skipped response logging and
                            # appeared forever as stale_no_response.
                            client_cancelled = True
                            stream_error = (
                                "Service shutting down"
                                if server.is_shutting_down
                                else "Client disconnected"
                            )
                            logger.info(f"[{request_id}] 流式响应中断: {stream_error}")
                        except Exception as e:
                            logger.warning(f"[{request_id}] 流式响应异常: {e}")
                            stream_error = str(e)
                            server.model_manager.handle_error(model_name, e)
                        finally:
                            server.model_manager.usage_controller.release_model(
                                model_name
                            )
                            server.model_manager.mark_model_inactive(model_name)

                        duration = time.time() - start_time

                        has_real_output = (
                            total_tokens > 0
                            or has_content_in_delta
                            or (valid_chunk_count > 2 and finish_reason_stop)
                        )
                        # The OpenAI Agents SDK often closes a streamed HTTP
                        # response as soon as it has received a complete tool
                        # call. Starlette surfaces that as GeneratorExit /
                        # CancelledError even though useful content and usage
                        # were already delivered. Treat those as successful
                        # early client closes so Activity does not show them as
                        # provider failures.
                        client_closed_after_output = client_cancelled and has_real_output
                        is_success = (
                            (not stream_error and has_real_output)
                            or client_closed_after_output
                        )

                        if is_success:
                            server.model_manager.handle_success(model_name)
                            if final_usage:
                                server.model_manager.record_usage(model_name, final_usage)
                            elif total_tokens == 0:
                                server.model_manager.record_usage(
                                    model_name,
                                    {"total_tokens": 1, "prompt_tokens": 0, "completion_tokens": 0},
                                )
                        elif not client_cancelled:
                            error_msg = stream_error or "Empty upstream response"
                            server.model_manager.handle_error(model_name, RuntimeError(error_msg))

                        status, final_error = classify_stream_completion(
                            is_success=is_success,
                            client_cancelled=client_cancelled,
                            client_closed_after_output=client_closed_after_output,
                            server_shutting_down=server.is_shutting_down,
                            total_tokens=total_tokens,
                            stream_error=stream_error,
                        )

                        # 记录请求完成
                        logged_usage = _usage_with_billing(
                            server,
                            model_name,
                            model_config,
                            {
                                **final_usage,
                                "total_tokens": total_tokens,
                                "prompt_tokens": input_tokens,
                                "completion_tokens": output_tokens,
                                "cached_input_tokens": cached_input_tokens,
                            },
                        )
                        request_logger.log_response(
                            request_id=request_id,
                            model_name=model_name,
                            duration=duration,
                            status=status,
                            usage=logged_usage,
                            error=final_error,
                            scan_context=scan_context,
                        )

                        logger.info(
                            f"[{request_id}] 流式请求{'完成' if is_success else '失败'}: {model_name} | "
                            f"耗时: {duration:.2f}s | tokens: {total_tokens}"
                            f"{' | client_closed_after_output' if client_closed_after_output else ''}"
                        )

                    return StreamingResponse(
                        stream_with_logging(), media_type="text/event-stream"
                    )
                else:
                    # 非流式请求前检查模型是否被禁用
                    if model_name in server.model_manager.disabled_models:
                        logger.warning(
                            f"[{request_id}] 模型 {model_name} 在发送前被禁用，重新选择"
                        )
                        server.model_manager.usage_controller.release_model(model_name)
                        server.model_manager.mark_model_inactive(model_name)
                        continue

                    response_data = await server.forward_request(
                        model_name, model_config, body, stream=False
                    )

                    # Native reasoning returns to the SDK only when tool-turn
                    # continuity is required.
                    if isinstance(response_data, dict) and not _uses_native_reasoning(model_config):
                        choices = response_data.get("choices")
                        if isinstance(choices, list):
                            for c in choices:
                                if not isinstance(c, dict):
                                    continue
                                msg = c.get("message") or {}
                                if isinstance(msg, dict):
                                    msg.pop("reasoning_content", None)

                    duration = time.time() - start_time
                    usage = _usage_with_billing(
                        server, model_name, model_config, response_data.get("usage", {})
                    )
                    server.model_manager.record_usage(model_name, usage)
                    server.model_manager.handle_success(model_name)

                    # 释放模型并发锁
                    server.model_manager.usage_controller.release_model(model_name)
                    # 释放模型活跃状态
                    server.model_manager.mark_model_inactive(model_name)

                    # 记录请求完成
                    request_logger.log_response(
                        request_id=request_id,
                        model_name=model_name,
                        duration=duration,
                        status="success",
                        usage=usage,
                        scan_context=scan_context,
                    )

                    logger.info(
                        f"[{request_id}] 请求完成: {model_name} | "
                        f"耗时: {duration:.2f}s | "
                        f"tokens: {usage.get('total_tokens', 0)}"
                    )

                    return JSONResponse(content=response_data)

            except Exception as e:
                last_error = e
                try:
                    next_model, next_config = server._handle_request_error(
                        request_id,
                        model_name,
                        model_config,
                        e,
                        attempt,
                        max_retries,
                        start_time,
                        scan_context=routing_context,
                    )
                    model_name = next_model
                    model_config = next_config
                    requested_model = next_model
                    continue
                except HTTPException as he:
                    raise he

        if last_error:
            raise last_error
        raise HTTPException(status_code=500, detail="All retries failed")

    @app.get("/v1/models")
    async def list_models():
        """返回可用模型列表"""
        models = []
        for name, config in server.model_manager.models.items():
            models.append(
                {
                    "id": name,
                    "object": "model",
                    "created": 0,
                    "owned_by": "proxy",
                    "permission": [],
                }
            )

        return {
            "object": "list",
            "data": models,
        }

    # ==================== 管理 API 路由 ====================

    @app.get("/proxy/status")
    async def proxy_status(scan_mode: str = "redteam"):
        """返回代理状态"""
        routing_context = {"scan_mode": str(scan_mode or "").strip().lower()}
        models = server.model_manager.get_all_models_status(routing_context)
        reasoning_capabilities = server.get_openrouter_reasoning_status()
        for name, capability in reasoning_capabilities.get("models", {}).items():
            if name in models:
                models[name]["reasoning_capability"] = capability
        return {
            "status": "running",
            "models": models,
            "openrouter_reasoning_capabilities": reasoning_capabilities,
            "usage": server.model_manager.usage_controller.get_usage_report(),
            "provider_balances": await server.get_provider_balances(),
            "health": server.model_manager.health_checker.get_health_report(),
            "schedule": server.model_manager.time_controller.get_status(),
            "config": server.config_watcher.get_status(),
            "routing": {
                "mode": server.model_manager.get_routing_mode(),
                "enabled_models": server.model_manager._get_available_models(),
                "description": (
                    "All eligible enabled models participate"
                    if server.model_manager.get_routing_mode() == "balanced_all"
                    else "Only the highest-priority eligible models participate"
                ),
            },
        }

    @app.get("/proxy/health")
    async def proxy_health():
        """返回健康检查结果"""
        return server.model_manager.health_checker.get_health_report()

    @app.get("/proxy/usage")
    async def proxy_usage():
        """返回使用量报告"""
        return server.model_manager.usage_controller.get_usage_report()

    @app.get("/proxy/usage/trend")
    async def proxy_usage_trend(granularity: str = "4h", model: str = None, group_by: str = "provider"):
        """返回趋势数据

        Args:
            granularity: 时间粒度，"day" 或 "4h"
            model: 模型名称，可选
            group_by: "provider" 或 "model"
        """
        safe_group_by = group_by if group_by in {"provider", "model", "billing"} else "provider"
        trend_group_by = "provider" if safe_group_by == "billing" else safe_group_by
        if granularity == "day":
            # Historical trend is database-first. JSON usage files remain a
            # recovery/export copy, but no longer decide dashboard history.
            history = await asyncio.to_thread(get_asset_database().usage_history, days=30)
            if history:
                trend = server.model_manager.usage_controller.daily_trend_from_history(
                    history, model, trend_group_by,
                )
                trend["billing"] = await asyncio.to_thread(
                    get_asset_database().response_billing_trend,
                    labels=trend.get("labels") or [],
                    granularity="day",
                )
                return trend
        else:
            # The response ledger is durable per request and therefore cannot
            # lose the current hour during a proxy restart.
            hourly = await asyncio.to_thread(get_asset_database().hourly_response_usage)
            if hourly:
                trend = server.model_manager.usage_controller.hourly_trend_from_history(
                    hourly, model, trend_group_by,
                )
                trend["billing"] = await asyncio.to_thread(
                    get_asset_database().response_billing_trend,
                    labels=trend.get("labels") or [],
                    granularity="4h",
                )
                return trend
        trend = server.model_manager.usage_controller.get_trend_data(
            granularity, model, trend_group_by
        )
        trend["billing"] = await asyncio.to_thread(
            get_asset_database().response_billing_trend,
            labels=trend.get("labels") or [],
            granularity=granularity,
        )
        return trend

    @app.get("/proxy/system/resources")
    async def proxy_system_resources():
        """返回服务器资源状态"""
        return get_system_resources()

    @app.get("/proxy/security/status")
    async def proxy_security_status(request: Request):
        """返回看板访问控制状态，不返回 PIN 原文。"""
        return get_security_status(request)

    @app.post("/proxy/security/verify")
    async def proxy_security_verify(request: Request):
        """PIN middleware 已验证该请求，签发持久管理会话。"""
        pin, source = get_dashboard_pin()
        payload = {
            "valid": True,
            "configured": bool(pin),
            "source": source or None,
            "session_days": get_dashboard_session_days(),
        }
        response = JSONResponse(content=payload)
        if pin:
            token, max_age = create_dashboard_session(pin)
            response.set_cookie(
                DASHBOARD_SESSION_COOKIE,
                token,
                max_age=max_age,
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                path="/",
            )
        return response

    @app.post("/proxy/security/logout")
    async def proxy_security_logout():
        """Clear the persistent dashboard administration session."""
        response = JSONResponse(content={"logged_out": True})
        response.delete_cookie(DASHBOARD_SESSION_COOKIE, path="/", samesite="strict")
        return response

    @app.get("/proxy/smart-batch/status")
    async def proxy_smart_batch_status(
        limit: int = Query(20, ge=1, le=200),
        include_finished: bool = True,
        include_tasks: bool = True,
    ):
        """返回 Smart Batch 运行状态快照列表"""
        return read_smart_batch_status(
            limit=limit,
            include_finished=include_finished,
            include_tasks=include_tasks,
        )

    @app.get("/proxy/smart-batch/status/{batch_id}")
    async def proxy_smart_batch_detail(batch_id: str):
        """返回单个 Smart Batch 运行状态快照"""
        detail = read_smart_batch_detail(batch_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"Smart Batch {batch_id} not found")
        return detail

    @app.get("/proxy/nscan-runtime/status")
    @app.get("/proxy/strix-runtime/status")
    async def proxy_nscan_runtime_status(check_nodes: bool = False):
        """返回 Nscan 运行与 egress 代理状态"""
        return get_strix_runtime_status(check_nodes=check_nodes)

    @app.get("/proxy/docker/containers")
    async def proxy_docker_containers():
        """返回正在运行的 strix 扫描 Docker 容器实时状态。"""
        import subprocess as _sp, json as _json, shutil as _shutil
        import datetime as _dt
        docker_bin = _shutil.which("docker")
        if not docker_bin:
            return {"available": False, "strix_containers": [], "error": "docker not found"}
        try:
            fmt = (
                '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}",'
                '"status":"{{.Status}}","state":"{{.State}}","created":"{{.CreatedAt}}"}' 
            )
            result = _sp.run(  # noqa: S603 - fixed docker argv, no shell, local read-only status command
                [docker_bin, "ps", "-a", "--format", fmt],
                capture_output=True, text=True, timeout=8, check=False,
            )
            all_containers = []
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    all_containers.append(_json.loads(line))
                except (TypeError, ValueError, _json.JSONDecodeError) as exc:
                    logger.debug("Ignoring malformed Docker status row: %s", exc)

            strix = [c for c in all_containers if "strix-scan" in c.get("name", "") or "strix-sandbox" in c.get("image", "")]
            other = [c for c in all_containers if "strix-scan" not in c.get("name", "")]

            enriched = []
            for c in strix:
                entry = dict(c)
                try:
                    insp = _sp.run(  # noqa: S603 - fixed docker argv, container id comes from docker ps
                        [docker_bin, "inspect", c["id"],
                         "--format",
                         "{{.HostConfig.NetworkMode}}|{{.State.Pid}}|{{.State.StartedAt}}|{{range .Config.Env}}{{.}} {{end}}"],
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    parts = insp.stdout.strip().split("|", 3)
                    if len(parts) == 4:
                        entry["network_mode"] = parts[0]
                        entry["pid"] = parts[1]
                        entry["started_at"] = parts[2]
                        for ev in parts[3].split():
                            if ev.startswith("TARGET=") or ev.startswith("STRIX_TARGET="):
                                entry["target"] = ev.split("=", 1)[1]
                                break
                except (OSError, _sp.SubprocessError, KeyError, ValueError) as exc:
                    logger.debug("Unable to enrich Docker container %s: %s", c.get("id", "unknown"), exc)
                enriched.append(entry)

            running_count = sum(1 for c in strix if c.get("state", "").lower() == "running")
            return {
                "available": True,
                "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "summary": {
                    "strix_total": len(strix),
                    "strix_running": running_count,
                    "strix_exited": len(strix) - running_count,
                    "other_total": len(other),
                },
                "strix_containers": enriched,
                "other_containers": other[:8],
            }
        except Exception as exc:
            return {"available": False, "strix_containers": [], "error": str(exc)}


    def read_enabled_flag(body: dict) -> bool:
        if "enabled" not in body:
            raise HTTPException(status_code=400, detail="Missing enabled boolean")
        if not isinstance(body["enabled"], bool):
            raise HTTPException(status_code=400, detail="enabled must be a boolean")
        return body["enabled"]

    @app.post("/proxy/nscan-runtime/proxy-enabled")
    @app.post("/proxy/strix-runtime/proxy-enabled")
    async def proxy_nscan_runtime_proxy_enabled(request: Request):
        """启用或关闭 Nscan Docker egress 代理当前运行状态。"""
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}") from exc
        return set_strix_egress_enabled(read_enabled_flag(body))

    @app.post("/proxy/nscan-runtime/proxy-startup-enabled")
    @app.post("/proxy/strix-runtime/proxy-startup-enabled")
    async def proxy_nscan_runtime_proxy_startup_enabled(request: Request):
        """启用或关闭 Nscan Docker egress 代理开机自启状态。"""
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}") from exc
        return set_strix_egress_startup_enabled(read_enabled_flag(body))

    @app.post("/proxy/nscan-runtime/nodes/{node_tag}/enabled")
    async def proxy_nscan_runtime_node_enabled(node_tag: str, request: Request):
        """Enable or disable one SOCKS5 node in the automatic egress pool."""
        try:
            body = await request.json()
            return set_strix_egress_node_enabled(node_tag, read_enabled_flag(body))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/proxy/nscan-runtime/proxy-restart")
    @app.post("/proxy/strix-runtime/proxy-restart")
    async def proxy_nscan_runtime_proxy_restart():
        """重启 Nscan Docker egress 代理。"""
        return restart_strix_egress()

    # ==================== 扫描程序 API ====================

    @app.get("/v1/models/available")
    async def get_available_models_for_scanner(scan_mode: str = None):
        """供扫描程序使用的 API - 获取可用模型状态

        返回:
            - 可用模型列表及当前状态
            - 并发信息
            - 成功率
            - 推荐模型
        """
        server.model_manager.get_all_models_status()
        health_report = server.model_manager.health_checker.get_health_report()

        available_models = []
        recommended_model = None
        best_score = -1
        recommended_parallel = 0
        routing_context = {"scan_mode": (scan_mode or "").lower()}

        for name, model_config in server.model_manager.models.items():
            if not model_config.enabled or name in server.model_manager.disabled_models:
                continue

            routing_status = server.model_manager.get_model_routing_status(
                name, routing_context
            )
            health = health_report.get(name, {})
            is_healthy = health.get("healthy", True)

            # 计算成功率
            total = health.get("total_successes", 0) + health.get("total_failures", 0)
            success_rate = (
                health.get("total_successes", 0) / total if total > 0 else 1.0
            )

            # 获取并发信息
            rate_limit_state = (
                server.model_manager.usage_controller.rate_limit_states.get(name)
            )
            active_requests = (
                rate_limit_state.active_requests if rate_limit_state else 0
            )

            model_limits = server.model_manager.usage_controller.per_model_limits.get(
                name, {}
            )
            max_concurrent = int(model_limits.get("max_concurrent", 0) or 0)
            max_rpm = model_limits.get("max_requests_per_minute", 999)
            slot_capacity = max_concurrent if max_concurrent > 0 else 1

            # 计算可用并发槽
            available_slots = max(0, slot_capacity - active_requests)

            model_info = {
                "name": name,
                "model": model_config.model,
                "provider": model_config.provider,
                "priority": model_config.priority,
                "healthy": is_healthy,
                "success_rate": round(success_rate, 3),
                "active_requests": active_requests,
                "max_concurrent": max_concurrent,
                "available_slots": available_slots,
                "slot_capacity": slot_capacity,
                "max_rpm": max_rpm,
                "health_reason": health.get("reason", ""),
                "routing_tier": model_config.routing_tier,
                "allowed_scan_modes": model_config.allowed_scan_modes,
                "quota_policy": model_config.quota_policy,
                "eligible_for_auto": routing_status["eligible"],
                "routing_reason": routing_status["reason"],
            }

            available_models.append(model_info)

            # 计算推荐模型（健康 + 成功率高 + 有可用槽）
            if (
                routing_status["eligible"]
                and is_healthy
                and available_slots > 0
                and success_rate >= 0.7
                and server.model_manager.usage_controller.check_budget(name)
            ):
                recommended_parallel += min(slot_capacity, available_slots)
                score = (1 if success_rate >= 0.9 else 0) + (
                    available_slots / slot_capacity
                )
                if score > best_score:
                    best_score = score
                    recommended_model = name

        schedule_limit = server.model_manager.time_controller.get_parallel_limit()
        if schedule_limit < 100:
            recommended_parallel = min(recommended_parallel, schedule_limit)
        recommended_parallel = (
            max(1, recommended_parallel) if recommended_parallel > 0 else 0
        )

        # 自动可用模型优先，再按可用槽位和优先级排序
        available_models.sort(
            key=lambda x: (
                not x["eligible_for_auto"],
                -x["available_slots"],
                x["priority"],
            )
        )

        return {
            "timestamp": time.time(),
            "scan_mode": scan_mode,
            "total_models": len(available_models),
            "healthy_models": sum(1 for m in available_models if m["healthy"]),
            "recommended_model": recommended_model,
            "recommended_parallel": recommended_parallel,
            "schedule_parallel_limit": schedule_limit,
            "models": available_models,
        }

    @app.get("/v1/models/recommended")
    async def get_recommended_model():
        """供扫描程序使用的 API - 获取推荐模型

        返回最适合使用的模型名称
        """
        result = await get_available_models_for_scanner()
        recommended = result.get("recommended_model")

        if not recommended:
            raise HTTPException(status_code=503, detail="No available models")

        # 返回 OpenAI 兼容格式
        return {
            "object": "model",
            "id": recommended,
            "created": int(time.time()),
            "owned_by": "proxy",
        }

    @app.get("/proxy/logs")
    async def proxy_logs(
        limit: int = 100,
        scan_id: str = None,
        proxy_slot: str = None,
        date: str = None,
        start_date: str = None,
        end_date: str = None,
        days: int = 1,
        joined: bool = False,
    ):
        """返回请求日志"""
        payload = request_logger.read_logs(
            limit=limit,
            scan_id=scan_id,
            proxy_slot=proxy_slot,
            log_date=date,
            start_date=start_date,
            end_date=end_date,
            days=days,
        )
        if joined:
            payload["joined"] = request_logger.join_logs(payload["logs"])
        return payload

    @app.get("/proxy/check")
    async def check_all_models():
        """检查所有模型连接状态"""
        results = await server.check_all_models()
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results,
            "summary": {
                "total": len(results),
                "healthy": sum(1 for r in results.values() if r["status"] == "healthy"),
                "unhealthy": sum(
                    1
                    for r in results.values()
                    if r["status"] in ["unhealthy", "error", "timeout"]
                ),
                "disabled": sum(
                    1 for r in results.values() if r["status"] == "disabled"
                ),
            },
        }

    @app.post("/proxy/models/{model_name:path}/test")
    async def test_model(model_name: str):
        """测试单个模型连接"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        result = await server.test_model(model_name)
        return result

    @app.post("/proxy/usage/reset")
    async def reset_usage():
        """重置每日统计"""
        server.model_manager.usage_controller.reset_daily_stats()
        return {"message": "Daily stats reset"}

    @app.get("/proxy/config")
    async def get_config():
        """返回当前配置"""
        return server.config

    @app.put("/proxy/config")
    async def update_config(request: Request):
        """更新配置"""
        try:
            config_patch = await request.json()
            if not isinstance(config_patch, dict):
                raise ValueError("Config update must be a JSON object")
            merged_config = validate_proxy_config(
                deep_merge_config(server.config, config_patch)
            )
            server._save_config(merged_config, create_backup=True)
            server._apply_runtime_config(merged_config)
            return {
                "message": "Config updated",
                "top_level_keys": sorted(config_patch.keys()),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/proxy/models/{model_name}/schedule-re-enable")
    async def schedule_model_re_enable(model_name: str, request: Request):
        """设置模型定时重新启用

        请求体:
            re_enable_at: ISO 格式的时间字符串，或 seconds: 秒数（从现在开始）
            reason: 原因（可选）
        """
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        try:
            body = await request.json()

            # 解析重新启用时间
            re_enable_at = body.get("re_enable_at")
            seconds = body.get("seconds")

            if re_enable_at:
                # ISO 格式时间
                from datetime import datetime

                if isinstance(re_enable_at, str):
                    dt = datetime.fromisoformat(re_enable_at.replace("Z", "+00:00"))
                    re_enable_timestamp = dt.timestamp()
                else:
                    re_enable_timestamp = float(re_enable_at)
            elif seconds:
                # 从现在开始的秒数
                re_enable_timestamp = time.time() + int(seconds)
            else:
                raise HTTPException(
                    status_code=400, detail="Either re_enable_at or seconds is required"
                )

            reason = body.get("reason", "Scheduled re-enable")

            # 禁用模型
            server.model_manager.disable_model(model_name)

            # 设置重新启用时间
            server.model_manager.health_checker.set_re_enable_time(
                model_name, re_enable_timestamp, reason
            )

            from datetime import datetime

            re_enable_time = datetime.fromtimestamp(re_enable_timestamp, timezone.utc).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            return {
                "message": f"Model {model_name} scheduled for re-enable at {re_enable_time}",
                "model": model_name,
                "re_enable_at": re_enable_time,
                "reason": reason,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/proxy/ip-whitelist")
    async def get_ip_whitelist():
        """获取 IP 白名单"""
        return {"allowed_ips": server.ip_whitelist.get_allowed_ips()}

    @app.post("/proxy/ip-whitelist/add")
    async def add_ip_whitelist(request: Request):
        """添加 IP 到白名单"""
        try:
            body = await request.json()
            ip = body.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP is required")

            server.ip_whitelist.add_ip(ip)

            # 更新配置文件
            if "server" not in server.config:
                server.config["server"] = {}
            if "allowed_ips" not in server.config["server"]:
                server.config["server"]["allowed_ips"] = []
            if ip not in server.config["server"]["allowed_ips"]:
                server.config["server"]["allowed_ips"].append(ip)
            server._save_config()

            return {"message": f"IP {ip} added to whitelist"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/proxy/ip-whitelist/remove")
    async def remove_ip_whitelist(request: Request):
        """从白名单中移除 IP"""
        try:
            body = await request.json()
            ip = body.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP is required")

            server.ip_whitelist.remove_ip(ip)

            # 更新配置文件
            if "server" in server.config and "allowed_ips" in server.config["server"]:
                if ip in server.config["server"]["allowed_ips"]:
                    server.config["server"]["allowed_ips"].remove(ip)
                server._save_config()

            return {"message": f"IP {ip} removed from whitelist"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.post("/proxy/models/{model_name:path}/enable")
    async def enable_model(model_name: str):
        """启用模型"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        server.model_manager.enable_model(model_name)
        # 持久化到配置文件
        server.model_manager.save_config(str(server.config_path))
        return {"message": f"Model {model_name} enabled"}

    @app.post("/proxy/models/{model_name:path}/disable")
    async def disable_model(model_name: str):
        """禁用模型"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        server.model_manager.disable_model(model_name, cooldown=False)
        # 持久化到配置文件
        server.model_manager.save_config(str(server.config_path))
        return {"message": f"Model {model_name} disabled"}

    @app.post("/proxy/models/routing-mode")
    async def set_model_routing_mode(request: Request):
        """Set how enabled models participate in automatic routing."""
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}") from exc
        mode = str(body.get("mode", ""))
        try:
            server.model_manager.set_routing_mode(mode)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        server.model_manager.save_config(str(server.config_path))
        return {
            "message": f"Model routing mode set to {mode}",
            "mode": mode,
        }

    @app.get("/proxy/vision-assist")
    async def get_vision_assist():
        """Return the image-assist role without exposing credentials."""
        selected = str((server.config.get("vision_assist") or {}).get("model") or "")
        candidates = server.model_manager.get_vision_assist_candidates()
        return {
            "model": selected,
            "available": any(
                item["name"] == selected and item["healthy"] for item in candidates
            ),
            "candidates": candidates,
        }

    @app.put("/proxy/vision-assist")
    async def set_vision_assist(request: Request):
        """Persist an opt-in global default for image-only assistance."""
        try:
            body = await request.json()
            requested = str(body.get("model") or "").strip()
            if requested:
                model = server.model_manager.models.get(requested)
                if not model:
                    raise ValueError("Vision assist model was not found")
                if not model.vision_supported or not model.vision_assist_enabled:
                    raise ValueError(
                        "Model must have Vision capability and Vision assist enabled"
                    )
            updated = copy.deepcopy(server.config)
            updated.setdefault("vision_assist", {})["model"] = requested
            server._save_config(updated, create_backup=True)
            server._apply_runtime_config(updated)
            return {"model": requested, "message": "Vision assist default updated"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/proxy/models/add")
    async def add_model(request: Request):
        """添加新模型"""
        try:
            body = await request.json()
            name = body.get("name")
            if not name:
                raise HTTPException(status_code=400, detail="Model name is required")

            # 检查模型是否已存在
            if name in server.model_manager.models:
                raise HTTPException(
                    status_code=409, detail=f"Model {name} already exists"
                )

            # 构建模型配置
            model_config = {
                "model": body.get("model", ""),
                "api_key": body.get("api_key", ""),
                "api_base": body.get("api_base", ""),
                "provider": body.get("provider", ""),
                "priority": body.get("priority", 100),
                "weight": body.get("weight", 100),
                "enabled": body.get("enabled", True),
                "peak_only": body.get("peak_only", False),
                "free": body.get("free", False),
                "label": body.get("label", ""),
                "routing_tier": body.get("routing_tier", "standard"),
                "allowed_scan_modes": body.get("allowed_scan_modes", []),
                "quota_policy": body.get("quota_policy", {}),
                "api_format": body.get("api_format", "openai"),
                "is_exact_url": bool(body.get("is_exact_url", False)),
                "custom_headers": body.get("custom_headers", {}),
                "strip_provider_prefix": bool(body.get("strip_provider_prefix", False)),
                "max_context_tokens": int(body.get("max_context_tokens", 0) or 0),
                "request_overrides": body.get("request_overrides", {}),
                "reasoning_supported": bool(
                    body.get(
                        "reasoning_supported",
                        supports_native_reasoning(
                            str(body.get("provider") or ""), body.get("model", "")
                        ),
                    )
                ),
                "reasoning_api": str(body.get("reasoning_api") or "auto").lower(),
                "thinking_enabled": bool(
                    body.get(
                        "thinking_enabled",
                        supports_native_reasoning(
                            str(body.get("provider") or ""), body.get("model", "")
                        ),
                    )
                ),
                "reasoning_effort": str(body.get("reasoning_effort") or "high").lower(),
                "vision_supported": bool(
                    body.get(
                        "vision_supported",
                        supports_vision_assist(
                            str(body.get("provider") or ""), body.get("model", "")
                        ),
                    )
                ),
                "vision_assist_enabled": bool(
                    body.get("vision_assist_enabled", False)
                ),
            }

            limits = server.config.setdefault("usage", {}).setdefault(
                "per_model_limits", {}
            ).setdefault(name, {})
            for field in (
                "max_concurrent", "max_requests_per_minute", "input_cost_per_1m",
                "output_cost_per_1m", "cached_read_cost_per_1m",
            ):
                if field in body and body[field] not in (None, ""):
                    limits[field] = body[field]

            # 添加到配置
            if "models" not in server.config:
                server.config["models"] = {}
            if "available" not in server.config["models"]:
                server.config["models"]["available"] = {}
            server.config["models"]["available"][name] = model_config

            # 更新模型管理器
            server.model_manager.update_config(server.config)

            # 保存配置
            server.model_manager.save_config(str(server.config_path))
            if str(model_config.get("provider") or "").lower() == "openrouter":
                await server.refresh_openrouter_reasoning_capabilities(force=True)

            return {"message": f"Model {name} added", "model": name}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.put("/proxy/models/{model_name}")
    async def update_model(model_name: str, request: Request):
        """更新模型配置"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        try:
            body = await request.json()
            stored = server.config["models"]["available"][model_name]
            for field in (
                "api_key",
                "api_base",
                "model",
                "provider",
                "label",
                "routing_tier",
                "allowed_scan_modes",
                "quota_policy",
                "api_format",
                "is_exact_url",
                "custom_headers",
                "strip_provider_prefix",
                "max_context_tokens",
                "request_overrides",
                "thinking_enabled",
                "reasoning_effort",
                "reasoning_supported",
                "reasoning_api",
                "vision_supported",
                "vision_assist_enabled",
                "enabled",
                "free",
                "peak_only",
            ):
                if field in body:
                    stored[field] = body[field]
            if "priority" in body:
                stored["priority"] = int(body["priority"])

            limits = server.config.setdefault("usage", {}).setdefault(
                "per_model_limits", {}
            ).setdefault(model_name, {})
            for field in ("max_concurrent", "max_requests_per_minute"):
                if field in body:
                    value = int(body[field] or 0)
                    if value < 0:
                        raise ValueError(f"{field} must be zero or greater")
                    if value:
                        limits[field] = value
                    else:
                        limits.pop(field, None)
            for field in (
                "input_cost_per_1m", "output_cost_per_1m", "cached_read_cost_per_1m",
            ):
                if field in body:
                    value = float(body[field] or 0)
                    if value < 0:
                        raise ValueError(f"{field} must be zero or greater")
                    if value:
                        limits[field] = value
                    else:
                        limits.pop(field, None)

            server.model_manager.update_config(server.config)
            server.model_manager.save_config(str(server.config_path))
            if str(stored.get("provider") or "").lower() == "openrouter":
                await server.refresh_openrouter_reasoning_capabilities(force=True)

            return {"message": f"Model {model_name} updated"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.delete("/proxy/models/{model_name}")
    async def delete_model(model_name: str):
        """删除模型"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        # Explicit deletion removes only this model and its model-scoped
        # metadata. Provider definitions remain because they may be shared.
        server.model_manager.delete_model(model_name)

        return {"message": f"Model {model_name} deleted"}

    @app.post("/proxy/models/active-requests/reset")
    async def reset_model_active_requests(model_name: Optional[str] = None):
        """重置模型运行时并发槽位计数，不清空用量统计。"""
        result = server.model_manager.usage_controller.reset_active_requests(model_name)
        if model_name:
            server.model_manager.mark_model_inactive(model_name)
        else:
            for name in result.get("models", {}):
                server.model_manager.mark_model_inactive(name)
        return {
            "message": "Model active request counters reset",
            **result,
        }

    @app.post("/proxy/models/reasoning-capabilities/refresh")
    async def refresh_model_reasoning_capabilities():
        """Refresh OpenRouter reasoning metadata for configured models."""
        return await server.refresh_openrouter_reasoning_capabilities(force=True)

    @app.post("/proxy/models/{model_name}/reset")
    async def reset_model(model_name: str):
        """重置模型健康状态"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        server.model_manager.reset_model_health(model_name)
        return {"message": f"Model {model_name} health reset"}

    @app.get("/proxy/models/{model_name}")
    async def get_model(model_name: str):
        """获取模型详情"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        config = server.model_manager.models[model_name]
        health = server.model_manager.health_checker.health_state.get(model_name)

        return {
            "name": model_name,
            "model": config.model,
            "api_base": config.api_base,
            "api_key_configured": bool(config.api_key),
            "api_key_hint": config.api_key[-5:] if config.api_key else "",
            "provider": config.provider,
            "priority": config.priority,
            "enabled": config.enabled
            and model_name not in server.model_manager.disabled_models,
            "peak_only": config.peak_only,
            "free": config.free,
            "label": config.label,
            "routing_tier": config.routing_tier,
            "allowed_scan_modes": config.allowed_scan_modes,
            "quota_policy": config.quota_policy,
            "reasoning_supported": config.reasoning_supported,
            "reasoning_api": config.reasoning_api,
            "thinking_enabled": config.thinking_enabled,
            "reasoning_effort": config.reasoning_effort,
            "vision_supported": config.vision_supported,
            "vision_assist_enabled": config.vision_assist_enabled,
            "reasoning_capability": server.get_openrouter_reasoning_status()
            .get("models", {})
            .get(model_name, {}),
            "limits": server.config.get("usage", {})
            .get("per_model_limits", {})
            .get(model_name, {}),
            "health": {
                "healthy": health.healthy if health else True,
                "reason": health.reason if health else "",
                "consecutive_failures": health.consecutive_failures if health else 0,
            }
            if health
            else None,
        }

    # ==================== Dashboard Pro 扩展路由 ====================

    @app.get("/proxy/dashboard/summary")
    async def proxy_dashboard_summary(include_telemetry: bool = True):
        try:
            resources = get_system_resources()
        except Exception:
            resources = {"available": False}
        try:
            batch_status = read_smart_batch_status(limit=20, include_finished=True, include_tasks=False)
            scans = {
                "summary": batch_status.get("summary", {}) if isinstance(batch_status, dict) else {},
                "batches": batch_status.get("batches", []) if isinstance(batch_status, dict) else [],
            }
        except Exception:
            scans = {"summary": {}}
        return {
            "health": "normal",
            "scans": scans,
            "resources": resources,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/proxy/dashboard/badges")
    async def proxy_dashboard_badges():
        try:
            resources = get_system_resources()
        except Exception:
            resources = None
        try:
            asset_summary = get_asset_database().summary()
        except Exception:
            asset_summary = {}
        health = server.model_manager.health_checker.health_state
        models = server.model_manager.models
        healthy_count = sum(
            1 for name in models if health.get(name) and health[name].healthy
        )
        total_models = len(models)
        try:
            batch_status = read_smart_batch_status(limit=20, include_finished=False)
            active_scans = int(
                (batch_status.get("summary") or {}).get("running_tasks") or 0
            )
        except Exception:
            active_scans = 0
        assets_total = int(asset_summary.get("total") or 0)
        findings_total = int(asset_summary.get("findings") or 0)
        return {
            "active_scans": active_scans,
            "vulnerabilities_total": findings_total,
            "vulnerabilities_new": 0,
            "models_healthy": healthy_count,
            "models_total": total_models,
            "scans": active_scans,
            "assets": assets_total,
            "assets_total": assets_total,
            "findings": findings_total,
            "models": healthy_count,
            "resources": resources,
        }

    @app.get("/proxy/egress/usage")
    async def proxy_egress_usage():
        try:
            return await asyncio.to_thread(get_egress_usage)
        except Exception:
            return {"usage": []}

    @app.post("/proxy/nscan-runtime/egress-check")
    async def proxy_nscan_runtime_egress_check():
        return {"status": "ok"}

    @app.get("/proxy/nscan-runtime/nodes")
    @app.post("/proxy/nscan-runtime/nodes")
    async def proxy_nscan_runtime_nodes(request: Request = None):
        if request is None or request.method == "GET":
            runtime = await asyncio.to_thread(get_strix_runtime_status, False)
            return {
                "nodes": runtime.get("egress", {}).get("outbounds", {}).get("socks_nodes", []),
            }
        try:
            body = await request.json()
            node_tag = str(body.pop("tag", "")).strip()
            if not node_tag:
                raise ValueError("tag is required")
            return await asyncio.to_thread(upsert_strix_egress_node, node_tag, body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.put("/proxy/nscan-runtime/nodes/{node_tag}")
    async def proxy_nscan_runtime_node_update(node_tag: str, request: Request):
        try:
            body = await request.json()
            return await asyncio.to_thread(upsert_strix_egress_node, node_tag, body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.delete("/proxy/nscan-runtime/nodes/{node_tag}")
    async def proxy_nscan_runtime_node_delete(node_tag: str):
        try:
            return await asyncio.to_thread(delete_strix_egress_node, node_tag)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/proxy/nscan-runtime/nodes/test")
    async def proxy_nscan_runtime_nodes_test(request: Request):
        try:
            body = await request.json()
            return await asyncio.to_thread(test_strix_egress_node, body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/proxy/security/pin")
    @app.put("/proxy/security/pin")
    async def proxy_security_pin():
        pin, source = get_dashboard_pin()
        return {"configured": bool(pin), "source": source or None}

    @app.get("/proxy/smart-batch/jobs")
    async def proxy_smart_batch_jobs_list(limit: int = Query(50, ge=1, le=200)):
        return await asyncio.to_thread(_job_manager.list_jobs, limit)

    @app.get("/proxy/smart-batch/jobs/health-summary")
    async def proxy_smart_batch_jobs_health_summary():
        chelmon_runtime = await asyncio.to_thread(get_chelmon_runtime_status)
        modes = {}
        enabled_total = 0
        eligible_total = 0
        for mode in ("quick", "standard", "deep", "redteam", "getshell"):
            model_status = server.model_manager.get_all_models_status({"scan_mode": mode})
            mode_enabled = 0
            mode_eligible = 0
            names = []
            for name, item in model_status.items():
                if item.get("enabled"):
                    mode_enabled += 1
                auto = item.get("auto_routing") if isinstance(item.get("auto_routing"), dict) else {}
                if auto.get("eligible"):
                    mode_eligible += 1
                    names.append(name)
            modes[mode] = {"enabled": mode_enabled, "eligible": mode_eligible, "models": names}
            enabled_total = max(enabled_total, mode_enabled)
            eligible_total = max(eligible_total, mode_eligible)
        return {
            "status": "running",
            "enabledModels": enabled_total,
            "eligibleModels": eligible_total,
            "engines": {
                "strix": {"available": True, "default": False},
                "chelmon-claude": {
                    "available": bool(chelmon_runtime.get("ready")),
                    "default": False,
                    "aliases": ["ansecai"],
                    "runtime": chelmon_runtime,
                },
                "dual": {
                    "available": bool(chelmon_runtime.get("ready")),
                    "default": bool(chelmon_runtime.get("ready")),
                    "plan": [
                        {"engine": "strix", "mode": "redteam"},
                        {"engine": "chelmon-claude", "mode": "default"},
                    ],
                    "runtime": chelmon_runtime,
                },
            },
            "sharedModes": ["redteam", "deep", "standard", "quick", "getshell"],
            "modes": modes,
        }

    @app.get("/proxy/smart-batch/jobs/runtime-summary")
    async def proxy_smart_batch_jobs_runtime_summary():
        return await asyncio.to_thread(_job_manager.runtime_summary)

    @app.get("/proxy/smart-batch/jobs/{job_id}/report")
    async def proxy_smart_batch_job_report(job_id: str):
        try:
            return await asyncio.to_thread(_job_manager.job_report, job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Smart Batch job not found") from None

    @app.get("/proxy/smart-batch/jobs/{job_id}/logs")
    async def proxy_smart_batch_job_logs(job_id: str, tail: int = Query(200, ge=1, le=1000)):
        try:
            return await asyncio.to_thread(_job_manager.job_logs, job_id, tail)
        except KeyError:
            raise HTTPException(status_code=404, detail="Smart Batch job not found") from None

    @app.post("/proxy/smart-batch/jobs/{job_id}/terminate")
    async def proxy_smart_batch_job_terminate(job_id: str):
        try:
            return await asyncio.to_thread(_job_manager.terminate_job, job_id, "dashboard")
        except KeyError:
            raise HTTPException(status_code=404, detail="Smart Batch job not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/proxy/smart-batch/jobs/{job_id}/resume")
    async def proxy_smart_batch_job_resume(job_id: str):
        try:
            return await asyncio.to_thread(_job_manager.resume_job, job_id, "dashboard")
        except KeyError:
            raise HTTPException(status_code=404, detail="Smart Batch job not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/proxy/smart-batch/jobs")
    async def proxy_smart_batch_jobs_submit(request: Request):
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        try:
            preview = await asyncio.to_thread(_job_manager.preview, payload)
            options = preview.get("options") if isinstance(preview.get("options"), dict) else {}
            accepted = list(preview.get("accepted_targets") or [])
            if not accepted:
                # Keep submit semantics aligned with SmartBatchJobManager.submit:
                # a scope/private/DNS rejection must never look like a successful
                # empty submission merely because automatic routing has no group.
                raise ValueError("No accepted targets supplied")
            workflow_mode = str(options.get("workflow_mode") or "")
            source = str(options.get("source") or "")
            jobs = []
            if workflow_mode == "retest":
                baseline = await _findings_service.retest_baseline(accepted)
                job_payload = {**payload, "targets": accepted, "_retest_baseline": baseline}
                jobs.append(await asyncio.to_thread(_job_manager.submit, job_payload))
            elif source != "target_ingest":
                scanned_keys = await asyncio.to_thread(get_asset_database().scanned_targets)
                rescans = [target for target in accepted if normalize_target(target)["canonical_key"] in scanned_keys]
                new_targets = [target for target in accepted if target not in rescans]
                if new_targets:
                    jobs.append(await asyncio.to_thread(_job_manager.submit, {**payload, "targets": new_targets}))
                if rescans:
                    baseline = await _findings_service.retest_baseline(rescans)
                    label = str(payload.get("label") or "retest")
                    jobs.append(await asyncio.to_thread(_job_manager.submit, {
                        **payload, "targets": rescans, "engine": "dual", "mode": "retest",
                        "label": f"{label}-retest", "_retest_baseline": baseline,
                    }))
            else:
                jobs.append(await asyncio.to_thread(_job_manager.submit, payload))
            if len(jobs) == 1:
                return jobs[0]
            return {
                "status": "started", "jobs": jobs, "job": jobs[0] if jobs else None,
                "new_target_count": sum(int(job.get("target_count") or 0) for job in jobs if job.get("workflow_mode") != "retest"),
                "retest_target_count": sum(int(job.get("target_count") or 0) for job in jobs if job.get("workflow_mode") == "retest"),
            }
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("smart batch submit error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/proxy/smart-batch/jobs/preview")
    async def proxy_smart_batch_jobs_preview(request: Request):
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        try:
            preview = await asyncio.to_thread(_job_manager.preview, payload)
            options = preview.get("options") if isinstance(preview.get("options"), dict) else {}
            accepted = list(preview.get("accepted_targets") or [])
            if str(options.get("workflow_mode") or "") == "retest":
                baseline = await _findings_service.retest_baseline(accepted)
                summaries = {
                    target: {
                        "asset_id": item.get("asset_id"),
                        "historical_findings_count": item.get("finding_count", 0),
                        "omitted_count": item.get("omitted_count", 0),
                        "context_bytes": item.get("context_bytes", 0),
                        "classifications": {
                            label: sum(1 for record in item.get("records", []) if record.get("classification") == label)
                            for label in ("verified_active", "unverified_lead", "excluded_false_positive", "archived")
                        },
                    }
                    for target, item in (baseline.get("targets") or {}).items()
                }
                preview["retest_baseline"] = {"max_bytes_per_target": baseline.get("max_bytes_per_target"), "targets": summaries}
            elif str(options.get("source") or "") != "target_ingest":
                scanned_keys = await asyncio.to_thread(get_asset_database().scanned_targets)
                preview["execution_groups"] = {
                    "new_targets": [target for target in accepted if normalize_target(target)["canonical_key"] not in scanned_keys],
                    "retest_targets": [target for target in accepted if normalize_target(target)["canonical_key"] in scanned_keys],
                }
            return preview
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("smart batch preview error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/proxy/assets/import")
    async def proxy_assets_import(request: Request):
        """Register a page of external assets without creating a scan job.

        This route is intentionally separate from ``target-ingest``. It is
        suitable for large upstream inventories: callers submit at most 10,000
        public targets with a stable source reference and cursor, then may
        safely replay a cursor after a network interruption.
        """
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="JSON body must be an object")
        source = str(payload.get("source") or "pii_alive_assets").strip()
        source_ref = str(payload.get("source_ref") or "").strip()
        cursor = asset_import_cursor(payload)
        targets = payload.get("targets")
        values = asset_import_target_values(targets)
        if not source:
            raise HTTPException(status_code=422, detail="source is required")
        if not source_ref:
            raise HTTPException(status_code=422, detail="source_ref is required")
        if not cursor:
            raise HTTPException(status_code=422, detail="sync_cursor is required")
        if not values:
            raise HTTPException(status_code=422, detail="targets is required")
        if len(values) > ASSET_IMPORT_MAX_TARGETS:
            raise HTTPException(
                status_code=422,
                detail=f"asset import batch limit is {ASSET_IMPORT_MAX_TARGETS} targets",
            )

        try:
            # Inventory registration deliberately accepts public targets from
            # every country. The UAE scope policy remains enforced later when
            # an operator creates an automatic scan job. Private/local targets
            # are still rejected here and never enter the shared inventory.
            analysis = await asyncio.to_thread(
                analyze_targets,
                values,
                max_targets=ASSET_IMPORT_MAX_TARGETS,
                allow_private=False,
                check_dns=False,
                source="dashboard",
                allow_non_uae=False,
                enforce_scope=False,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        accepted_targets = list(analysis.get("accepted_targets") or [])
        rejected_targets = list(analysis.get("rejected_targets") or [])
        if bool(payload.get("dry_run", False)):
            return {
                "status": "dry_run",
                "register_only": True,
                "source": source,
                "source_ref": source_ref,
                "sync_cursor": cursor,
                "input_count": len(values),
                "accepted_count": len(accepted_targets),
                "rejected_count": len(rejected_targets),
                "accepted_targets": accepted_targets[:50],
                "rejected_targets": rejected_targets[:50],
                "scan_job": None,
            }

        db = get_asset_database()
        record = await asyncio.to_thread(
            db.record_asset_import,
            source_type=source,
            source_ref=source_ref,
            sync_cursor=cursor,
            accepted_targets=accepted_targets,
            rejected_targets=rejected_targets,
            input_count=len(values),
            metadata={
                "source_type": "asset_import",
                "label": str(payload.get("label") or ""),
                "inventory_only": True,
                "scope_policy": "deferred_until_scan_submission",
            },
        )
        await asyncio.to_thread(
            db.record_scope_decisions,
            list(analysis.get("scope_decisions") or []),
            source_type=source,
            source_ref=source_ref,
        )
        return {
            "status": "registered",
            "register_only": True,
            **record,
            "scan_job": None,
            "accepted_targets": accepted_targets[:50],
            "rejected_targets": rejected_targets[:50],
        }

    @app.get("/proxy/assets/imports")
    async def proxy_assets_imports(source: str = "", source_ref: str = ""):
        db = get_asset_database()
        return await asyncio.to_thread(
            db.asset_import_progress,
            source_type=source,
            source_ref=source_ref,
        )

    @app.post("/proxy/target-ingest")
    async def proxy_target_ingest(request: Request):
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="JSON body must be an object")
        platform = str(payload.get("platform") or "").strip()
        if not platform:
            raise HTTPException(status_code=422, detail="platform is required")
        targets = payload.get("targets")
        if targets is None or (isinstance(targets, str) and not targets.strip()) or (isinstance(targets, list) and not targets):
            raise HTTPException(status_code=422, detail="targets is required")

        dry_run = bool(payload.get("dry_run", False))
        register_only = bool(payload.get("register_only", False))
        source_ref = str(payload.get("source_ref") or "").strip()
        if register_only:
            cursor = asset_import_cursor(payload)
            values = asset_import_target_values(targets)
            if not source_ref:
                raise HTTPException(status_code=422, detail="source_ref is required when register_only=true")
            if not cursor:
                raise HTTPException(status_code=422, detail="sync_cursor is required when register_only=true")
            if len(values) > ASSET_IMPORT_MAX_TARGETS:
                raise HTTPException(
                    status_code=422,
                    detail=f"asset import batch limit is {ASSET_IMPORT_MAX_TARGETS} targets",
                )
            try:
                analysis = await asyncio.to_thread(
                    analyze_targets,
                    values,
                    max_targets=ASSET_IMPORT_MAX_TARGETS,
                    allow_private=False,
                    check_dns=False,
                    source="target_ingest",
                    allow_non_uae=False,
                    country=str(payload.get("country") or ""),
                    region=str(payload.get("region") or ""),
                    enforce_scope=False,
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            accepted_targets = list(analysis.get("accepted_targets") or [])
            rejected_targets = list(analysis.get("rejected_targets") or [])
            if dry_run:
                return {
                    "status": "dry_run",
                    "register_only": True,
                    "platform": platform,
                    "source_ref": source_ref,
                    "sync_cursor": cursor,
                    "accepted_count": len(accepted_targets),
                    "rejected_count": len(rejected_targets),
                    "accepted_targets": accepted_targets[:50],
                    "rejected_targets": rejected_targets[:50],
                    "scan_job": None,
                }
            db = get_asset_database()
            record = await asyncio.to_thread(
                db.record_asset_import,
                source_type=platform,
                source_ref=source_ref,
                sync_cursor=cursor,
                accepted_targets=accepted_targets,
                rejected_targets=rejected_targets,
                input_count=len(values),
                metadata={
                    "source_type": "target_ingest_register_only",
                    "platform": platform,
                    "country": str(payload.get("country") or ""),
                    "region": str(payload.get("region") or ""),
                    "inventory_only": True,
                },
            )
            await asyncio.to_thread(
                db.record_scope_decisions,
                list(analysis.get("scope_decisions") or []),
                source_type=platform,
                source_ref=source_ref,
            )
            return {
                "status": "registered" if accepted_targets else "quarantined",
                "register_only": True,
                **record,
                "scan_job": None,
                "accepted_targets": accepted_targets[:50],
                "rejected_targets": rejected_targets[:50],
            }
        engine = str(payload.get("engine") or "dual").strip().lower()
        if engine == "ansecai":
            engine = "chelmon-claude"
        mode = str(payload.get("mode") or "redteam").strip().lower()
        ingest_payload = {
            **payload,
            "source": "target_ingest",
            "platform": platform,
            "source_ref": source_ref,
            "allow_non_uae": False,
        }
        try:
            preview = await asyncio.to_thread(_job_manager.preview, ingest_payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("target ingest preview error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        preview_options = preview.get("options") if isinstance(preview.get("options"), dict) else {}
        engine = str(preview_options.get("engine") or engine)
        mode = str(preview_options.get("mode") or mode)

        accepted_targets = list(preview.get("accepted_targets") or [])
        rejected_targets = list(preview.get("rejected_targets") or [])
        if dry_run:
            return {
                "status": "dry_run",
                "platform": platform,
                "source_ref": source_ref,
                "engine": engine,
                "mode": mode,
                "engine_plan": preview.get("engine_plan", []),
                "accepted_count": len(accepted_targets),
                "rejected_count": len(rejected_targets),
                "preview": preview,
            }

        job = None
        if accepted_targets:
            submit_payload = {
                **ingest_payload,
                "targets": accepted_targets,
                "dry_run": False,
                "label": str(payload.get("label") or f"{platform}-ingest"),
            }
            try:
                job = await asyncio.to_thread(_job_manager.submit, submit_payload)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except Exception as exc:
                logger.exception("target ingest submit error")
                raise HTTPException(status_code=500, detail=str(exc)) from exc

        db = get_asset_database()
        ingest_record = await asyncio.to_thread(
            db.record_target_ingest,
            platform=platform,
            source_ref=source_ref,
            accepted_targets=accepted_targets,
            rejected_targets=rejected_targets,
            job_id=str((job or {}).get("job_id") or ""),
            dry_run=False,
            metadata={
                "source_type": "target_ingest",
                "engine": engine,
                "mode": mode,
                "engine_plan": preview.get("engine_plan", []),
                "country": str(payload.get("country") or ""),
                "region": str(payload.get("region") or ""),
                "submitted_count": len(targets) if isinstance(targets, list) else len(str(targets).splitlines()),
            },
        )
        await asyncio.to_thread(
            db.record_scope_decisions,
            list(preview.get("scope_decisions") or []),
            source_type=platform,
            source_ref=source_ref,
        )
        return {
            "status": "accepted" if accepted_targets else "quarantined",
            **ingest_record,
            "engine": engine,
            "mode": mode,
            "engine_plan": preview.get("engine_plan", []),
            "job": job,
            "accepted_targets": accepted_targets[:50],
            "rejected_targets": rejected_targets,
        }

    @app.get("/proxy/target-ingest/quarantine")
    async def proxy_target_ingest_quarantine(
        platform: str = "",
        reason: str = "",
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ):
        db = get_asset_database()
        return await asyncio.to_thread(
            db.target_quarantine_page,
            platform=platform,
            reason=reason,
            page=page,
            page_size=page_size,
        )

    @app.get("/proxy/asset-groups")
    async def proxy_asset_groups():
        db = get_asset_database()
        return await asyncio.to_thread(db.asset_groups)

    @app.post("/proxy/smart-batch/status/{batch_id}/parallel")
    async def proxy_smart_batch_parallel(batch_id: str, request: Request):
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None

        try:
            requested = int(body.get("parallel"))
        except (AttributeError, TypeError, ValueError):
            raise HTTPException(status_code=422, detail="parallel must be an integer") from None

        if requested < 1 or requested > 32:
            raise HTTPException(status_code=422, detail="parallel must be between 1 and 32")

        try:
            updated = await asyncio.to_thread(
                set_smart_batch_parallel,
                batch_id,
                requested,
                "dashboard",
            )
        except ValueError as exc:
            message = str(exc)
            if "not found" in message:
                raise HTTPException(status_code=404, detail=message) from exc
            if "finished" in message:
                raise HTTPException(status_code=409, detail=message) from exc
            raise HTTPException(status_code=422, detail=message) from exc

        control = updated.get("parallel_control") or {}
        return {
            "status": "accepted",
            "batch_id": batch_id,
            "requested_parallel": requested,
            "current_parallel": int(updated.get("parallel") or 0),
            "effective_parallel": int(updated.get("effective_parallel") or 0),
            "requested_at": control.get("requested_at"),
        }

    @app.post("/proxy/smart-batch/status/{batch_id}/pause")
    async def proxy_smart_batch_pause(batch_id: str, request: Request):
        try:
            body = await request.json()
            paused = body.get("paused")
            if not isinstance(paused, bool):
                raise HTTPException(status_code=422, detail="paused must be a boolean")
            updated = await asyncio.to_thread(set_smart_batch_paused, batch_id, paused, "dashboard")
            return {"status": "paused" if paused else "running", "batch_id": batch_id, "paused": paused, "requested_at": (updated.get("pause_control") or {}).get("requested_at")}
        except ValueError as exc:
            raise HTTPException(status_code=409 if "finished" in str(exc) else 404, detail=str(exc)) from exc

    @app.post("/proxy/smart-batch/status/{batch_id}/terminate")
    async def proxy_smart_batch_terminate(batch_id: str):
        try:
            return await asyncio.to_thread(terminate_smart_batch, batch_id, "dashboard")
        except ValueError as exc:
            raise HTTPException(status_code=409 if "finished" in str(exc) else 404, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.delete("/proxy/smart-batch/status/{batch_id}")
    async def proxy_smart_batch_delete(batch_id: str):
        try:
            return await asyncio.to_thread(delete_smart_batch, batch_id, "dashboard")
        except ValueError as exc:
            message = str(exc)
            raise HTTPException(status_code=409 if "terminate" in message else 404, detail=message) from exc

    @app.get("/proxy/scanned-targets")
    async def proxy_scanned_targets(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        query: str = "",
        source: str = "",
        platform: str = "",
        group: str = "",
    ):
        db = get_asset_database()
        return await asyncio.to_thread(
            db.scanned_targets_page,
            query=query,
            source=source,
            platform=platform,
            group=group,
            page=page,
            page_size=page_size,
        )

    @app.post("/proxy/docker/orphan-containers/cleanup")
    async def proxy_docker_orphan_cleanup():
        return {"cleaned": 0}

    @app.get("/proxy/assets/summary")
    async def proxy_assets_summary():
        db = get_asset_database()
        return await asyncio.to_thread(db.summary)

    @app.get("/proxy/assets/scope-summary")
    async def proxy_assets_scope_summary():
        db = get_asset_database()
        summary = await asyncio.to_thread(db.summary)
        catalog = await asyncio.to_thread(load_scope_catalog)
        return {
            "generated_at": summary.get("generated_at"),
            "scope": summary.get("scope", {}),
            "categories": summary.get("scope_categories", {}),
            "catalog": {
                "version": catalog.get("version", "uninitialized"),
                "generated_at": catalog.get("generated_at", ""),
                "source": catalog.get("source", ""),
                "item_count": len(catalog.get("items") or []),
            },
        }

    @app.post("/proxy/assets/scope-catalog")
    async def proxy_assets_scope_catalog(request: Request):
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="Scope catalog must be a JSON object")
        try:
            catalog = await asyncio.to_thread(save_scope_catalog, payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "status": "updated",
            "version": catalog.get("version"),
            "source": catalog.get("source"),
            "item_count": len(catalog.get("items") or []),
        }

    @app.get("/proxy/assets/export")
    async def proxy_assets_export(
        format: str = "csv",
        query: str = "",
        scan_status: str = "",
        probe_status: str = "",
        source: str = "",
        platform: str = "",
        group: str = "",
        scope_status: str = "",
        scope_category: str = "",
    ):
        from fastapi.responses import Response as FastAPIResponse
        db = get_asset_database()
        filters = {k: v for k, v in {
            "query": query,
            "scan_status": scan_status,
            "probe_status": probe_status,
            "source": source,
            "platform": platform,
            "group": group,
            "scope_status": scope_status,
            "scope_category": scope_category,
        }.items() if v}
        data, media_type = await asyncio.to_thread(db.export_assets, format, **filters)
        ext = {"json": "json", "csv": "csv"}.get(format, "txt")
        return FastAPIResponse(
            content=data,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename=assets.{ext}"},
        )

    @app.get("/proxy/assets")
    async def proxy_assets(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        query: str = "",
        scan_status: str = "",
        probe_status: str = "",
        source: str = "",
        platform: str = "",
        group: str = "",
        scope_status: str = "",
        scope_category: str = "",
        sort: str = "last_seen",
    ):
        if sort not in {"last_seen", "last_scanned", "findings", "target"}:
            raise HTTPException(status_code=422, detail="sort must be one of last_seen, last_scanned, findings, target")
        db = get_asset_database()
        return await asyncio.to_thread(
            db.list_assets,
            query=query,
            scan_status=scan_status,
            probe_status=probe_status,
            source=source,
            platform=platform,
            group=group,
            scope_status=scope_status,
            scope_category=scope_category,
            sort=sort,
            page=page,
            page_size=page_size,
        )

    @app.get("/proxy/integrations/assets/changes")
    async def proxy_integration_asset_changes(
        cursor: str = "",
        limit: int = Query(500, ge=1, le=1000),
    ):
        return await asyncio.to_thread(list_asset_changes, cursor, limit)

    @app.get("/proxy/assets/{asset_id}")
    async def proxy_asset_detail(asset_id: int):
        db = get_asset_database()
        detail = await asyncio.to_thread(db.asset_detail, asset_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return detail

    @app.post("/proxy/assets/spool/replay")
    async def proxy_assets_spool_replay():
        db = get_asset_database()
        return await asyncio.to_thread(db.replay_spool)

    # Use the proper FindingsService router for all /proxy/vulnerabilities/*
    # and /proxy/vulnerability-reports/* routes.
    # NOTE: _findings_service is the singleton created before lifespan above.
    findings_router = create_findings_router(_findings_service)
    app.include_router(findings_router)

    return app
