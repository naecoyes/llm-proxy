"""LLM Proxy Server - FastAPI HTTP 服务器"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Set

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from config_watcher import ConfigWatcher
from model_manager import ModelManager, NoAvailableModelError
from request_logger import (
    SCAN_CONTEXT_FIELD_HEADERS,
    request_logger,
    sanitize_scan_context_value,
)
from smart_batch_monitor import (
    get_system_resources,
    read_smart_batch_detail,
    read_smart_batch_status,
)
from strix_runtime_monitor import (
    get_strix_runtime_status,
    restart_strix_egress,
    set_strix_egress_enabled,
    set_strix_egress_node_enabled,
    set_strix_egress_startup_enabled,
)
from egress_usage_monitor import get_egress_usage
from findings import FindingsService, create_findings_router

logger = logging.getLogger(__name__)

DASHBOARD_SESSION_COOKIE = "nscan_admin_session"


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
    """LLM Proxy Server"""

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

    def _load_config(self) -> dict:
        """加载配置文件"""
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _save_config(self):
        """保存配置文件"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False)

    def _on_config_change(self, new_config: dict):
        """配置变化回调"""
        self.config = new_config
        self.model_manager.update_config(new_config)

        # 更新 IP 白名单
        server_config = new_config.get("server", {})
        allowed_ips = server_config.get("allowed_ips", [])
        self.ip_whitelist._update_config(allowed_ips)

        logger.info("配置已热更新")

    async def start(self):
        """启动服务"""
        # 启动配置监控
        self.config_watcher.start()

        # 创建 HTTP 客户端
        self.http_client = httpx.AsyncClient(timeout=300.0)

        # 启动定时健康检查
        self.health_check_task = asyncio.create_task(self._health_check_loop())

        logger.info("LLM Proxy Server 已启动")

    async def stop(self):
        """停止服务"""
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

        logger.info("LLM Proxy Server 已停止")

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
        """检查所有 unhealthy 模型，401 直接删除"""
        health_report = self.model_manager.health_checker.get_health_report()
        models_to_delete = []
        models_to_reset = []

        for name, health in health_report.items():
            if health.get("healthy", True):
                continue
            if name not in self.model_manager.models:
                continue

            model_config = self.model_manager.models[name]
            reason = health.get("reason", "")

            # 401 直接标记删除
            if (
                "401" in reason
                or "Invalid API Key" in reason.lower()
                or "authentication" in reason.lower()
            ):
                models_to_delete.append(name)
                logger.warning(f"🗑️ 模型 {name} 认证失败，将删除: {reason}")
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
                    "max_tokens": 1,
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
                    models_to_delete.append(name)
                    logger.warning(f"🗑️ 模型 {name} 探测返回 401，将删除")
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

        # 删除 401 模型
        for name in models_to_delete:
            self._delete_model(name)

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
                    "max_tokens": 5,
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
                    "max_tokens": 10,
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
                    "max_tokens": 10,
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
            
            if fallback:
                new_model_name, new_model_config = fallback
                logger.warning(
                    f"[{request_id}] 模型 {model_name} 请求失败 ({reason_str})，"
                    f"切换到备用模型: {new_model_name} ({attempt + 1}/{max_retries})"
                )
                from request_logger import request_logger
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
                from request_logger import request_logger
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

        body = request_body.copy()

        # Strip reasoning_content from all messages so that previous
        # reasoning tokens never trigger provider rejections (e.g.
        # DeepSeek: "reasoning_content must be passed back to API").
        for msg in body.get("messages", []):
            if isinstance(msg, dict):
                msg.pop("reasoning_content", None)

        model_id = model_config.model
        if getattr(model_config, "strip_provider_prefix", True) and "/" in model_id:
            model_id = model_id.split("/", 1)[1]
        body["model"] = model_id

        # DeepSeek: disable native thinking to prevent new reasoning tokens.
        if getattr(model_config, "provider", "") == "deepseek":
            body.pop("thinking", None)
            body.pop("reasoning_effort", None)
            body["thinking"] = {"type": "disabled"}

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
            "created": int(datetime.now().timestamp()),
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
                    "id": f"chatcmpl-{int(datetime.now().timestamp())}",
                    "object": "chat.completion.chunk",
                    "created": int(datetime.now().timestamp()),
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
                    "id": f"chatcmpl-{int(datetime.now().timestamp())}",
                    "object": "chat.completion.chunk",
                    "created": int(datetime.now().timestamp()),
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
                "id": f"chatcmpl-{int(datetime.now().timestamp())}",
                "object": "chat.completion.chunk",
                "created": int(datetime.now().timestamp()),
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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await server.start()
        yield
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
        if not context.get("scan_mode"): context["scan_mode"] = "deep"
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

        # Enforce IP whitelist (TCP peer address, not spoofable forwarded headers)
        if not is_local_client and not server.ip_whitelist.is_allowed(peer_ip):
            logger.warning(f"拒绝访问: {peer_ip} - {request.url.path}")
            return JSONResponse(
                status_code=403, content={"detail": f"IP {peer_ip} not allowed"}
            )

        if request_needs_pin(request) and not request_has_valid_pin(request):
            accept = request.headers.get("accept", "")
            path = request.url.path
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
            raise HTTPException(status_code=400, detail=f"Invalid request body: {e}")

        stream = body.get("stream", False)
        requested_model = body.get("model", None)
        messages = body.get("messages", [])
        max_retries = server.model_manager.health_checker.max_retries
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                model_name, model_config = server.model_manager.select_model(
                    requested_model, scan_context
                )
            except NoAvailableModelError as e:
                raise HTTPException(status_code=503, detail=str(e))

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
                    messages=messages,
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
                        model_switched = False
                        valid_chunk_count = 0
                        finish_reason_stop = False
                        has_content_in_delta = False
                        stream_error: Optional[str] = None
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

                                # Strip reasoning_content from delta before
                                # forwarding to agent SDK so it never enters
                                # conversation history and triggers rejection.
                                try:
                                    chunk_str_before = (
                                        chunk.decode()
                                        if isinstance(chunk, bytes)
                                        else chunk
                                    )
                                    if (
                                        chunk_str_before.startswith("data: ")
                                        and chunk_str_before.strip() != "data: [DONE]"
                                    ):
                                        data = json.loads(chunk_str_before[6:])
                                        choices = data.get("choices")
                                        if isinstance(choices, list):
                                            for c in choices:
                                                if isinstance(c, dict):
                                                    delta = c.get("delta") or {}
                                                    if isinstance(delta, dict):
                                                        delta.pop("reasoning_content", None)
                                                        if str(delta.get("content") or "").strip():
                                                            has_content_in_delta = True
                                        chunk = f"data: {json.dumps(data)}\n\n".encode()
                                except Exception:
                                    pass

                                yield chunk
                                try:
                                    chunk_str = (
                                        chunk.decode()
                                        if isinstance(chunk, bytes)
                                        else chunk
                                    )
                                    if chunk_str.strip():
                                        valid_chunk_count += 1
                                    if (
                                        chunk_str.startswith("data: ")
                                        and chunk_str.strip() != "data: [DONE]"
                                    ):
                                        data = json.loads(chunk_str[6:])
                                        if "usage" in data and data["usage"]:
                                            usage = data["usage"]
                                            total_tokens = usage.get("total_tokens", 0)
                                            input_tokens = usage.get("prompt_tokens", 0)
                                            output_tokens = usage.get(
                                                "completion_tokens", 0
                                            )
                                            final_usage = usage
                                        if data.get("choices") and isinstance(data["choices"], list):
                                            if data["choices"][0].get("finish_reason") in ("stop", "length"):
                                                finish_reason_stop = True
                                        if data.get("error"):
                                            stream_error = json.dumps(data["error"], ensure_ascii=False)
                                except Exception:
                                    pass
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
                        is_success = not stream_error and has_real_output

                        if is_success:
                            server.model_manager.handle_success(model_name)
                            if final_usage:
                                server.model_manager.record_usage(model_name, final_usage)
                            elif total_tokens == 0:
                                server.model_manager.record_usage(
                                    model_name,
                                    {"total_tokens": 1, "prompt_tokens": 0, "completion_tokens": 0},
                                )
                        else:
                            error_msg = stream_error or "Empty response or rate limited"
                            server.model_manager.handle_error(model_name, RuntimeError(error_msg))

                        zero_usage_partial = is_success and total_tokens == 0
                        if zero_usage_partial:
                            status = "partial"
                        else:
                            status = "success" if is_success else "failed"
                        final_error = None if is_success else error_msg

                        # 记录请求完成
                        request_logger.log_response(
                            request_id=request_id,
                            model_name=model_name,
                            duration=duration,
                            status=status,
                            usage={
                                "total_tokens": total_tokens,
                                "prompt_tokens": input_tokens,
                                "completion_tokens": output_tokens,
                            },
                            error=final_error,
                            scan_context=scan_context,
                        )

                        logger.info(
                            f"[{request_id}] 流式请求{'完成' if is_success else '失败'}: {model_name} | "
                            f"耗时: {duration:.2f}s | tokens: {total_tokens}"
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

                    # Strip reasoning_content from non-streaming response
                    # before returning to agent SDK.
                    if isinstance(response_data, dict):
                        choices = response_data.get("choices")
                        if isinstance(choices, list):
                            for c in choices:
                                if not isinstance(c, dict):
                                    continue
                                msg = c.get("message") or {}
                                if isinstance(msg, dict):
                                    msg.pop("reasoning_content", None)

                    duration = time.time() - start_time
                    usage = response_data.get("usage", {})
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
                        scan_context=scan_context,
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
    async def proxy_status():
        """返回代理状态"""
        return {
            "status": "running",
            "models": server.model_manager.get_all_models_status(),
            "usage": server.model_manager.usage_controller.get_usage_report(),
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
    async def proxy_usage_trend(granularity: str = "4h", model: str = None):
        """返回趋势数据

        Args:
            granularity: 时间粒度，"day" 或 "4h"
            model: 模型名称，可选
        """
        return server.model_manager.usage_controller.get_trend_data(granularity, model)

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
    async def proxy_smart_batch_status(limit: int = 20, include_finished: bool = True):
        """返回 Smart Batch 运行状态快照列表"""
        return read_smart_batch_status(limit=limit, include_finished=include_finished)

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
        if not _shutil.which("docker"):
            return {"available": False, "strix_containers": [], "error": "docker not found"}
        try:
            fmt = (
                '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}",'
                '"status":"{{.Status}}","state":"{{.State}}","created":"{{.CreatedAt}}"}' 
            )
            result = _sp.run(
                ["docker", "ps", "-a", "--format", fmt],
                capture_output=True, text=True, timeout=8, check=False,
            )
            all_containers = []
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    all_containers.append(_json.loads(line))
                except Exception:
                    pass

            strix = [c for c in all_containers if "strix-scan" in c.get("name", "") or "strix-sandbox" in c.get("image", "")]
            other = [c for c in all_containers if "strix-scan" not in c.get("name", "")]

            enriched = []
            for c in strix:
                entry = dict(c)
                try:
                    insp = _sp.run(
                        ["docker", "inspect", c["id"],
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
                except Exception:
                    pass
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
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}")
        return set_strix_egress_enabled(read_enabled_flag(body))

    @app.post("/proxy/nscan-runtime/proxy-startup-enabled")
    @app.post("/proxy/strix-runtime/proxy-startup-enabled")
    async def proxy_nscan_runtime_proxy_startup_enabled(request: Request):
        """启用或关闭 Nscan Docker egress 代理开机自启状态。"""
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}")
        return set_strix_egress_startup_enabled(read_enabled_flag(body))

    @app.post("/proxy/nscan-runtime/nodes/{node_tag}/enabled")
    async def proxy_nscan_runtime_node_enabled(node_tag: str, request: Request):
        """Enable or disable one SOCKS5 node in the automatic egress pool."""
        try:
            body = await request.json()
            return set_strix_egress_node_enabled(node_tag, read_enabled_flag(body))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

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
            "timestamp": datetime.now().isoformat(),
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
            new_config = await request.json()
            server.config = new_config
            server.model_manager.update_config(new_config)
            server._save_config()
            return {"message": "Config updated"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

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

            re_enable_time = datetime.fromtimestamp(re_enable_timestamp).strftime(
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
            raise HTTPException(status_code=400, detail=str(e))

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
            raise HTTPException(status_code=400, detail=str(e))

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
            raise HTTPException(status_code=400, detail=str(e))

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
            raise HTTPException(status_code=400, detail=f"Invalid request body: {exc}")
        mode = str(body.get("mode", ""))
        try:
            server.model_manager.set_routing_mode(mode)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        server.model_manager.save_config(str(server.config_path))
        return {
            "message": f"Model routing mode set to {mode}",
            "mode": mode,
        }

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
            }

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

            return {"message": f"Model {name} added", "model": name}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

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

            server.model_manager.update_config(server.config)
            server.model_manager.save_config(str(server.config_path))

            return {"message": f"Model {model_name} updated"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.delete("/proxy/models/{model_name}")
    async def delete_model(model_name: str):
        """删除模型"""
        if model_name not in server.model_manager.models:
            raise HTTPException(
                status_code=404, detail=f"Model not found: {model_name}"
            )

        # 从配置中删除
        if "models" in server.config and "available" in server.config["models"]:
            if model_name in server.config["models"]["available"]:
                del server.config["models"]["available"][model_name]

        # 从providers配置中删除
        if "providers" in server.config:
            for provider, provider_config in server.config["providers"].items():
                if "fallback_models" in provider_config:
                    if model_name in provider_config["fallback_models"]:
                        provider_config["fallback_models"].remove(model_name)

        # 更新模型管理器
        server.model_manager.update_config(server.config)

        # 保存配置
        server.model_manager.save_config(str(server.config_path))

        return {"message": f"Model {model_name} deleted"}

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
            "api_key": config.api_key,
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
            batch_status = read_smart_batch_status(limit=20, include_finished=True)
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
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

    @app.get("/proxy/dashboard/badges")
    async def proxy_dashboard_badges():
        try:
            resources = get_system_resources()
        except Exception:
            resources = None
        healthy_count = len(server.model_manager.health_checker.get_healthy_models())
        total_models = len(server.model_manager.models)
        return {
            "active_scans": 0,
            "vulnerabilities_total": 0,
            "vulnerabilities_new": 0,
            "models_healthy": healthy_count,
            "models_total": total_models,
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
        return {"nodes": []}

    @app.put("/proxy/nscan-runtime/nodes/{node_tag}")
    async def proxy_nscan_runtime_node_update(node_tag: str):
        return {"status": "ok"}

    @app.delete("/proxy/nscan-runtime/nodes/{node_tag}")
    async def proxy_nscan_runtime_node_delete(node_tag: str):
        return {"status": "ok"}

    @app.post("/proxy/nscan-runtime/nodes/test")
    async def proxy_nscan_runtime_nodes_test(request: Request):
        return {"status": "ok"}

    @app.get("/proxy/security/pin")
    @app.put("/proxy/security/pin")
    async def proxy_security_pin():
        pin, source = get_dashboard_pin()
        return {"configured": bool(pin), "source": source or None}

    @app.get("/proxy/smart-batch/jobs")
    @app.post("/proxy/smart-batch/jobs")
    async def proxy_smart_batch_jobs():
        return {"jobs": []}

    @app.post("/proxy/smart-batch/jobs/preview")
    async def proxy_smart_batch_jobs_preview(request: Request):
        return {"tasks": []}

    @app.post("/proxy/smart-batch/status/{batch_id}/parallel")
    async def proxy_smart_batch_parallel(batch_id: str):
        return {"status": "ok"}

    @app.get("/proxy/scanned-targets")
    async def proxy_scanned_targets(page: int = 1, page_size: int = 50):
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    @app.post("/proxy/docker/orphan-containers/cleanup")
    async def proxy_docker_orphan_cleanup():
        return {"cleaned": 0}

    @app.get("/proxy/assets")
    async def proxy_assets(page: int = 1, page_size: int = 50):
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    @app.get("/proxy/assets/summary")
    async def proxy_assets_summary():
        return {"total": 0, "scanned": 0, "unscanned": 0, "with_findings": 0}

    @app.get("/proxy/assets/export")
    async def proxy_assets_export(format: str = "csv"):
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("")

    @app.get("/proxy/assets/{asset_id}")
    async def proxy_asset_detail(asset_id: str):
        raise HTTPException(status_code=404, detail="Asset not found")

    @app.post("/proxy/assets/spool/replay")
    async def proxy_assets_spool_replay(request: Request):
        return {"status": "ok"}

    # Use the proper FindingsService router for all /proxy/vulnerabilities/*
    # and /proxy/vulnerability-reports/* routes.
    findings_router = create_findings_router(FindingsService())
    app.include_router(findings_router)

    return app
