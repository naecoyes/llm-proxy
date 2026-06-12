"""LLM Proxy Server - FastAPI HTTP 服务器"""

import asyncio
import json
import logging
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
from request_logger import request_logger

logger = logging.getLogger(__name__)


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
                    data = response.json()
                    content = ""
                    if "choices" in data and len(data["choices"]) > 0:
                        content = (
                            data["choices"][0].get("message", {}).get("content", "")
                        )

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

    async def _get_mimo_free_token(self) -> str:
        """动态获取 Mimo Free API 的 JWT Token"""
        if not hasattr(self, "_mimo_free_token") or not hasattr(
            self, "_mimo_free_token_expiry"
        ):
            self._mimo_free_token = None
            self._mimo_free_token_expiry = 0

        import time

        if self._mimo_free_token and time.time() < self._mimo_free_token_expiry:
            return self._mimo_free_token

        url = "https://api.xiaomimimo.com/api/free-ai/bootstrap"
        try:
            response = await self.http_client.post(
                url, json={"client": "llm-proxy-auto"}
            )
            if response.status_code == 200:
                data = response.json()
                self._mimo_free_token = data.get("jwt")
                # Token valid for ~1 hour, refresh after 50 minutes (3000 seconds)
                self._mimo_free_token_expiry = time.time() + 3000
                logger.info("成功获取 Mimo Free JWT Token")
                return self._mimo_free_token
            else:
                logger.error(f"获取 Mimo Free Token 失败: HTTP {response.status_code}")
                return ""
        except Exception as e:
            logger.error(f"获取 Mimo Free Token 异常: {e}")
            return ""

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

        if getattr(model_config, "provider", "") == "mimo-free":
            api_key = await self._get_mimo_free_token()
            headers["X-Mimo-Source"] = "mimocode-cli-free"

        headers["Authorization"] = f"Bearer {api_key}"

        # Add custom headers
        if hasattr(model_config, "custom_headers") and model_config.custom_headers:
            headers.update(model_config.custom_headers)

        body = request_body.copy()
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
        body["model"] = model_id

        if stream:

            async def stream_generator() -> AsyncGenerator[bytes, None]:
                async with self.http_client.stream(
                    "POST", url, json=body, headers=headers
                ) as response:
                    if response.status_code != 200:
                        error_body = await response.aread()
                        raise HTTPException(
                            status_code=response.status_code, detail=error_body.decode()
                        )
                    async for chunk in response.aiter_bytes():
                        yield chunk

            return StreamingResponse(stream_generator(), media_type="text/event-stream")
        else:
            response = await self.http_client.post(url, json=body, headers=headers)
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
        title="LLM Proxy Hub",
        description="多 LLM API 管理与自动调度代理服务",
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

    @app.middleware("http")
    async def ip_whitelist_middleware(request: Request, call_next):
        """IP 白名单中间件"""
        client_ip = get_client_ip(request)

        # 允许本地访问
        if client_ip in ["127.0.0.1", "::1", "localhost"]:
            response = await call_next(request)
            return response

        # API 端点检查白名单
        if request.url.path.startswith("/proxy/") or request.url.path.startswith(
            "/v1/"
        ):
            if not server.ip_whitelist.is_allowed(client_ip):
                logger.warning(f"拒绝访问: {client_ip} - {request.url.path}")
                return JSONResponse(
                    status_code=403, content={"detail": f"IP {client_ip} not allowed"}
                )

        response = await call_next(request)
        return response

    # ==================== Web 面板路由 ====================

    @app.get("/", response_class=HTMLResponse)
    async def index():
        """Web 面板首页"""
        html_file = static_dir / "index.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>LLM Proxy Hub</h1><p>Web 面板未找到</p>")

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page():
        """设置页面"""
        html_file = static_dir / "settings.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>Settings</h1><p>设置页面未找到</p>")

    # ==================== LLM API 代理路由 ====================

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        """代理 LLM 请求"""
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip(request)

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
                    requested_model
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
                )

                if stream:
                    response = await server.forward_request(
                        model_name, model_config, body, stream=True
                    )

                    server.model_manager.handle_success(model_name)

                    async def stream_with_logging():
                        total_tokens = 0
                        input_tokens = 0
                        output_tokens = 0
                        model_switched = False
                        try:
                            async for chunk in response.body_iterator:
                                # 检查模型是否被禁用，如果是则中断流
                                if (
                                    model_name in server.model_manager.disabled_models
                                    and not model_switched
                                ):
                                    logger.warning(
                                        f"[{request_id}] 流式中检测到模型 {model_name} 被禁用，中断切换"
                                    )
                                    model_switched = True
                                    # 发送错误事件，客户端可据此重试
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
                                yield chunk
                                try:
                                    chunk_str = (
                                        chunk.decode()
                                        if isinstance(chunk, bytes)
                                        else chunk
                                    )
                                    if (
                                        chunk_str.startswith("data: ")
                                        and chunk_str.strip() != "data: [DONE]"
                                    ):
                                        data = json.loads(chunk_str[6:])
                                        if "usage" in data:
                                            usage = data["usage"]
                                            total_tokens = usage.get("total_tokens", 0)
                                            input_tokens = usage.get("prompt_tokens", 0)
                                            output_tokens = usage.get(
                                                "completion_tokens", 0
                                            )
                                            server.model_manager.record_usage(
                                                model_name, usage
                                            )
                                except Exception:
                                    pass
                        except Exception as e:
                            logger.warning(f"[{request_id}] 流式响应异常: {e}")
                            # 处理错误（429 重试不禁用，额度/key 错误禁用）
                            server.model_manager.handle_error(model_name, e)
                        finally:
                            # 释放模型并发锁
                            server.model_manager.usage_controller.release_model(
                                model_name
                            )
                            # 释放模型活跃状态
                            server.model_manager.mark_model_inactive(model_name)

                        duration = time.time() - start_time

                        # 判断是否成功（有异常或无 token 统计视为失败）
                        is_success = total_tokens > 0
                        status = "success" if is_success else "failed"
                        error_msg = (
                            None if is_success else "Empty response or rate limited"
                        )

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
                            error=error_msg,
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
                    )

                    logger.info(
                        f"[{request_id}] 请求完成: {model_name} | "
                        f"耗时: {duration:.2f}s | "
                        f"tokens: {usage.get('total_tokens', 0)}"
                    )

                    return JSONResponse(content=response_data)

            except HTTPException as e:
                last_error = e
                # 释放模型并发锁
                server.model_manager.usage_controller.release_model(model_name)
                # 释放模型活跃状态
                server.model_manager.mark_model_inactive(model_name)
                should_switch = server.model_manager.handle_error(model_name, e)

                if should_switch and attempt < max_retries:
                    old_model = model_name
                    # 尝试选择备用模型（跨 provider）
                    fallback = server.model_manager.select_fallback_model(model_name)
                    if fallback:
                        new_model_name, new_model_config = fallback
                        logger.warning(
                            f"[{request_id}] 模型 {model_name} 请求失败 (HTTP {e.status_code})，"
                            f"切换到备用模型: {new_model_name} ({attempt + 1}/{max_retries})"
                        )
                        request_logger.log_model_switch(
                            request_id=request_id,
                            from_model=old_model,
                            to_model=new_model_name,
                            reason=f"HTTP {e.status_code}",
                        )
                        model_name = new_model_name
                        model_config = new_model_config
                        requested_model = new_model_name
                        continue
                    else:
                        # 没有备用模型，使用自动选择
                        logger.warning(
                            f"[{request_id}] 模型 {model_name} 请求失败 (HTTP {e.status_code})，"
                            f"切换模型重试 ({attempt + 1}/{max_retries})"
                        )
                        request_logger.log_model_switch(
                            request_id=request_id,
                            from_model=old_model,
                            to_model="auto",
                            reason=f"HTTP {e.status_code}",
                        )
                        requested_model = None
                        continue
                else:
                    # 记录失败
                    request_logger.log_response(
                        request_id=request_id,
                        model_name=model_name,
                        duration=time.time() - start_time,
                        status="failed",
                        error=str(e.detail),
                    )
                    raise

            except Exception as e:
                last_error = e
                # 释放模型并发锁
                server.model_manager.usage_controller.release_model(model_name)
                # 释放模型活跃状态
                server.model_manager.mark_model_inactive(model_name)
                should_switch = server.model_manager.handle_error(model_name, e)

                if should_switch and attempt < max_retries:
                    old_model = model_name
                    # 尝试选择备用模型（跨 provider）
                    fallback = server.model_manager.select_fallback_model(model_name)
                    if fallback:
                        new_model_name, new_model_config = fallback
                        logger.warning(
                            f"[{request_id}] 模型 {model_name} 请求失败: {e}，"
                            f"切换到备用模型: {new_model_name} ({attempt + 1}/{max_retries})"
                        )
                        request_logger.log_model_switch(
                            request_id=request_id,
                            from_model=old_model,
                            to_model=new_model_name,
                            reason=str(e),
                        )
                        model_name = new_model_name
                        model_config = new_model_config
                        requested_model = new_model_name
                        continue
                    else:
                        logger.warning(
                            f"[{request_id}] 模型 {model_name} 请求失败: {e}，"
                            f"切换模型重试 ({attempt + 1}/{max_retries})"
                        )
                        request_logger.log_model_switch(
                            request_id=request_id,
                            from_model=model_name,
                            to_model="auto",
                            reason=str(e),
                        )
                        continue
                else:
                    # 记录失败
                    request_logger.log_response(
                        request_id=request_id,
                        model_name=model_name,
                        duration=time.time() - start_time,
                        status="failed",
                        error=str(e),
                    )
                    raise HTTPException(status_code=500, detail=str(e))

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

    # ==================== 扫描程序 API ====================

    @app.get("/v1/models/available")
    async def get_available_models_for_scanner():
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

        for name, model_config in server.model_manager.models.items():
            if not model_config.enabled or name in server.model_manager.disabled_models:
                continue

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
            max_concurrent = model_limits.get("max_concurrent", 999)
            max_rpm = model_limits.get("max_requests_per_minute", 999)

            # 计算可用并发槽
            available_slots = max(0, max_concurrent - active_requests)

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
                "max_rpm": max_rpm,
                "health_reason": health.get("reason", ""),
            }

            available_models.append(model_info)

            # 计算推荐模型（健康 + 成功率高 + 有可用槽）
            if is_healthy and available_slots > 0 and success_rate >= 0.7:
                score = (1 if success_rate >= 0.9 else 0) + (
                    available_slots / max_concurrent
                )
                if score > best_score:
                    best_score = score
                    recommended_model = name

        # 按可用槽位排序
        available_models.sort(key=lambda x: (-x["available_slots"], x["priority"]))

        return {
            "timestamp": time.time(),
            "total_models": len(available_models),
            "healthy_models": sum(1 for m in available_models if m["healthy"]),
            "recommended_model": recommended_model,
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
    async def proxy_logs(limit: int = 100):
        """返回请求日志"""
        from datetime import datetime

        today = datetime.now().strftime("%Y-%m-%d")
        # 使用 request_logger 的日志目录（绝对路径）
        log_file = request_logger.log_dir / f"requests_{today}.log"

        if not log_file.exists():
            return {"logs": [], "total": 0}

        logs = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        # 返回最近的 N 条日志
        logs = logs[-limit:]
        return {"logs": logs, "total": len(logs)}

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

        server.model_manager.disable_model(model_name)
        # 持久化到配置文件
        server.model_manager.save_config(str(server.config_path))
        return {"message": f"Model {model_name} disabled"}

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
            model_config = server.model_manager.models[model_name]

            # 更新允许的字段
            if "api_key" in body:
                model_config.api_key = body["api_key"]
            if "api_base" in body:
                model_config.api_base = body["api_base"]
            if "model" in body:
                model_config.model = body["model"]
            if "provider" in body:
                model_config.provider = body["provider"]
            if "priority" in body:
                model_config.priority = int(body["priority"])
            if "enabled" in body:
                enabled = body["enabled"]
                if enabled:
                    server.model_manager.enable_model(model_name)
                else:
                    server.model_manager.disable_model(model_name)

            # 更新配置文件
            if "models" in server.config and "available" in server.config["models"]:
                if model_name in server.config["models"]["available"]:
                    server.config["models"]["available"][model_name].update(
                        {
                            "api_key": model_config.api_key,
                            "api_base": model_config.api_base,
                            "model": model_config.model,
                            "provider": model_config.provider,
                            "priority": model_config.priority,
                        }
                    )

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
            "health": {
                "healthy": health.healthy if health else True,
                "reason": health.reason if health else "",
                "consecutive_failures": health.consecutive_failures if health else 0,
            }
            if health
            else None,
        }

    return app
