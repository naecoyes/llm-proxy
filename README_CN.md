<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">LLM Proxy Hub</h1>

<p align="center">
  一个轻量级、高性能的 LLM API 代理服务器
</p>

<p align="center">
  <a href="README.md">English</a> | 中文
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

---

## 功能特性

- **多模型管理** - 支持配置多个 LLM 提供商，统一为 OpenAI 兼容接口。
- **Anthropic API 支持** - 原生支持 Anthropic Claude 模型，自动完成 OpenAI ↔ Anthropic 格式转换（含流式）。
- **固定槽位路由 (Slot Routing)** - 支持通过请求指定 `auto1`、`auto2` 等固定槽位，实现智能的会话保持和连接复用。**严格遵守并发控制**：当高优先级模型达到 `max_concurrent` 并发上限时，剩余槽位将自动分配给次优优先级的备用模型；且在模型被禁用（如触及额度熔断）时，槽位支持自动无缝漂移。
- **智能负载均衡** - 自动分发请求到可用模型，支持基于近期成功率的动态过滤（自动跳过成功率低于 70% 的模型）。
- **离峰调度** - 非高峰时段动态提升指定模型优先级（可配置时区），支持 `mimo_priority` 等灵活时间策略。
- **额度感知与自动恢复** - 识别由于额度限制或速率限制导致的错误，自动解析重置时间（如 Minimax 5小时限制）并在到期后重新启用模型。
- **速率限制感知** - 自动跳过触发速率限制的模型，回退到同 Provider 或其他 Provider 的可用模型。
- **免费模型回退 (Fallback to Free)** - 在所有付费模型不可用时，可自动安全回退到配置的免费模型以保障服务不中断。
- **故障转移** - 动态检测失败并自动切换备用模型，保障服务高可用性。
- **自动禁用与探测** - 连续健康检查失败自动禁用模型，并支持按概率对不健康的模型发起探测请求以自动恢复。
- **并发控制** - 细粒度支持对每个模型配置最大并发数（如 `max_concurrent`）。
- **IP 白名单** - 精细化访问控制，支持 `X-Forwarded-For` 和 `X-Real-IP`。
- **请求日志与统计** - 完整记录所有 API 请求响应耗时及 Token 消耗。
- **热重载配置** - 修改 `proxy_config.yaml` 无需重启服务，配置立即生效。
- **Web 管理面板** - 直观的可视化管理界面，支持在线查看模型健康状态和监控。

## 界面预览

| 仪表盘 | 模型管理 |
|--------|----------|
| ![Dashboard](images/dashboard.png) | ![Models](images/models.png) |

| 配置管理 | 请求日志 |
|----------|----------|
| ![Config](images/cofing.png) | ![Logs](images/logs.png) |

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置模型

创建或编辑 `proxy_config.yaml`：

```yaml
server:
  host: "0.0.0.0"
  port: 8888
  allowed_ips:
    - 127.0.0.1
    - ::1

models:
  available:
    # OpenAI 兼容模型
    my-openai:
      api_base: https://api.openai.com/v1
      api_key: your-api-key
      model: gpt-4
      provider: openai
      priority: 100
      enabled: true

    # Anthropic Claude 模型
    my-claude:
      api_base: https://api.anthropic.com
      api_key: your-anthropic-key
      model: claude-sonnet-4-20250514
      provider: anthropic
      api_format: anthropic
      priority: 90
      enabled: true

# 时间调度策略（可选）
schedule:
  timezone: "Asia/Shanghai"
  peak_hours:
    - [18, 23]
  off_peak_hours:
    enabled: true
    hours: [[20, 4]]
    timezone: "Asia/Dubai"
    models: ["my-openai"]
    priority_boost: true
    boost_priority: 1
    default_priority: 100

usage:
  per_model_limits:
    my-openai:
      max_concurrent: 3
```

### 3. 启动服务

```bash
# 使用脚本
chmod +x start.sh stop.sh
./start.sh    # 启动后台服务
./stop.sh     # 停止后台服务

# 或直接启动
python start_proxy.py --config proxy_config.yaml --port 8888
```

服务启动后访问 `http://127.0.0.1:8888`，管理面板在同一地址。

### 4. 命令行参数

```
python start_proxy.py [选项]

选项:
  --config, -c    配置文件路径 (默认: proxy_config.yaml)
  --host          监听地址 (默认: 使用配置文件中的值)
  --port, -p      监听端口 (默认: 使用配置文件中的值)
  --log-level     日志级别 (debug/info/warning/error)
  --reload        启用自动重载 (开发模式)
```

## API 调用

代理完全兼容 **OpenAI Chat Completions API** 格式。

### Chat Completions

**固定槽位请求（会话保持）：**
在 `model` 参数中传入 `auto1`, `auto2` 等，系统会固定将该槽位映射到一个健康的后端模型。

```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto1",
    "messages": [
      {"role": "user", "content": "你好！"}
    ]
  }'
```

**Python（OpenAI SDK）：**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8888/v1",
    api_key="any-string"  # 代理会处理真实的 API Key
)

response = client.chat.completions.create(
    model="auto",  # 自动选择最优模型，或传入具体模型名/槽位名 (如 auto1)
    messages=[{"role": "user", "content": "你好！"}]
)
print(response.choices[0].message.content)
```

## 接口参考

| 接口 | 方法 | 说明 |
|------|------|------|
| `/v1/chat/completions` | POST | Chat Completions 兼容接口 |
| `/v1/models` | GET | 获取可用模型列表 |
| `/proxy/status` | GET | 代理状态概览 |
| `/proxy/health` | GET | 模型健康检查结果 |
| `/proxy/usage` | GET | 用量统计 |
| `/proxy/logs` | GET | 请求日志 |
| `/proxy/config` | GET/PUT | 读取或更新配置 |

## 项目结构

```
llm_proxy/
├── server.py           # FastAPI 服务器
├── model_manager.py    # 模型管理、负载均衡、并发控制
├── config_watcher.py   # 配置文件热重载
├── health_checker.py   # 模型健康检查与探测
├── request_logger.py   # 请求日志记录
├── usage_controller.py # 用量与速率限制控制
├── time_controller.py  # 时间调度与离峰策略
├── start_proxy.py      # 启动脚本
├── proxy_config.yaml   # 主配置文件
└── static/             # 前端静态资源
```

## 许可证

MIT
