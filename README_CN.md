<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">LLM Proxy</h1>

<p align="center">
  一个轻量级、高性能的 LLM API 代理服务器
</p>

<p align="center">
  English | <a href="README.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

---

## 功能特性

- **多模型管理** - 支持配置多个 LLM 提供商，统一 OpenAI 兼容接口
- **Anthropic API 支持** - 原生支持 Anthropic Claude 模型，自动完成 OpenAI ↔ Anthropic 格式转换（含流式）
- **智能负载均衡** - 自动分发请求到可用模型
- **故障转移** - 检测失败自动切换备用模型，保障服务可用性
- **自动禁用** - 健康检查连续失败超阈值后自动禁用模型
- **请求日志** - 完整记录所有 API 请求和响应
- **IP 白名单** - 精细化访问控制
- **热重载配置** - 修改配置无需重启服务
- **Web 管理面板** - 直观的可视化管理界面，支持在线编辑模型

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
pip install fastapi uvicorn httpx pyyaml
```

### 2. 配置模型

创建或编辑 `proxy_config.yaml`：

```yaml
models:
  available:
    # OpenAI 兼容模型
    my-model:
      api_base: https://api.example.com/v1
      api_key: your-api-key
      enabled: true
      model: model-name

    # Anthropic Claude 模型
    my-claude:
      api_base: https://api.anthropic.com
      api_key: your-anthropic-key
      enabled: true
      model: claude-sonnet-4-20250514
      provider: anthropic
      api_format: anthropic
```

### 3. 启动服务

```bash
uvicorn llm_proxy.server:app --host 0.0.0.0 --port 8000
```

服务启动后访问 `http://localhost:8000`，管理面板在 `http://localhost:8000/`。

## API 调用

代理完全兼容 **OpenAI Chat Completions API** 格式。

### Chat Completions

**cURL（非流式）：**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-model",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "你好！"}
    ]
  }'
```

**cURL（流式）：**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-model",
    "stream": true,
    "messages": [
      {"role": "user", "content": "讲个笑话。"}
    ]
  }'
```

**Python（OpenAI SDK）：**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="any-string"  # 代理会处理真实的 API Key
)

response = client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "你好！"}]
)
print(response.choices[0].message.content)
```

**自动选择模型：**

省略 `model` 字段，代理会自动选择可用模型：

```python
response = client.chat.completions.create(
    messages=[{"role": "user", "content": "你好！"}]
)
```

### 管理接口

```bash
# 获取模型列表
curl http://localhost:8000/v1/models

# 代理状态
curl http://localhost:8000/proxy/status

# 健康检查
curl http://localhost:8000/proxy/health

# 用量统计
curl http://localhost:8000/proxy/usage

# 请求日志
curl http://localhost:8000/proxy/logs
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
| `/proxy/models/{name}/enable` | POST | 启用模型 |
| `/proxy/models/{name}/disable` | POST | 禁用模型 |
| `/proxy/models/{name}` | PUT | 更新模型配置 |
| `/proxy/models/{name}` | DELETE | 删除模型 |
| `/proxy/models/{name}/test` | POST | 测试模型连接 |

## 项目结构

```
llm_proxy/
├── server.py           # 主服务器
├── model_manager.py    # 模型管理与负载均衡
├── config_watcher.py   # 配置文件热重载
├── health_checker.py   # 模型健康检查
├── request_logger.py   # 请求日志记录
├── usage_controller.py # 用量控制
├── time_controller.py  # 时间控制
├── proxy_config.yaml   # 配置文件
├── static/             # 前端静态资源
├── images/             # README 截图
└── logs/               # 日志目录
```

## License

MIT
