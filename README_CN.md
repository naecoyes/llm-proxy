<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="200" />
</p>

<h1 align="center">LLM Proxy</h1>

<p align="center">
  一个轻量级、高性能的 LLM API 代理服务器
</p>

<p align="center">
  <a href="README.md">English</a> | 中文
</p>

---

## 功能特性

- **多模型管理** - 支持配置多个 LLM 提供商和模型，统一入口调用
- **智能负载均衡** - 自动分发请求到可用模型
- **故障转移** - 检测失败自动切换备用模型，保障服务可用性
- **请求日志** - 完整记录所有 API 请求和响应
- **IP 白名单** - 精细化访问控制
- **热重载配置** - 修改配置无需重启服务
- **Web 管理面板** - 直观的可视化管理界面

## 界面预览

### 仪表盘

![Dashboard](images/dashboard.png)

### 模型管理

![Models](images/models.png)

### 配置管理

![Config](images/cofing.png)

### 请求日志

![Logs](images/logs.png)

## 快速开始

### 安装依赖

```bash
pip install fastapi uvicorn httpx pyyaml
```

### 启动服务

```bash
uvicorn llm_proxy.server:app --host 0.0.0.0 --port 8000
```

### 配置模型

编辑 `proxy_config.yaml`：

```yaml
models:
  available:
    my-model:
      api_base: https://api.example.com/v1
      api_key: your-api-key
      enabled: true
      model: model-name
```

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
└── logs/               # 日志目录
```

## API 调用

### Chat Completions

代理完全兼容 OpenAI Chat Completions API 格式。

**基础请求（非流式）：**

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

**流式请求：**

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

### 获取模型列表

```bash
curl http://localhost:8000/v1/models
```

返回：

```json
{
  "object": "list",
  "data": [
    {"id": "my-model", "object": "model", "created": 0, "owned_by": "proxy"}
  ]
}
```

### 代理状态

```bash
curl http://localhost:8000/proxy/status
```

### 健康检查

```bash
curl http://localhost:8000/proxy/health
```

### 用量统计

```bash
curl http://localhost:8000/proxy/usage
```

### 请求日志

```bash
curl http://localhost:8000/proxy/logs
```

## API 接口参考

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
| `/proxy/models/{name}/test` | POST | 测试模型连接 |

## License

MIT
