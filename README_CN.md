<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">LLM Proxy Hub</h1>

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
- **离峰调度** - 非高峰时段动态提升指定模型优先级（可配置时区）
- **速率限制感知** - 自动跳过触发速率限制的模型，回退到可用模型
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
pip install -r requirements.txt
```

### 2. 配置模型

创建或编辑 `proxy_config.yaml`：

```yaml
server:
  host: "127.0.0.1"
  port: 8888

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
  peak_hours: [18, 19, 20, 21, 22, 23]
  peak_strategy: openrouter
  off_peak_hours:
    enabled: true
    hours: [[20, 4]]        # UTC+4 20:00 - 04:00
    timezone: "Asia/Dubai"
    models: ["my-openai"]
    priority_boost: true
    boost_priority: 1       # 离峰时段优先级提升
    default_priority: 100
```

### 3. 启动服务

```bash
# 使用脚本
chmod +x start.sh stop.sh
./start.sh    # 启动
./stop.sh     # 停止

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

**cURL（非流式）：**

```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-openai",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "你好！"}
    ]
  }'
```

**cURL（流式）：**

```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-openai",
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
    base_url="http://localhost:8888/v1",
    api_key="any-string"  # 代理会处理真实的 API Key
)

response = client.chat.completions.create(
    model="auto",  # 自动选择模型
    messages=[{"role": "user", "content": "你好！"}]
)
print(response.choices[0].message.content)
```

### 管理接口

```bash
# 获取模型列表
curl http://localhost:8888/v1/models

# 代理状态
curl http://localhost:8888/proxy/status

# 健康检查
curl http://localhost:8888/proxy/health

# 用量统计
curl http://localhost:8888/proxy/usage

# 请求日志
curl http://localhost:8888/proxy/logs
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
├── server.py           # FastAPI 服务器
├── model_manager.py    # 模型管理与负载均衡
├── config_watcher.py   # 配置文件热重载
├── health_checker.py   # 模型健康检查
├── request_logger.py   # 请求日志记录
├── usage_controller.py # 用量控制
├── time_controller.py  # 时间调度与离峰策略
├── start_proxy.py      # 启动脚本（支持命令行参数）
├── start.sh            # Shell 启动脚本
├── stop.sh             # Shell 停止脚本
├── requirements.txt    # Python 依赖
├── proxy_config.yaml   # 配置文件
├── static/             # 前端静态资源
├── images/             # README 截图
├── logs/               # 日志目录
└── stats/              # 统计数据目录
```

## 许可证

MIT
