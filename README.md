<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">LLM Proxy Hub</h1>

<p align="center">
  A lightweight, high-performance LLM API proxy server
</p>

<p align="center">
  <a href="README_CN.md">中文</a> | English
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

---

## Features

- **Multi-Model Management** - Configure multiple LLM providers with a unified OpenAI-compatible endpoint
- **Anthropic API Support** - Native support for Anthropic Claude models with automatic OpenAI ↔ Anthropic format conversion (including streaming)
- **Smart Load Balancing** - Automatically distribute requests across available models
- **Off-Peak Scheduling** - Dynamic priority boost for specified models during off-peak hours (configurable timezone)
- **Rate Limit Awareness** - Skip models that have triggered rate limits, auto fallback to available ones
- **Failover** - Detect failures and switch to backup models to ensure availability
- **Auto-Disable** - Automatically disable models after consecutive health check failures
- **Request Logging** - Complete logging of all API requests and responses
- **IP Whitelist** - Fine-grained access control
- **Hot Reload** - Update configuration without restarting the server
- **Web Dashboard** - Intuitive visual management interface with model editing support

## Screenshots

| Dashboard | Model Management |
|-----------|------------------|
| ![Dashboard](images/dashboard.png) | ![Models](images/models.png) |

| Configuration | Request Logs |
|---------------|--------------|
| ![Config](images/cofing.png) | ![Logs](images/logs.png) |

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Models

Create or edit `proxy_config.yaml`:

```yaml
server:
  host: "127.0.0.1"
  port: 8888

models:
  available:
    # OpenAI-compatible model
    my-openai:
      api_base: https://api.openai.com/v1
      api_key: your-api-key
      model: gpt-4
      provider: openai
      priority: 100
      enabled: true

    # Anthropic Claude model
    my-claude:
      api_base: https://api.anthropic.com
      api_key: your-anthropic-key
      model: claude-sonnet-4-20250514
      provider: anthropic
      api_format: anthropic
      priority: 90
      enabled: true

# Time-based scheduling (optional)
schedule:
  timezone: "Asia/Shanghai"
  peak_hours: [18, 19, 20, 21, 22, 23]
  peak_strategy: openrouter
  off_peak_hours:
    enabled: true
    hours: [[20, 4]]        # UTC+4 8PM - 4AM
    timezone: "Asia/Dubai"
    models: ["my-openai"]
    priority_boost: true
    boost_priority: 1       # Higher priority during off-peak
    default_priority: 100
```

### 3. Start Server

```bash
# Using shell scripts
chmod +x start.sh stop.sh
./start.sh    # Start
./stop.sh     # Stop

# Or directly
python start_proxy.py --config proxy_config.yaml --port 8888
```

Server will be available at `http://127.0.0.1:8888`, with the dashboard at the same address.

### 4. Command Line Options

```
python start_proxy.py [options]

Options:
  --config, -c    Config file path (default: proxy_config.yaml)
  --host          Listen address (default: from config)
  --port, -p      Listen port (default: from config)
  --log-level     Log level (debug/info/warning/error)
  --reload        Enable auto-reload (dev mode)
```

## API Usage

The proxy is fully compatible with the **OpenAI Chat Completions API** format.

### Chat Completions

**cURL (non-streaming):**

```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-openai",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

**Python (OpenAI SDK):**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8888/v1",
    api_key="any-string"  # Proxy handles the real API key
)

response = client.chat.completions.create(
    model="auto",  # Auto model selection
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)
```

### Management API

```bash
# List available models
curl http://localhost:8888/v1/models

# Proxy status
curl http://localhost:8888/proxy/status

# Health check
curl http://localhost:8888/proxy/health

# Usage statistics
curl http://localhost:8888/proxy/usage

# Request logs
curl http://localhost:8888/proxy/logs
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat Completions compatible API |
| `/v1/models` | GET | List available models |
| `/proxy/status` | GET | Proxy status overview |
| `/proxy/health` | GET | Model health check results |
| `/proxy/usage` | GET | Usage statistics |
| `/proxy/logs` | GET | Request logs |
| `/proxy/config` | GET/PUT | Read or update configuration |
| `/proxy/models/{name}/enable` | POST | Enable a model |
| `/proxy/models/{name}/disable` | POST | Disable a model |
| `/proxy/models/{name}` | PUT | Update a model's configuration |
| `/proxy/models/{name}` | DELETE | Delete a model |
| `/proxy/models/{name}/test` | POST | Test a model connection |

## Project Structure

```
llm_proxy/
├── server.py           # FastAPI server
├── model_manager.py    # Model management & load balancing
├── config_watcher.py   # Config file hot reload
├── health_checker.py   # Model health checks
├── request_logger.py   # Request logging
├── usage_controller.py # Usage control
├── time_controller.py  # Time-based scheduling & off-peak
├── start_proxy.py      # Startup script with CLI args
├── start.sh            # Shell start script
├── stop.sh             # Shell stop script
├── requirements.txt    # Python dependencies
├── proxy_config.yaml   # Configuration file
├── static/             # Frontend static assets
├── images/             # README screenshots
├── logs/               # Log directory
└── stats/              # Statistics data
```

## License

MIT
