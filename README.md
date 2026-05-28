<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="200" />
</p>

<h1 align="center">LLM Proxy</h1>

<p align="center">
  A lightweight, high-performance LLM API proxy server
</p>

<p align="center">
  English | <a href="README_CN.md">中文</a>
</p>

---

## Features

- **Multi-Model Management** - Configure multiple LLM providers and models with a unified endpoint
- **Smart Load Balancing** - Automatically distribute requests across available models
- **Failover** - Detect failures and switch to backup models to ensure availability
- **Request Logging** - Complete logging of all API requests and responses
- **IP Whitelist** - Fine-grained access control
- **Hot Reload** - Update configuration without restarting the server
- **Web Dashboard** - Intuitive visual management interface

## Screenshots

### Dashboard

![Dashboard](images/dashboard.png)

### Model Management

![Models](images/models.png)

### Configuration

![Config](images/cofing.png)

### Request Logs

![Logs](images/logs.png)

## Quick Start

### Install Dependencies

```bash
pip install fastapi uvicorn httpx pyyaml
```

### Start Server

```bash
uvicorn llm_proxy.server:app --host 0.0.0.0 --port 8000
```

### Configure Models

Edit `proxy_config.yaml`:

```yaml
models:
  available:
    my-model:
      api_base: https://api.example.com/v1
      api_key: your-api-key
      enabled: true
      model: model-name
```

## Project Structure

```
llm_proxy/
├── server.py           # Main server
├── model_manager.py    # Model management & load balancing
├── config_watcher.py   # Config file hot reload
├── health_checker.py   # Model health checks
├── request_logger.py   # Request logging
├── usage_controller.py # Usage control
├── time_controller.py  # Time control
├── proxy_config.yaml   # Configuration file
├── static/             # Frontend static assets
└── logs/               # Log directory
```

## API Usage

### Chat Completions

The proxy is fully compatible with the OpenAI Chat Completions API format.

**Basic Request (non-streaming):**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-model",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

**Streaming Request:**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "my-model",
    "stream": true,
    "messages": [
      {"role": "user", "content": "Tell me a joke."}
    ]
  }'
```

**Python (OpenAI SDK):**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="any-string"  # Proxy handles the real API key
)

response = client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)
```

**Auto Model Selection:**

Omit the `model` field to let the proxy automatically select an available model:

```python
response = client.chat.completions.create(
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### List Models

```bash
curl http://localhost:8000/v1/models
```

Response:

```json
{
  "object": "list",
  "data": [
    {"id": "my-model", "object": "model", "created": 0, "owned_by": "proxy"}
  ]
}
```

### Proxy Status

```bash
curl http://localhost:8000/proxy/status
```

### Health Check

```bash
curl http://localhost:8000/proxy/health
```

### Usage Statistics

```bash
curl http://localhost:8000/proxy/usage
```

### Request Logs

```bash
curl http://localhost:8000/proxy/logs
```

## API Endpoints Reference

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
| `/proxy/models/{name}/test` | POST | Test a model connection |

## License

MIT
