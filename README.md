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

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/chat/completions` | Chat Completions compatible API |
| `GET /v1/models` | List available models |
| `GET /admin/dashboard` | Admin dashboard |
| `GET /admin/logs` | Request logs |

## License

MIT
