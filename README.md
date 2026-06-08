<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">LLM Proxy Hub</h1>

<p align="center">
  A Lightweight, High-Performance LLM API Proxy Server
</p>

<p align="center">
  English | <a href="README_CN.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

---

## Features

- **Multi-Model Management** - Configure multiple LLM providers behind a unified OpenAI-compatible interface.
- **Anthropic API Support** - Native support for Anthropic Claude models with automatic conversion between OpenAI and Anthropic formats (including streaming).
- **Slot Routing (Session Affinity)** - Request specific "slots" (e.g., `auto1`, `auto2`) to consistently map to the same underlying model for better context caching and connection reuse. **Strictly respects `max_concurrent` limits**: if a high-priority model reaches its max concurrency, remaining slots automatically map to the next best priority models. Slots also automatically failover upon model quota exhaustion.
- **Intelligent Load Balancing** - Automatically dispatch requests to healthy models with dynamic filtering (skips models with recent success rates < 70%).
- **Off-Peak Scheduling** - Dynamically boost priority of specified models during off-peak hours (with timezone support) to optimize costs.
- **Quota Awareness & Auto-Recovery** - Recognizes rate limit and quota exhaustion errors, parsing the reset time (e.g., Minimax's 5-hour limit) to automatically re-enable models when their quota resets.
- **Rate Limit Awareness** - Automatically skips models hitting rate limits, gracefully falling back to other models in the same or different providers.
- **Fallback to Free Models** - Seamlessly switch to designated free models when all paid models are exhausted or unavailable, ensuring zero downtime.
- **High Availability Failover** - Detects failures in real-time and switches to backup models seamlessly.
- **Auto-Disable & Active Probing** - Automatically disables models after consecutive health check failures, and occasionally probes them to automatically restore them when they become healthy again.
- **Concurrency Control** - Fine-grained concurrency limits (`max_concurrent`) per model to prevent overloading upstream APIs.
- **IP Whitelist** - Strict access control based on client IPs, supporting `X-Forwarded-For` and `X-Real-IP` headers.
- **Usage & Request Logging** - Detailed tracking of API requests, response times, and token usage.
- **Hot Configuration Reload** - Modify `proxy_config.yaml` on the fly without restarting the server.
- **Web Dashboard** - Intuitive visual management panel for real-time monitoring and model health checks.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configuration

Create or edit `proxy_config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8888
  allowed_ips:
    - 127.0.0.1
    - ::1

models:
  available:
    # OpenAI compatible model
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

# Time-based scheduling strategy (optional)
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

### 3. Start the Service

```bash
# Using shell scripts
chmod +x start.sh stop.sh
./start.sh    # Start in background
./stop.sh     # Stop background service

# Or start directly
python start_proxy.py --config proxy_config.yaml --port 8888
```

Once started, the Web Dashboard will be available at `http://127.0.0.1:8888`.

### 4. Command Line Arguments

```
python start_proxy.py [options]

Options:
  --config, -c    Path to config file (default: proxy_config.yaml)
  --host          Listen address (default: from config)
  --port, -p      Listen port (default: from config)
  --log-level     Log level (debug/info/warning/error)
  --reload        Enable auto-reload (development mode)
```

## API Usage

The proxy server is fully compatible with the **OpenAI Chat Completions API**.

### Chat Completions

**Slot Routing (Session Affinity):**
Pass `auto1`, `auto2`, etc., as the `model` parameter to firmly map requests from the same session to the same backend model.

```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto1",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

**Python (OpenAI SDK):**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8888/v1",
    api_key="any-string"  # API keys are handled by the proxy
)

response = client.chat.completions.create(
    model="auto",  # Automatically selects the best model, or use specific model/slot name like 'auto1'
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat Completions compatible endpoint |
| `/v1/models` | GET | List available models |
| `/proxy/status` | GET | Proxy status overview |
| `/proxy/health` | GET | Model health check results |
| `/proxy/usage` | GET | Usage statistics |
| `/proxy/logs` | GET | Request logs |
| `/proxy/config` | GET/PUT | Read or update configuration |

## License

MIT
