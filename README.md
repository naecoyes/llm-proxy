<p align="center">
  <img src="images/ChatGPT Image May 27, 2026, 11_09_44 AM.png" width="180" />
</p>

<h1 align="center">Nscan Runtime Dashboard</h1>

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

## Pre-Scan Scope Gate

Dashboard and API job submission uses the strict Nscan UAE public-interest
scope gate. `allow_non_uae` is retained only for compatibility and cannot
bypass admission. Use `GET /proxy/assets/scope-summary` to inspect catalog
freshness and derived counts, and `POST /proxy/assets/scope-catalog` to update
the protected versioned ScopeSentry catalog. Assets remain searchable even
when marked `scope_review_required` or `out_of_scope`; only target traffic is
blocked. See [Target Asset Scope](../docs/target_asset_scope.md).

- **Multi-Model Management** - Configure multiple LLM providers behind a unified OpenAI-compatible interface.
- **Anthropic API Support** - Native support for Anthropic Claude models with automatic conversion between OpenAI and Anthropic formats (including streaming).
- **OpenCode Go Provider Support** - Add OpenCode Go models from the dashboard or YAML, including OpenAI-compatible `/chat/completions` models and Anthropic-style `/messages` models.
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
- **Smart Batch Attribution** - Records Strix batch `scan_id`, target, PID, proxy slot, actual backend model, provider, model ID, token usage, failures, and model switches.
- **Nscan Runtime Dashboard** - Shows Smart Batch progress, host resources, sing-box egress status, Docker bridge scope, masked SOCKS5 pool configuration, and read-only boundary checks.
- **Asset Inventory Database** - Stores targets, aliases, resolved IPs, probe state, Smart Batch tasks, attempts, events, artifacts, and finding references in a local SQLite WAL database while keeping raw reports in their original directories.
- **Integrated Findings** - Searches and reviews vulnerability records, target aggregates, and Markdown reports in their existing Strix run directories, with shared tags, archive, star, and verification state from the retained 8080 viewer.
- **Egress Proxy Control** - Separately controls the current running state and boot startup state, plus restart, when the dashboard user has narrow `systemctl` permission.
- **Access Control Status** - Shows whether the IP whitelist and dashboard PIN are configured. Sensitive reads and all `/proxy` write operations require `X-Nscan-Pin` when a PIN is set.
- **Hot Configuration Reload** - Modify `proxy_config.yaml` on the fly without restarting the server.
- **Web Dashboard** - Intuitive visual management panel for Strix scan runtime, model health, and request logs.

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

    # OpenCode Go OpenAI-compatible model
    opencode-deepseek-flash:
      api_base: https://opencode.ai/zen/go/v1
      api_key: your-opencode-go-key
      model: opencode-go/deepseek-v4-flash
      provider: opencode-go
      api_format: openai
      strip_provider_prefix: true
      routing_tier: reserve
      allowed_scan_modes: [deep, redteam]
      priority: 80
      enabled: false

    # OpenCode Go Anthropic-style messages model
    opencode-qwen-plus:
      api_base: https://opencode.ai/zen/go/v1/messages
      api_key: your-opencode-go-key
      model: opencode-go/qwen3.7-plus
      provider: opencode-go
      api_format: anthropic
      is_exact_url: true
      strip_provider_prefix: true
      routing_tier: reserve
      allowed_scan_modes: [deep, redteam]
      priority: 90
      enabled: false

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

    # Optional local safety limits for a plan-limited model
    my-reserve-model:
      max_concurrent: 1
      max_requests_per_minute: 4
      max_requests_per_day: 500
      max_tokens_per_day: 2000000

    opencode-deepseek-flash:
      max_concurrent: 1
      max_requests_per_minute: 4
      input_cost_per_1m: 0.14
      output_cost_per_1m: 0.28
```

The Models page includes an **OpenCode Go preset** selector that fills the provider, endpoint,
API format, reserve routing tier, conservative rate limits, and cost metadata. The official
JS/TS `@opencode-ai/sdk` is not used here because that SDK controls an `opencode serve`
instance; Nscan consumes OpenCode Go as an upstream model provider through HTTP endpoints.

Plan-limited models may opt into quota-aware automatic routing:

```yaml
models:
  available:
    my-reserve-model:
      api_base: https://provider.example/v1
      api_key: keep-this-in-the-untracked-runtime-config
      model: coding-model
      provider: example
      routing_tier: reserve
      allowed_scan_modes: [deep, redteam]
      quota_policy:
        limited: true
        weekly_percent: 1
        monthly_percent: 0
        auto_disable_at_percent: 80
        observed_at: "2026-06-18T09:54:02+08:00"
```

Reserve models are excluded from automatic routing when the scan mode is not allowed or the
configured usage snapshot reaches the soft threshold. Explicit model selection still works.
`GET /v1/models/available?scan_mode=redteam` returns the quota-aware recommended scan parallelism.

### Model switches and usage mode

Each model has a persistent independent switch on the Models page. Manual disable stays off
until an operator enables it again; automatic health disable still uses a cooldown retry.

Set `models.routing_mode` from the dashboard or YAML:

- `balanced_all` (default): all enabled, healthy, eligible models participate in round-robin
  requests and `autoN` slot distribution.
- `priority`: only the highest-priority eligible group participates until fallback is needed.

Quota, rate, health, time-window, and scan-mode filters apply in both modes. The Nscan Runtime
page shows current model connectivity and provides a shortcut for testing or adding a model.

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
| `/proxy/logs` | GET | Request logs; supports `limit`, `scan_id`, `proxy_slot`, `date`, `start_date`, `end_date`, `days`, and `joined` filters |
| `/proxy/smart-batch/status` | GET | Smart Batch run snapshots and task progress |
| `/proxy/smart-batch/status/{batch_id}` | GET | One Smart Batch run snapshot |
| `/proxy/system/resources` | GET | Host CPU, memory, disk, network, proxy process, and Smart Batch PID status |
| `/proxy/egress/usage` | GET | `br-strix` bridge counters, scan container traffic, target attribution, and SOCKS pool summary |
| `/proxy/docker/containers` | GET | Cached Docker scan container state, attribution, and traffic counters |
| `/proxy/dashboard/summary` | GET | Overview aggregate; use `include_telemetry=false` for the fast initial page payload |
| `/proxy/dashboard/badges` | GET | Lightweight scan/model navigation counts without Docker sampling |
| `/proxy/vulnerabilities/summary` | GET | Cached Findings counts, source inventory, and shared-state availability |
| `/proxy/vulnerabilities` | GET | Server-side Findings search, filters, sorting, and pagination |
| `/proxy/assets/summary` | GET | SQLite asset inventory totals by scan/probe state |
| `/proxy/assets` | GET | Asset search, filters, sorting, and pagination |
| `/proxy/assets/{asset_id}` | GET | One asset with aliases, addresses, probes, scans, findings, and artifacts |
| `/proxy/assets/export` | GET | Filtered asset export as txt, csv, or json |
| `/proxy/vulnerabilities/{record_id}` | GET | One finding and its shared review state |
| `/proxy/vulnerabilities/{record_id}/content` | GET | Referenced Markdown evidence; add `download=true` for attachment mode |
| `/proxy/vulnerabilities/{record_id}/state` | PATCH | Update tags, star, mark, archive, read, or verification state |
| `/proxy/vulnerabilities/bulk-state` | POST | Apply one state change to multiple findings |
| `/proxy/vulnerabilities/autoclean` | POST | Run the retained viewer's auto-clean rules |
| `/proxy/vulnerability-reports` | GET | List configured consolidated Markdown reports |
| `/proxy/security/status` | GET | IP whitelist and dashboard PIN configuration status |
| `/proxy/security/verify` | POST | Verify the `X-Nscan-Pin` header |
| `/proxy/security/logout` | POST | Clear the persistent dashboard administration session |
| `/proxy/nscan-runtime/status` | GET | Nscan runtime, sing-box egress, Docker network, and masked SOCKS5 pool status |
| `/proxy/nscan-runtime/proxy-enabled` | POST | Start or stop the current egress service with `{"enabled": true/false}` |
| `/proxy/nscan-runtime/proxy-startup-enabled` | POST | Enable or disable service startup with `{"enabled": true/false}` |
| `/proxy/nscan-runtime/proxy-restart` | POST | Restart the Nscan egress proxy service |
| `/proxy/nscan-runtime/nodes/{node_tag}/enabled` | POST | Add or remove one SOCKS5 node from the automatic pool |
| `/proxy/config` | GET/PUT | Read or update configuration |

### Smart Batch Scan Context

When Strix Smart Batch runs through this proxy, it can attach local-only attribution headers:

```text
X-Strix-Batch-Scan-Id
X-Strix-Batch-Target
X-Strix-Batch-Root-Domain
X-Strix-Batch-Proxy-Slot
X-Strix-Batch-Retry
X-Strix-Process-Pid
```

The proxy stores these fields in request, response, and model-switch logs. They are used for local observability only and do not change model selection. The dashboard groups active processes by `scan_id` when present, and falls back to the older `autoN`/client IP grouping for ordinary requests.

Examples:

```bash
curl "http://127.0.0.1:8888/proxy/logs?scan_id=<scan-id>&limit=500"
curl "http://127.0.0.1:8888/proxy/logs?proxy_slot=auto1&limit=500"
curl "http://127.0.0.1:8888/proxy/logs?scan_id=<scan-id>&days=2&joined=true"
```

`joined=true` returns a per-request view that joins request, response, and model-switch entries by `request_id`, plus model-switch reason counts for the selected logs.

### Smart Batch Dashboard

`scanScript/smart_batch_scan.py` writes state snapshots to `llm_proxy/runtime/smart_batch/` by default. Set `STRIX_BATCH_STATE_DIR` when the proxy and scanner need to share another directory.

The Web Dashboard includes a **Smart Batch** section with active/stale/recent batches, task tables, failures, recent events, scan-level model attribution, and server resource cards.

### Dual Engine Runtime

New Dashboard jobs use **Dual engine** when its preflight is healthy: Strix runs `redteam` first,
then Chelmon-Claude runs its own native headless task brief. Chelmon is executed in a dedicated
`nscan/chelmon-engine` container on `strix-egress`; target traffic stays in the scan egress path,
while LLM traffic goes only to the local Nscan Proxy using the assigned `autoN` alias.

The runner writes a task-local provider configuration with a non-secret placeholder key and injects
the existing `X-Strix-Batch-*` attribution headers only for local proxy requests. It never reads a
host-level Chelmon configuration or upstream provider credentials. Dual submission is fail-closed
unless the image, Docker network, local proxy, and an eligible `redteam` model are all healthy.
Check `GET /proxy/smart-batch/jobs/health-summary` for the current gate result.

Chelmon findings are evidence-gated review candidates. Each reported candidate must reference one
or more immutable `ev-*` records generated by real target-host `curl` traffic and a direct impact
proof. Requests to Nscan/LLM endpoints, loopback, Docker bridge addresses, private infrastructure,
or a different host are rejected by the tool layer. New candidates are tagged
`pending_evidence_review`, excluded from normal Critical/High totals, and remain invisible from the
default Findings list until manually Verified. A completed Chelmon child with candidates reports
`completed_with_review_pending`; it is not a verified-vulnerability outcome.

### Independent Workers And Recovery

New Dual jobs are launched through `systemd-run --user` as `nscan-scan-<job-id>` units rather than as children
of `llm-proxy.service`. This isolates active scans from a 8888 restart. Each job snapshot records
`worker_unit`, `worker_status`, PID, `recovery_state`, and child Smart Batch IDs. On reconciliation, a missing
unit/PID is recorded as `interrupted`; it is never inferred to be complete. `POST
/proxy/smart-batch/jobs/{job_id}/resume` starts a new worker for only unfinished checkpointed stages. Completed
stages and their reports remain intact.

Parent preflight is resumable. During DNS/TLS/HTTP probing, each completed target is appended to
`<job-state-dir>/_preflight/preflight_results.jsonl`; the worker updates `preflight_progress` in the job
snapshot every two seconds or 25 completed targets. A completed run also writes the stable
`preflight_manifest.json` and a filtered live-target file. Recovery reads the ledger and probes only unfinished
targets. If the manifest and filtered file are already complete, the coordinator reuses them without repeating
network requests.

The Activity page shows preflight counters even when no LLM call exists yet. Scans presents preflight progress,
effective scan progress, and the Dual engine stage separately. Opening `static/index.html` through `file://` is
not a supported data source; the page links to the production dashboard instead of issuing silent relative API
requests.

PwnDoc-compatible Word export requires `python-docx`. The dashboard checks
`GET /proxy/vulnerabilities/export-capabilities` and disables Word export with a reason when the runtime
dependency is unavailable. Run the production contract suite with the project Python environment:

```bash
make test-nscan
```

Model routing uses a network circuit breaker: transient DNS/TCP/stream errors stay retryable for two events;
the third opens a jittered cooldown. Quota, authentication, context-length and deterministic request errors
remain separate classes. `GET /proxy/smart-batch/jobs/runtime-summary` is a lightweight worker-only status API
for Dashboard polling and does not invoke Docker telemetry.

Docker and egress telemetry is sampled once and shared for 3 seconds across Overview, Scans, and
Egress API calls. Blocking Docker CLI work runs outside the FastAPI event loop. Pages render their
fast operational data first and fill container/bandwidth panels independently; a slow or failed
telemetry refresh therefore does not block navigation. The navigation badges use
`/proxy/dashboard/badges` and never invoke `docker stats`.

### Nscan Runtime Dashboard

The dashboard root is now oriented around Nscan runtime operations. The **Egress Proxy** page reads
the local sing-box configuration, masks credentials, shows the `include_interface` boundary, checks
the `strix-egress` Docker network, and can optionally test TCP reachability for each SOCKS5 node.
It also reads `/proxy/egress/usage` for bridge-level bandwidth, Docker scan container traffic,
target/domain/IP attribution, and `scan_id` mapping. These metrics cover Nscan Docker scan traffic
only; LLM provider requests are routed by the model proxy configuration, not this SOCKS5 egress pool.

By default it reads `/etc/sing-box/config.json` and controls the `sing-box` systemd service. Override
with:

```bash
export STRIX_EGRESS_SING_BOX_CONFIG=/etc/sing-box/config.json
export STRIX_EGRESS_SERVICE=sing-box
export STRIX_DOCKER_NETWORK=strix-egress
```

Start/stop, enable/disable startup, and restart actions use `systemctl` directly first, then
`sudo -n systemctl ...` if needed.
For a production dashboard, grant only the specific commands required for `sing-box`; do not grant
general sudo. This control only affects the Nscan Docker bridge egress path and does not modify LLM
provider routing.

Per-node switches update only the selector pool, keep at least one node enabled, restart sing-box,
and roll the configuration back if restart fails. Install `nscan_egress_node_control.py` as the
root-owned `/usr/local/sbin/nscan-egress-node-control` helper and allow only that helper via sudoers.
The Egress page can also add, edit, and delete SOCKS5 nodes through this helper. Existing passwords
remain write-only: reads return only a masked hint, and an empty password during edit preserves the
current secret. Every configuration change is atomic and rolls back if `sing-box` cannot restart.

`Scan History` includes a paginated scanned-target registry from `scanned_domains.txt`, Smart Batch
history files under `reports/`, and legacy 0.8.3 history files when that directory is present. Set
`NSCAN_SCANNED_HISTORY_PATHS` to an `os.pathsep`-separated list to override the indexed sources.

### Asset Database

The dashboard keeps a local SQLite WAL database at `llm_proxy/runtime/nscan-assets.sqlite3`.
It is a metadata store only: Strix reports, CSV files, SDK databases, and Markdown evidence remain in
their original directories and are referenced by path.

```bash
# Repeatable online import
python llm_proxy/asset_migrate.py --report reports/asset_migration.json

# Online backup with retention
python llm_proxy/asset_maintenance.py backup

# Dry-run cold archive preview for old completed runs
python llm_proxy/asset_maintenance.py archive --days 30
```

Probe and Smart Batch write best-effort updates into the database. If the DB is temporarily locked or
unavailable, events are spooled under `llm_proxy/runtime/asset_spool/` and can be replayed through
`POST /proxy/assets/spool/replay`.

### Native Reasoning

Nscan enables native reasoning at `high` by default only for models with a known or explicitly
configured provider contract. DeepSeek uses its `thinking` request shape; OpenRouter uses the
portable `reasoning.effort` object. `tencent/hy3:free` is recognized as an OpenRouter reasoning
model and supports `none`, `low`, and `high` effort. When an OpenRouter model is added or edited,
Nscan refreshes `/api/v1/models` once and reads its per-model reasoning metadata; **Sync OpenRouter
reasoning** performs the same refresh on demand. In **Models**, set **Native reasoning support**,
choose the provider request contract, and select the effort. Unknown models remain off until their
reasoning API compatibility is explicitly confirmed, so Nscan never sends speculative parameters to
an upstream provider. Reasoning is retained only for required tool-call continuity and is not stored
in Nscan request logs.

Set the dashboard PIN with `NSCAN_DASHBOARD_PIN` or `admin.pin_code`. Existing deployments may use
`admin.api_key` as a compatibility fallback. The first successful `X-Nscan-Pin` verification issues
an HttpOnly, SameSite=Strict administration cookie, so later visits do not need the PIN again.
The default lifetime is 30 days; set `NSCAN_DASHBOARD_SESSION_DAYS` or `admin.session_days` to 1-365.
Changing the PIN invalidates existing sessions. The signing secret is persisted under `runtime/` and
the raw PIN is never stored in browser storage.

## License

MIT
