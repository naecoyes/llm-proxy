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
- **Smart Batch 归因** - 记录 Strix 批扫 `scan_id`、目标、PID、proxy slot、实际模型、provider/model_id、token、失败和模型切换。
- **Nscan 运行看板** - 展示 Smart Batch 进度、服务器资源、sing-box egress 状态、Docker bridge 作用域、脱敏后的 SOCKS5 节点池配置。
- **Egress 代理控制** - 当前运行状态和开机自启状态可独立设置，并支持重启。
- **访问控制检查** - 显示 IP 白名单和看板 PIN 是否已配置；设置 PIN 后，敏感读取和全部 `/proxy` 写操作要求 `X-Nscan-Pin`。
- **热重载配置** - 修改 `proxy_config.yaml` 无需重启服务，配置立即生效。
- **Web 管理面板** - 直观展示 Strix 扫描运行、模型健康和请求日志。

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

    # 套餐受限模型的本地保护阈值
    my-reserve-model:
      max_concurrent: 1
      max_requests_per_minute: 4
      max_requests_per_day: 500
      max_tokens_per_day: 2000000
```

套餐受限模型可配置为只参与指定扫描模式的自动路由：

```yaml
models:
  available:
    my-reserve-model:
      api_base: https://provider.example/v1
      api_key: 仅保存在未跟踪的运行配置中
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

扫描模式不匹配或用量达到软阈值时，Reserve 模型会退出 `autoN` 路由；显式指定模型仍可使用。
`GET /v1/models/available?scan_mode=redteam` 会返回套餐感知的推荐扫描并发。

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
| `/proxy/smart-batch/status` | GET | Smart Batch 状态快照和任务进度 |
| `/proxy/smart-batch/status/{batch_id}` | GET | 单个 Smart Batch 状态快照 |
| `/proxy/system/resources` | GET | 宿主机 CPU、内存、磁盘、网络、proxy 进程和批扫 PID 状态 |
| `/proxy/egress/usage` | GET | `br-strix` 网桥计数、扫描容器流量、目标归因和 SOCKS 节点池摘要 |
| `/proxy/security/status` | GET | 检查 IP 白名单和看板 PIN 是否配置 |
| `/proxy/security/verify` | POST | 校验 `X-Nscan-Pin` |
| `/proxy/security/logout` | POST | 清除浏览器持久管理会话 |
| `/proxy/nscan-runtime/status` | GET | Nscan 运行、sing-box egress、Docker 网络和脱敏 SOCKS5 节点池状态 |
| `/proxy/nscan-runtime/proxy-enabled` | POST | 使用 `{"enabled": true/false}` 单独设置当前运行状态 |
| `/proxy/nscan-runtime/proxy-startup-enabled` | POST | 使用 `{"enabled": true/false}` 单独设置开机自启状态 |
| `/proxy/nscan-runtime/proxy-restart` | POST | 重启 Nscan egress 代理服务 |
| `/proxy/nscan-runtime/nodes/{node_tag}/enabled` | POST | 将单个 SOCKS5 节点加入或移出自动代理池 |
| `/proxy/config` | GET/PUT | 读取或更新配置 |

## Nscan 运行看板

Web 首页已改为 Nscan Runtime Dashboard。进入 **Egress Proxy** 页面可以查看当前
`sing-box` 配置、`include_interface` 边界、`strix-egress` Docker 网络、SOCKS5 节点池和
节点 TCP 可达性。密码只显示脱敏结果。
看板也会通过 `/proxy/egress/usage` 展示 `br-strix` 网桥带宽、Docker 扫描容器流量、
目标域名/IP 和 `scan_id` 归因。这些指标只覆盖 Nscan Docker 扫描出站链路，不统计
LLM provider 请求流量。

默认读取 `/etc/sing-box/config.json` 并控制 `sing-box` systemd 服务，可通过环境变量覆盖：

```bash
export STRIX_EGRESS_SING_BOX_CONFIG=/etc/sing-box/config.json
export STRIX_EGRESS_SERVICE=sing-box
export STRIX_DOCKER_NETWORK=strix-egress
```

运行态 start/stop、开机自启 enable/disable 和 restart 会先尝试直接执行 `systemctl`，再尝试
`sudo -n systemctl ...`。生产环境建议只给
运行看板的用户授予 sing-box 相关的窄 sudo 权限，不要授予通用 sudo。该控制只影响 Nscan
Docker bridge 出站链路，不改变 LLM provider 路由，也不让 LLM proxy 自身走 SOCKS5。

节点卡片的独立开关只修改 `proxy-auto` 节点池，并强制至少保留一个出口。配置采用原子写入，
重启失败时自动回滚。`nscan_egress_node_control.py` 应以 root 所有、不可由面板用户修改的方式
安装到 `/usr/local/sbin/nscan-egress-node-control`，sudoers 只放行这个固定 helper。

看板 PIN 优先读取 `NSCAN_DASHBOARD_PIN`，其次读取 `admin.pin_code`，并兼容旧配置
`admin.api_key`。浏览器首次通过 `X-Nscan-Pin` 验证后会获得 HttpOnly、SameSite=Strict
管理 Cookie，后续访问无需重复输入 PIN。默认有效期 30 天，可通过
`NSCAN_DASHBOARD_SESSION_DAYS` 或 `admin.session_days` 设置为 1-365 天。修改 PIN 会使旧会话
自动失效；签名密钥保存在 `runtime/`，浏览器不会持久保存明文 PIN。

## 模型独立开关与使用方式

Models 页面为每个模型提供持久化独立开关。手动关闭后不会在 30 分钟后自动恢复；
健康检查触发的临时关闭仍保留冷却重试。Nscan Runtime 页面同时显示模型连接状态，
可以直接测试连接或进入新增模型表单。

`models.routing_mode` 支持两种自动路由方式：

- `balanced_all`（默认）：所有已开启、健康且满足额度与扫描模式约束的模型都会参与轮询和 `autoN` 槽位分配。
- `priority`：仅使用最高优先级的合格模型组，失败时再执行 fallback。

两种模式都会继续执行健康度、并发、速率、套餐额度和 scan mode 过滤。

## 项目结构

```
llm_proxy/
├── server.py                # FastAPI、OpenAI 兼容入口和 API 路由
├── model_manager.py         # 模型选择、fallback、并发与健康门控
├── usage_controller.py      # RPM、额度和并发状态
├── health_checker.py        # 健康检查、冷却与恢复
├── request_logger.py        # 请求、响应和模型切换归因
├── smart_batch_monitor.py   # 批次状态与运行时并发控制
├── smart_batch_jobs.py      # Dashboard 扫描预览与提交
├── asset_database.py        # Assets SQLite 数据访问层
├── findings.py              # Findings 文件索引与缓存
├── strix_runtime_monitor.py # 扫描 PID、容器及运行状态
├── start_proxy.py           # 启动脚本
├── proxy_config.yaml        # 本地敏感配置（不提交 Git）
├── static/                  # Dashboard 前端资源
└── tests/                   # 流式响应、状态并发等回归测试
```

完整的跨仓库架构、数据所有权、验证和部署流程见主仓库
[`docs/project-architecture.md`](../docs/project-architecture.md)。`llm_proxy` 是独立 Git 仓库：应先提交并推送本仓库，再在主仓库更新 gitlink。

## 许可证

MIT
