import { api } from "../api.js";
import { Poller } from "../poller.js";
import { badge, confirmAction, emptyState, errorState, modelIdentity, openDrawer, closeDrawer, providerChip, skeleton, toast } from "../components.js?v=20260623-provider-ui";
import { debounce, escapeHtml, formatNumber } from "../utils.js";

const STALE_PENDING_MS = 10 * 60 * 1000;
const OPENCODE_CHAT_BASE = "https://opencode.ai/zen/go/v1";
const OPENCODE_MESSAGES_URL = "https://opencode.ai/zen/go/v1/messages";
const OPENCODE_PRESETS = [
  ["glm-5.2", "GLM-5.2", "openai", 1.40, 4.40],
  ["glm-5.1", "GLM-5.1", "openai", 1.40, 4.40],
  ["kimi-k2.7-code", "Kimi K2.7 Code", "openai", 0.95, 4.00],
  ["kimi-k2.6", "Kimi K2.6", "openai", 0.95, 4.00],
  ["deepseek-v4-pro", "DeepSeek V4 Pro", "openai", 1.74, 3.48],
  ["deepseek-v4-flash", "DeepSeek V4 Flash", "openai", 0.14, 0.28],
  ["mimo-v2.5", "MiMo V2.5", "openai", 0.14, 0.28],
  ["mimo-v2.5-pro", "MiMo V2.5 Pro", "openai", 1.74, 3.48],
  ["minimax-m3", "MiniMax M3", "anthropic", 0.30, 1.20],
  ["minimax-m2.7", "MiniMax M2.7", "anthropic", 0.30, 1.20],
  ["minimax-m2.5", "MiniMax M2.5", "anthropic", 0.30, 1.20],
  ["qwen3.7-max", "Qwen3.7 Max", "anthropic", 2.50, 7.50],
  ["qwen3.7-plus", "Qwen3.7 Plus", "anthropic", 0.40, 1.60],
  ["qwen3.6-plus", "Qwen3.6 Plus", "anthropic", 0.50, 3.00],
].map(([id, label, apiFormat, inputCost, outputCost]) => ({ id, label, apiFormat, inputCost, outputCost }));

function modelLimits(config, name) {
  return config?.usage?.per_model_limits?.[name] || {};
}

function formatMoney(value = 0) {
  const number = Number(value) || 0;
  if (number === 0) return "$0.0000";
  if (Math.abs(number) < 0.0001) return "<$0.0001";
  return `$${number.toFixed(4)}`;
}

function formatProviderBalance(balance = {}) {
  if (!balance) return "";
  if (balance.error) return `Balance unavailable: ${balance.error}`;
  if (balance.total_balance === undefined || balance.total_balance === null) return "";
  const value = Number(balance.total_balance);
  const amount = Number.isFinite(value) ? value.toFixed(2) : String(balance.total_balance);
  const currency = balance.currency || "";
  const status = balance.available === false ? "unavailable" : "available";
  return `Balance ${amount}${currency ? ` ${currency}` : ""} · ${status}`;
}

function usageTokens(stats = {}) {
  return Number(stats.tokens ?? stats.total_tokens ?? 0) || 0;
}

function usageInputTokens(stats = {}) {
  return Number(stats.input_tokens ?? stats.prompt_tokens ?? 0) || 0;
}

function usageOutputTokens(stats = {}) {
  return Number(stats.output_tokens ?? stats.completion_tokens ?? 0) || 0;
}

function classifyRow(row) {
  if (row.status === "pending") {
    const reqTime = new Date(row.request_timestamp || 0).getTime();
    if (reqTime && Date.now() - reqTime > STALE_PENDING_MS) return "stale_no_response";
    if (!row.scan_id && !row.scan_target) return "orphan_request";
    return "pending_active";
  }
  return row.status || "unknown";
}

function joinedRequests(logs) {
  return (logs?.joined?.requests || []).map((row) => ({ ...row, classified_status: classifyRow(row) }));
}

function summarizeRequests(rows) {
  const acc = { pending_active: 0, stale_no_response: 0, orphan_request: 0 };
  for (const row of rows) {
    if (row.classified_status === "pending_active") acc.pending_active += 1;
    else if (row.classified_status === "stale_no_response") acc.stale_no_response += 1;
    else if (row.classified_status === "orphan_request") acc.orphan_request += 1;
  }
  return acc;
}

function renderActivityMetrics(status, logs, logsError) {
  const usage = status.usage?.daily || {};
  const history7d = status.usage?.history?.["7d"] || {};
  const historyTotal = status.usage?.history?.total || {};
  const requests = joinedRequests(logs);
  const buckets = summarizeRequests(requests);
  return `<div class="metrics-grid single-row">
    <div class="metric-card"><div class="metric-label">Daily requests</div><div class="metric-value">${formatNumber(usage.requests || 0)}</div><div class="metric-detail">Persistent usage counter</div></div>
    <div class="metric-card"><div class="metric-label">Daily tokens</div><div class="metric-value">${formatNumber(usage.tokens || 0)}</div><div class="metric-detail">${formatNumber(usage.output_tokens || 0)} output</div></div>
    <div class="metric-card"><div class="metric-label">Daily cost</div><div class="metric-value">${formatMoney(usage.cost || 0)}</div><div class="metric-detail">Provider or fallback estimate</div></div>
    <div class="metric-card"><div class="metric-label">7d usage</div><div class="metric-value">${formatNumber(history7d.tokens || 0)}</div><div class="metric-detail">${formatMoney(history7d.cost || 0)} · ${formatNumber(history7d.requests || 0, 0)} requests</div></div>
    <div class="metric-card"><div class="metric-label">Total usage</div><div class="metric-value">${formatNumber(historyTotal.tokens || 0)}</div><div class="metric-detail">${formatMoney(historyTotal.cost || 0)} · ${formatNumber(historyTotal.requests || 0, 0)} requests</div></div>
    <div class="metric-card ${logsError || buckets.stale_no_response ? "warning" : ""}"><div class="metric-label">Stale (no response)</div><div class="metric-value">${logsError ? "-" : buckets.stale_no_response}</div><div class="metric-detail">${logsError ? "Log window unavailable" : `${buckets.pending_active} pending · ${buckets.orphan_request} orphan`}</div></div>
  </div>`;
}

function inferredProvider(name) {
  const value = String(name || "").toLowerCase();
  if (value.includes("mimo") || value.includes("xiaomi")) return "xiaomi";
  if (value.includes("ark") || value.includes("volc")) return "volces";
  if (value.includes("opencode")) return "opencode-go";
  if (value.includes("openai-proxy") || value.includes("openai")) return "openai-proxy";
  if (value.includes("deepseek")) return "deepseek";
  if (value.includes("openrouter") || value.startsWith("or-") || value.includes("owl")) return "openrouter";
  if (value.includes("anyrouter")) return "anyrouter";
  if (value.includes("nvidia") || value.includes("nemotron")) return "nvidia";
  if (value.includes("minimax")) return "minimax";
  return "unknown";
}

function normalizeProvider(provider, fallbackName = "") {
  const value = String(provider || "").trim().toLowerCase();
  if (!value || value === "unknown") return inferredProvider(fallbackName);
  if (value.includes("mimo") || value.includes("xiaomi")) return "xiaomi";
  return value;
}

function buildProviderUsage(status) {
  const configuredModels = status.models || {};
  const perModel = status.usage?.history?.total?.per_model || status.usage?.per_model || {};
  const providerBalances = status.provider_balances || {};
  const providers = new Map();

  Object.entries(perModel).forEach(([name, stats]) => {
    const model = configuredModels[name] || {};
    const provider = normalizeProvider(model.provider || stats.provider, name);
    if (!provider || provider === "unknown") return;
    const providerRow = providers.get(provider) || {
      provider,
      balance: providerBalances[provider],
      requests: 0,
      tokens: 0,
      input_tokens: 0,
      output_tokens: 0,
      cost: 0,
      models: [],
    };
    const row = {
      name,
      model_id: model.model || stats.model_id || name,
      provider,
      requests: Number(stats.requests || 0),
      tokens: usageTokens(stats),
      input_tokens: usageInputTokens(stats),
      output_tokens: usageOutputTokens(stats),
      cost: Number(stats.cost || 0),
      budget_available: stats.budget_available,
    };
    providerRow.requests += row.requests;
    providerRow.tokens += row.tokens;
    providerRow.input_tokens += row.input_tokens;
    providerRow.output_tokens += row.output_tokens;
    providerRow.cost += row.cost;
    providerRow.models.push(row);
    providers.set(provider, providerRow);
  });

  return Array.from(providers.values())
    .map((provider) => ({
      ...provider,
      models: provider.models.sort((a, b) => b.tokens - a.tokens || b.cost - a.cost),
    }))
    .sort((a, b) => b.tokens - a.tokens || b.cost - a.cost || a.provider.localeCompare(b.provider));
}

function renderProviderUsage(status) {
  const providers = buildProviderUsage(status);
  if (!providers.length) {
    return emptyState("No provider usage recorded", "Usage appears here after successful model responses are logged.");
  }
  const cards = providers.map((provider) => {
    const topModels = provider.models.slice(0, 2).map((model) => model.name).join(", ");
    const more = provider.models.length > 2 ? ` +${provider.models.length - 2} more` : "";
    const balance = formatProviderBalance(provider.balance);
    return `<div class="metric-card provider-usage-card">
      <div class="metric-label">${providerChip({ provider: provider.provider })}</div>
      <div class="metric-value">${formatNumber(provider.tokens)}</div>
      <div class="metric-detail">${formatMoney(provider.cost)} · ${formatNumber(provider.requests, 0)} requests</div>
      ${balance ? `<div class="metric-detail">${escapeHtml(balance)}</div>` : ""}
      <div class="provider-usage-models" title="${escapeHtml(topModels)}">${escapeHtml(topModels || "No model")}${escapeHtml(more)}</div>
    </div>`;
  }).join("");
  return `<div class="metrics-grid single-row provider-usage-grid">${cards}</div>`;
}

function renderModels(status, config, query) {
  const entries = Object.entries(status.models || {}).filter(([name, model]) => `${name} ${model.model} ${model.provider} ${model.label}`.toLowerCase().includes(query.toLowerCase()));
  if (!entries.length) return emptyState("No matching models");
  return `<div class="table-scroll"><table class="data-table"><thead><tr><th>Model</th><th>Provider</th><th>Priority</th><th>Limits</th><th>Routing</th><th>Use</th><th>Status</th><th></th></tr></thead><tbody>${entries.map(([name, model]) => {
    const limits = modelLimits(config, name);
    const health = model.health || {};
    const route = model.auto_routing || {};
    const statusLabel = !model.enabled ? "Disabled" : health.healthy === false ? "Unhealthy" : "Healthy";
    const tags = [model.free ? "Free" : "Paid", model.routing_tier === "reserve" ? "Reserve" : "", model.api_format === "anthropic" ? "Messages" : "Chat", model.thinking_enabled && model.reasoning_supported ? `Thinking ${model.reasoning_effort || "high"}` : "", ...(model.allowed_scan_modes || [])].filter(Boolean);
    const secondary = `<div class="tag-row">${tags.map((tag) => badge(tag, tag === "Free" ? "success" : "info")).join("")}</div><div class="mono">${escapeHtml(model.model || "-")} ${model.api_key_hint ? `· key •••${escapeHtml(model.api_key_hint)}` : ""}</div>`;
    return `<tr data-model="${escapeHtml(name)}"><td>${modelIdentity({ ...model, name }, { secondary })}</td>
      <td>${providerChip({ ...model, name })}</td><td>${model.priority ?? "-"}</td><td><div>${limits.max_concurrent || "unlimited"} concurrent</div><div class="cell-secondary">${limits.max_requests_per_minute || "unlimited"} RPM</div></td>
      <td><div>${badge(route.eligible && model.enabled ? "eligible" : "excluded", route.eligible && model.enabled ? "success" : "warning")}</div><div class="cell-secondary">${escapeHtml(route.reason || (route.eligible ? "auto routing" : "filtered"))}</div></td>
      <td><label class="switch" title="${model.enabled ? "Disable" : "Enable"} ${escapeHtml(name)}"><input type="checkbox" data-action="toggle" ${model.enabled ? "checked" : ""}><span class="switch-track"></span></label></td>
      <td>${badge(statusLabel)}${health.reason ? `<div class="cell-secondary break-anywhere" title="${escapeHtml(health.reason)}">${escapeHtml(health.reason.slice(0, 72))}</div>` : ""}</td>
      <td class="actions-cell"><button class="button ghost small" type="button" data-action="test">Test</button><button class="button ghost small" type="button" data-action="edit">Edit</button><button class="button text-danger small" type="button" data-action="delete">Delete</button></td></tr>`;
  }).join("")}</tbody></table></div>`;
}

function modelForm(model = null) {
  const editing = Boolean(model);
  const limits = model?.limits || {};
  const overrides = model?.request_overrides || {};
  const customHeaders = model?.custom_headers && Object.keys(model.custom_headers).length ? JSON.stringify(model.custom_headers, null, 2) : "";
  return `<form id="modelForm" class="form-grid">
    <label class="field full">OpenCode Go preset<select name="opencode_preset">
      <option value="">Manual provider model</option>
      ${OPENCODE_PRESETS.map((preset) => `<option value="${preset.id}" ${model?.provider === "opencode-go" && model?.model?.endsWith(preset.id) ? "selected" : ""}>${escapeHtml(preset.label)} · ${preset.apiFormat}</option>`).join("")}
    </select><span class="field-help">Optional. Prefills OpenCode Go endpoints and conservative routing limits.</span></label>
    <label class="field">Display name<input name="name" required ${editing ? "disabled" : ""} value="${escapeHtml(model?.name || "")}" placeholder="provider-model"></label>
    <label class="field">Provider<input name="provider" value="${escapeHtml(model?.provider || "")}" placeholder="openrouter"></label>
    <label class="field full">Model ID<input name="model" required value="${escapeHtml(model?.model || "")}" placeholder="provider/model-id"></label>
    <label class="field full">API base URL<input name="api_base" type="url" required value="${escapeHtml(model?.api_base || "")}" placeholder="https://api.example.com/v1"></label>
    <label class="field full">API key<input name="api_key" type="password" autocomplete="new-password" placeholder="${model?.api_key_configured ? `Configured · •••${escapeHtml(model.api_key_hint || "")}. Leave blank to keep.` : "Enter API key"}"><span class="field-help">Write-only. Existing keys are never returned to the browser.</span></label>
    <label class="field">API format<select name="api_format"><option value="openai" ${model?.api_format !== "anthropic" ? "selected" : ""}>OpenAI compatible</option><option value="anthropic" ${model?.api_format === "anthropic" ? "selected" : ""}>Anthropic messages</option></select></label>
    <label class="field">Exact endpoint URL<select name="is_exact_url"><option value="false" ${!model?.is_exact_url ? "selected" : ""}>Append route</option><option value="true" ${model?.is_exact_url ? "selected" : ""}>Use exact URL</option></select></label>
    <label class="field">Strip provider prefix<select name="strip_provider_prefix"><option value="true" ${model?.strip_provider_prefix !== false ? "selected" : ""}>Enabled</option><option value="false" ${model?.strip_provider_prefix === false ? "selected" : ""}>Disabled</option></select></label>
    <label class="field">Context window<input name="max_context_tokens" type="number" min="0" value="${model?.max_context_tokens || 0}"><span class="field-help">0 means unknown; redteam routing may exclude small windows.</span></label>
    <label class="field">Native reasoning support<select name="reasoning_supported"><option value="true" ${model?.reasoning_supported ? "selected" : ""}>Supported</option><option value="false" ${model?.reasoning_supported !== true ? "selected" : ""}>Not supported</option></select><span class="field-help">Enable only when the provider accepts native reasoning controls.</span></label>
    <label class="field">Thinking mode<select name="thinking_enabled"><option value="true" ${model?.thinking_enabled !== false && model?.reasoning_supported !== false ? "selected" : ""}>Enabled</option><option value="false" ${model?.thinking_enabled === false ? "selected" : ""}>Disabled</option></select><span class="field-help">Enabled models default to High. Reasoning stays out of Nscan logs.</span></label>
    <label class="field">Reasoning API<select name="reasoning_api"><option value="auto" ${!model?.reasoning_api || model?.reasoning_api === "auto" ? "selected" : ""}>Auto by provider</option><option value="openrouter" ${model?.reasoning_api === "openrouter" ? "selected" : ""}>OpenRouter reasoning</option><option value="openai" ${model?.reasoning_api === "openai" ? "selected" : ""}>OpenAI reasoning effort</option><option value="deepseek" ${model?.reasoning_api === "deepseek" ? "selected" : ""}>DeepSeek thinking</option></select></label>
    <label class="field">Reasoning effort<select name="reasoning_effort"><option value="none" ${(model?.reasoning_effort || "") === "none" ? "selected" : ""}>Off</option><option value="low" ${(model?.reasoning_effort || "") === "low" ? "selected" : ""}>Low</option><option value="high" ${(model?.reasoning_effort || "high") === "high" ? "selected" : ""}>High</option><option value="max" ${(model?.reasoning_effort || "") === "max" ? "selected" : ""}>Max</option></select><span class="field-help">Default High. OpenRouter Hy3 supports Off, Low, and High.</span></label>
    <label class="field">Priority<input name="priority" type="number" min="0" value="${model?.priority ?? 100}"></label>
    <label class="field">Label<input name="label" value="${escapeHtml(model?.label || "")}" placeholder="Optional label"></label>
    <label class="field">Max concurrent<input name="max_concurrent" type="number" min="0" value="${limits.max_concurrent || 0}"><span class="field-help">0 uses the provider default.</span></label>
    <label class="field">Max RPM<input name="max_requests_per_minute" type="number" min="0" value="${limits.max_requests_per_minute || 0}"></label>
    <label class="field">Input $ / 1M<input name="input_cost_per_1m" type="number" min="0" step="0.0001" value="${limits.input_cost_per_1m || 0}"></label>
    <label class="field">Output $ / 1M<input name="output_cost_per_1m" type="number" min="0" step="0.0001" value="${limits.output_cost_per_1m || 0}"></label>
    <label class="field">Max output tokens<input name="max_tokens" type="number" min="0" value="${overrides.max_tokens || overrides.max_output_tokens || 0}"><span class="field-help">0 leaves client request unchanged.</span></label>
    <label class="field">Routing tier<select name="routing_tier"><option value="standard" ${model?.routing_tier !== "reserve" ? "selected" : ""}>Standard</option><option value="reserve" ${model?.routing_tier === "reserve" ? "selected" : ""}>Reserve</option></select></label>
    <label class="field">Allowed scan modes<input name="allowed_scan_modes" value="${escapeHtml((model?.allowed_scan_modes || []).join(", "))}" placeholder="deep, redteam"></label>
    <label class="field">Plan type<select name="free"><option value="false" ${!model?.free ? "selected" : ""}>Paid / limited</option><option value="true" ${model?.free ? "selected" : ""}>Free</option></select></label>
    <label class="field">Enabled<select name="enabled"><option value="true" ${model?.enabled !== false ? "selected" : ""}>Enabled</option><option value="false" ${model?.enabled === false ? "selected" : ""}>Disabled</option></select></label>
    <label class="field full">Custom headers<textarea name="custom_headers" rows="4" placeholder='{"X-Header":"value"}'>${escapeHtml(customHeaders)}</textarea><span class="field-help">Optional JSON object. API keys remain separate and write-only.</span></label>
    <div class="drawer-footer full"><button class="button secondary" type="button" data-close-drawer>Cancel</button><button class="button" type="submit">${editing ? "Save changes" : "Add model"}</button></div>
  </form>`;
}

function formPayload(form, editing = false) {
  const values = Object.fromEntries(new FormData(form).entries());
  let customHeaders = {};
  if (values.custom_headers?.trim()) {
    customHeaders = JSON.parse(values.custom_headers);
    if (!customHeaders || Array.isArray(customHeaders) || typeof customHeaders !== "object") {
      throw new Error("Custom headers must be a JSON object");
    }
  }
  const payload = {
    name: values.name,
    provider: values.provider.trim(),
    model: values.model.trim(),
    api_base: values.api_base.trim(),
    api_format: values.api_format || "openai",
    is_exact_url: values.is_exact_url === "true",
    strip_provider_prefix: values.strip_provider_prefix !== "false",
    custom_headers: customHeaders,
    max_context_tokens: Number(values.max_context_tokens) || 0,
    reasoning_supported: values.reasoning_supported === "true",
    reasoning_api: values.reasoning_api || "auto",
    thinking_enabled: values.thinking_enabled === "true",
    reasoning_effort: values.reasoning_effort || "high",
    priority: Number(values.priority) || 0,
    label: values.label.trim(),
    max_concurrent: Number(values.max_concurrent) || 0,
    max_requests_per_minute: Number(values.max_requests_per_minute) || 0,
    input_cost_per_1m: Number(values.input_cost_per_1m) || 0,
    output_cost_per_1m: Number(values.output_cost_per_1m) || 0,
    routing_tier: values.routing_tier,
    allowed_scan_modes: values.allowed_scan_modes.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean),
    request_overrides: {},
    free: values.free === "true",
    enabled: values.enabled === "true",
  };
  const maxTokens = Number(values.max_tokens) || 0;
  if (maxTokens > 0) payload.request_overrides.max_tokens = maxTokens;
  if (values.api_key.trim()) payload.api_key = values.api_key.trim();
  if (editing) delete payload.name;
  return payload;
}

function applyOpenCodePreset(form, presetId) {
  const preset = OPENCODE_PRESETS.find((item) => item.id === presetId);
  if (!preset) return;
  const set = (name, value) => {
    const field = form.elements[name];
    if (field) field.value = value;
  };
  set("provider", "opencode-go");
  set("model", `opencode-go/${preset.id}`);
  set("api_format", preset.apiFormat);
  set("api_base", preset.apiFormat === "anthropic" ? OPENCODE_MESSAGES_URL : OPENCODE_CHAT_BASE);
  set("is_exact_url", preset.apiFormat === "anthropic" ? "true" : "false");
  set("strip_provider_prefix", "true");
  set("routing_tier", "reserve");
  set("max_concurrent", "1");
  set("max_requests_per_minute", "4");
  set("input_cost_per_1m", String(preset.inputCost));
  set("output_cost_per_1m", String(preset.outputCost));
  set("label", "OpenCode Go");
  if (!form.elements.name?.disabled) set("name", `opencode-${preset.id}`);
}

export function mountModels(context) {
  const { root, setFreshness, setRefreshHandler, setTopbarActions } = context;
  root.innerHTML = skeleton(5);
  let status = null;
  let config = null;
  let logs = null;
  let logsError = null;
  let query = "";
  let poller;

  const render = () => {
    const models = Object.values(status.models || {});
    root.innerHTML = `<div class="page-stack">
      ${renderActivityMetrics(status, logs, logsError)}
      <section class="panel"><header class="panel-header"><div><h2>Provider usage</h2><p>Total tokens and estimated spend grouped by provider</p></div></header><div class="panel-body">${renderProviderUsage(status)}</div></section>
      <section class="panel"><header class="panel-header"><div><h2>Model administration</h2><p>Connectivity, limits, persistent use state, and write-only credentials · ${models.length} configured across ${new Set(models.map((m) => m.provider)).size} providers</p></div><div class="panel-actions model-admin-actions"><select class="model-routing-select" id="routingMode" aria-label="Model routing mode" title="${escapeHtml(status.routing?.description || "")}"><option value="balanced_all" ${status.routing?.mode === "balanced_all" ? "selected" : ""}>All eligible</option><option value="priority" ${status.routing?.mode === "priority" ? "selected" : ""}>Priority only</option></select><input id="modelSearch" type="search" placeholder="Search models" value="${escapeHtml(query)}"><button class="button ghost" id="refreshReasoning" type="button">Sync OpenRouter reasoning</button><button class="button" id="addModel" type="button">Add model</button></div></header><div class="panel-body flush" id="modelsTable">${renderModels(status, config, query)}</div></section>
    </div>`;
    bind();
  };

  const openModelEditor = async (name = "") => {
    if (!name) {
      openDrawer({ title: "Add model", subtitle: "Create a new provider route", body: modelForm() });
      bindDrawer(false);
      return;
    }
    openDrawer({ title: "Edit model", subtitle: name, body: skeleton(3) });
    try {
      const model = await api.model(name);
      document.getElementById("drawerBody").innerHTML = modelForm(model);
      bindDrawer(true, name);
    } catch (error) {
      document.getElementById("drawerBody").innerHTML = errorState(error);
    }
  };

  const bindDrawer = (editing, name = "") => {
    const form = document.getElementById("modelForm");
    form?.querySelector("[data-close-drawer]")?.addEventListener("click", closeDrawer);
    form?.elements.opencode_preset?.addEventListener("change", (event) => applyOpenCodePreset(form, event.target.value));
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector('[type="submit"]');
      button.disabled = true;
      try {
        const payload = formPayload(form, editing);
        if (editing) await api.updateModel(name, payload);
        else await api.addModel(payload);
        toast(`${editing ? name : payload.name} ${editing ? "updated" : "added"}`);
        closeDrawer();
        await poller.run();
      } catch (error) {
        toast(error.message, "error");
        button.disabled = false;
      }
    });
  };

  const handleRowAction = async (button, row) => {
    const name = row.dataset.model;
    const action = button.dataset.action;
    if (action === "edit") return openModelEditor(name);
    if (action === "delete") {
      const accepted = await confirmAction({ title: "Delete model", message: `Delete ${name} from the proxy configuration?`, confirmLabel: "Delete" });
      if (!accepted) return;
      try { await api.deleteModel(name); toast(`${name} deleted`); await poller.run(); } catch (error) { toast(error.message, "error"); }
      return;
    }
    if (action === "test") {
      button.disabled = true;
      button.textContent = "Testing";
      try {
        const result = await api.testModel(name);
        const ok = ["success", "healthy"].includes(result.status);
        toast(ok ? `${name} is reachable${result.latency ? ` (${result.latency}s)` : ""}` : `${name}: ${result.message || result.error || result.status}`, ok ? "success" : "error", 6000);
        await poller.run();
      } catch (error) { toast(error.message, "error"); button.disabled = false; button.textContent = "Test"; }
    }
  };

  const bind = () => {
    root.querySelector("#modelSearch")?.addEventListener("input", debounce((event) => { query = event.target.value; root.querySelector("#modelsTable").innerHTML = renderModels(status, config, query); bindRows(); }, 120));
    root.querySelector("#addModel")?.addEventListener("click", () => openModelEditor());
    root.querySelector("#refreshReasoning")?.addEventListener("click", async (event) => {
      event.currentTarget.disabled = true;
      try {
        const result = await api.refreshModelReasoningCapabilities();
        const count = Object.keys(result.models || {}).length;
        toast(`OpenRouter reasoning metadata synced for ${count} model${count === 1 ? "" : "s"}`);
        await poller.run();
      } catch (error) {
        toast(error.message, "error");
        event.currentTarget.disabled = false;
      }
    });
    root.querySelector("#routingMode")?.addEventListener("change", async (event) => {
      event.target.disabled = true;
      try { await api.setRoutingMode(event.target.value); toast("Routing mode updated"); await poller.run(); } catch (error) { toast(error.message, "error"); event.target.disabled = false; }
    });
    bindRows();
  };

  const bindRows = () => {
    root.querySelectorAll("tr[data-model]").forEach((row) => {
      row.querySelectorAll("button[data-action]").forEach((button) => button.addEventListener("click", () => handleRowAction(button, row)));
      row.querySelector('input[data-action="toggle"]')?.addEventListener("change", async (event) => {
        event.target.disabled = true;
        try { await api.toggleModel(row.dataset.model, event.target.checked); toast(`${row.dataset.model} ${event.target.checked ? "enabled" : "disabled"}`); await poller.run(); } catch (error) { event.target.checked = !event.target.checked; event.target.disabled = false; toast(error.message, "error"); }
      });
    });
  };

  const load = async (signal) => {
    const [nextStatus, nextConfig, nextLogs] = await Promise.all([
      api.status(signal),
      api.config(signal),
      api.logs(signal, { limit: 1000, days: 2, joined: true }).then((value) => ({ value })).catch((error) => ({ error })),
    ]);
    status = nextStatus;
    config = nextConfig;
    if (nextLogs.error) {
      logsError = nextLogs.error;
      logs = logs || { joined: { requests: [] } };
    } else {
      logsError = null;
      logs = nextLogs.value;
    }
    render();
    setFreshness(new Date().toISOString());
  };
  poller = new Poller(15000, load, (error) => {
    if (!status) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  setTopbarActions('<button class="button secondary" id="checkAllModels" type="button">Check all models</button>');
  document.getElementById("checkAllModels")?.addEventListener("click", async (event) => {
    event.currentTarget.disabled = true;
    try { const result = await api.checkModels(); toast(`Health check: ${result.summary.healthy}/${result.summary.total} healthy`, result.summary.unhealthy ? "warning" : "success", 6000); await poller.run(); } catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
  });
  return () => poller.stop();
}
