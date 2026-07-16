import { api } from "../api.js";
import { Poller } from "../poller.js";
import { badge, emptyState, errorState, modelIdentity, openDrawer, skeleton } from "../components.js";
import { debounce, escapeHtml, formatDate, formatDuration, formatNumber, relativeTime } from "../utils.js";

const STALE_PENDING_MS = 10 * 60 * 1000;
const TREND_REFRESH_MS = 60 * 60 * 1000;

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
  const rows = (logs.joined?.requests || []).map((row) => ({ ...row, classified_status: classifyRow(row) }));
  return sortNewest(rows);
}

function requestTime(row) {
  const response = new Date(row.response_timestamp || 0).getTime();
  const request = new Date(row.request_timestamp || 0).getTime();
  return Math.max(Number.isNaN(response) ? 0 : response, Number.isNaN(request) ? 0 : request);
}

function displayTimestamp(row) {
  return requestTime(row) === new Date(row.response_timestamp || 0).getTime()
    ? row.response_timestamp
    : row.request_timestamp || row.response_timestamp;
}

function sortNewest(rows) {
  return [...rows].sort((a, b) => requestTime(b) - requestTime(a));
}

function activeProcesses(requests) {
  const grouped = new Map();
  for (const row of requests) {
    // The process panel is an operational view, not a recent-activity feed.
    // Completed requests belong in the request table below; otherwise a fast
    // serial Chelmon run makes many finished targets look concurrent.
    if (row.classified_status !== "pending_active") continue;
    const key = row.scan_id || `${row.proxy_slot || "auto"}:${row.client_ip || "local"}`;
    const timestamp = new Date(row.response_timestamp || row.request_timestamp || 0).getTime();
    const current = grouped.get(key);
    if (!current || timestamp > current.timestamp) grouped.set(key, { ...row, timestamp, key });
  }
  return [...grouped.values()].sort((a, b) => b.timestamp - a.timestamp);
}

function renderProcesses(requests) {
  const processes = activeProcesses(requests);
  if (!processes.length) return emptyState("No active LLM calls", "Completed calls are available in Request activity.");
  return `<div class="process-list">${processes.slice(0, 12).map((row) => `<button class="process-row" type="button" data-process-scan="${escapeHtml(row.scan_id || "")}"><div class="process-main"><div class="process-title">${escapeHtml(row.scan_target || row.scan_id || row.proxy_slot || row.client_ip || "local")}</div><div class="process-meta">${modelIdentity({ name: row.actual_model || "awaiting model", model: row.actual_model || "", provider: row.provider || row.proxy_slot || "" }, { compact: true, secondary: `${escapeHtml(row.provider || row.proxy_slot || "-")} · PID ${escapeHtml(row.scan_pid || "-")}` })}</div></div>${badge(row.classified_status || "active")}</button>`).join("")}</div>`;
}

function activePipelineJobs(payload) {
  const activeStatuses = new Set(["started", "running", "recovering", "network_backoff", "awaiting_model"]);
  return (payload?.jobs || [])
    .filter((job) => job.process_alive && activeStatuses.has(String(job.status || "").toLowerCase()))
    .sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime());
}

function renderPipelineActivity(payload) {
  const jobs = activePipelineJobs(payload);
  if (!jobs.length) return emptyState("No active scan pipelines");
  return `<div class="process-list">${jobs.slice(0, 8).map((job) => {
    const preflight = job.pipeline?.preflight || {};
    const preflightProgress = job.preflight_progress || job.pipeline?.preflight_progress || preflight.progress || {};
    const inPreflight = String(preflight.status || "").toLowerCase() === "running";
    const percent = Math.max(0, Math.min(100, Number(preflightProgress.progress_percent || 0)));
    const checked = Number(preflightProgress.checked_targets || 0);
    const total = Number(preflightProgress.total_targets || job.target_count || 0);
    const label = inPreflight ? `preflight ${percent.toFixed(1)}%` : (job.recovery_state || job.status || "running");
    const egress = preflight.container_egress;
    const detail = inPreflight
      ? `${formatNumber(checked)} / ${formatNumber(total)} checked · ${formatNumber(preflightProgress.alive_targets || 0)} alive · ${formatNumber(preflightProgress.dead_targets || 0)} dead · ${formatNumber(preflightProgress.inconclusive_targets || 0)} inconclusive · ${formatNumber(preflightProgress.blocked_targets || 0)} blocked · ${Number(preflightProgress.rate_per_second || 0).toFixed(1)}/s${egress ? ` · egress ${egress.ok ? "ready" : "failed"}` : ""}${preflightProgress.updated_at ? ` · snapshot ${relativeTime(preflightProgress.updated_at)}` : ""}`
      : `${formatNumber(job.target_count || 0)} targets · worker ${job.worker_status || "active"}`;
    return `<div class="process-row"><div class="process-main"><div class="process-title">${escapeHtml(job.label || job.name || job.job_name || job.job_id || "Scan pipeline")}</div><div class="process-meta">${escapeHtml(job.engine || "strix")} · ${escapeHtml(job.scan_mode || "standard")} · ${escapeHtml(detail)}</div></div>${badge(label)}</div>`;
  }).join("")}</div>`;
}

function renderStalePanel(requests) {
  const rows = requests.filter((row) => row.classified_status === "stale_no_response" || row.classified_status === "orphan_request");
  if (!rows.length) return emptyState("No stale or orphan requests");

  const grouped = new Map();
  for (const row of rows) {
    const key = [
      row.classified_status,
      row.scan_id || row.request_id || "no-scan",
      row.scan_target || "",
      row.actual_model || "",
      row.provider || row.proxy_slot || "",
    ].join("|");
    const current = grouped.get(key);
    if (!current) {
      grouped.set(key, { ...row, count: 1, newest_time: requestTime(row) });
    } else {
      current.count += 1;
      if (requestTime(row) > current.newest_time) {
        current.newest_time = requestTime(row);
        current.request_timestamp = row.request_timestamp;
        current.response_timestamp = row.response_timestamp;
      }
    }
  }

  const renderRow = (row) => `<div class="stale-request-row"><time>${formatDate(displayTimestamp(row))}</time><div class="stale-request-content"><div class="stale-request-heading">${badge(row.classified_status)}<strong>${escapeHtml(row.scan_target || row.scan_id || row.request_id || "-")}</strong>${row.count > 1 ? `<span class="count-pill">x${row.count}</span>` : ""}</div><div class="stale-request-meta">${escapeHtml(row.actual_model || "-")} · ${escapeHtml(row.provider || row.proxy_slot || "-")} · ${escapeHtml(row.scan_id || "no scan_id")}</div></div></div>`;
  return `<div class="event-list">${[...grouped.values()].sort((a, b) => b.newest_time - a.newest_time).slice(0, 14).map(renderRow).join("")}</div>`;
}

function renderLogRows(requests, filters, page) {
  const query = filters.query.toLowerCase();
  const filtered = sortNewest(requests.filter((row) => {
    if (filters.status) {
      if (filters.status === row.classified_status) return true;
      if (filters.status === "pending" && (row.classified_status === "pending_active" || row.classified_status === "stale_no_response" || row.classified_status === "orphan_request")) return true;
      return filters.status === row.status;
    }
    if (filters.model && !`${row.actual_model} ${row.provider}`.toLowerCase().includes(filters.model.toLowerCase())) return false;
    if (filters.scan && !`${row.scan_id} ${row.scan_target}`.toLowerCase().includes(filters.scan.toLowerCase())) return false;
    return !query || `${row.request_id} ${row.actual_model} ${row.error}`.toLowerCase().includes(query);
  }));
  const pageSize = 25;
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, pages);
  const rows = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);
  const scanExecution = (row) => [row.scan_engine, row.scan_mode, row.workflow_mode].filter(Boolean).join(" · ") || "-";
  const reasoningLabel = (row) => row.reasoning_enabled
    ? `Thinking ${row.reasoning_effort || "high"}`
    : "";
  const inputTokens = (row) => {
    const usage = row.usage || {};
    const input = usage.prompt_tokens ?? usage.input_tokens;
    const cached = usage.cached_input_tokens;
    if (input == null) return "-";
    return `${formatNumber(input || 0)}${cached == null ? "" : `<div class="cell-secondary">Cache hit ${formatNumber(cached)}</div>`}`;
  };
  const outputTokens = (row) => {
    const usage = row.usage || {};
    const output = usage.completion_tokens ?? usage.output_tokens;
    return output == null ? "-" : formatNumber(output || 0);
  };
  const requestCost = (row) => {
    const usage = row.usage || {};
    if (usage.estimated_cost_cny != null) {
      const period = usage.pricing_period === "peak" ? "BJT peak" : "BJT off-peak";
      return `<div>¥${Number(usage.estimated_cost_cny).toFixed(4)}</div><div class="cell-secondary">${period}</div>`;
    }
    if (usage.cost != null) return `$${Number(usage.cost || 0).toFixed(4)}`;
    return "-";
  };
  const fallbackOutcome = (row) => {
    const switches = row.model_switches || [];
    const latest = switches[switches.length - 1];
    if (["success", "partial"].includes(row.status) && latest) {
      const destination = latest.to_model || row.actual_model || "fallback model";
      return `${badge("Recovered", "success")}<div class="cell-secondary break-anywhere">via ${escapeHtml(destination)} after ${escapeHtml(latest.reason || "provider retry")}</div>`;
    }
    if (row.error) return `<span class="break-anywhere">${escapeHtml(String(row.error).slice(0, 120))}</span>`;
    if (latest) return `<span class="break-anywhere">${escapeHtml(`Fallback: ${latest.reason || "provider retry"}`.slice(0, 120))}</span>`;
    return "-";
  };
  const table = rows.length ? `<div class="table-scroll"><table class="data-table"><thead><tr><th>Time</th><th>scan_id / target</th><th>Model / provider</th><th>Engine / mode</th><th>Status</th><th>Duration</th><th>Input</th><th>Output</th><th>Total Cost</th><th>Switches</th><th>Outcome / fallback</th></tr></thead><tbody>${rows.map((row) => `
    <tr><td>${formatDate(displayTimestamp(row), { seconds: true })}</td><td><button class="button ghost small" type="button" data-log-scan="${escapeHtml(row.scan_id || "")}">${escapeHtml(row.scan_target || row.scan_id || "-")}</button><div class="cell-secondary mono">${escapeHtml(row.scan_id || row.request_id || "-")}</div></td>
    <td>${modelIdentity({ name: row.actual_model || "-", model: row.actual_model || "", provider: row.provider || row.proxy_slot || "" }, { compact: true, secondary: escapeHtml([row.provider || row.proxy_slot || "-", reasoningLabel(row)].filter(Boolean).join(" · ")) })}</td><td><span class="cell-secondary">${escapeHtml(scanExecution(row))}</span></td><td>${badge(row.classified_status || row.status || "pending")}</td><td>${row.duration_seconds == null ? "-" : formatDuration(row.duration_seconds)}</td><td>${inputTokens(row)}</td><td>${outputTokens(row)}</td><td>${requestCost(row)}</td><td>${row.model_switches?.length || 0}</td><td>${fallbackOutcome(row)}</td></tr>`).join("")}</tbody></table></div>` : emptyState("No matching requests");
  return { html: `${table}<div class="toolbar" style="justify-content:flex-end;margin-top:12px"><button class="button secondary small" id="prevLogPage" ${safePage <= 1 ? "disabled" : ""}>Previous</button><span class="muted">Page ${safePage} of ${pages} · ${filtered.length} requests</span><button class="button secondary small" id="nextLogPage" ${safePage >= pages ? "disabled" : ""}>Next</button></div>`, pages, safePage };
}

function drawTrend(trend, existing, groupBy = "provider") {
  existing?.destroy();
  if (!window.Chart || !trend?.labels?.length) return null;
  const canvas = document.getElementById("activityTrendChart");
  if (!canvas) return null;
  const colors = ["#2563eb", "#067647", "#b54708", "#7f56d9", "#0e7090", "#c11574"];
  const billing = trend.billing || {};
  const billingView = groupBy === "billing";
  const datasets = billingView
    ? [
      { label: "Input", data: billing.input_tokens || [], borderColor: "#2563eb", backgroundColor: "transparent", borderWidth: 2, pointRadius: 2, tension: .25, yAxisID: "tokens" },
      { label: "Output", data: billing.output_tokens || [], borderColor: "#16a34a", backgroundColor: "transparent", borderWidth: 2, pointRadius: 2, tension: .25, yAxisID: "tokens" },
      { label: "Cache hit", data: billing.cached_input_tokens || [], borderColor: "#8b5cf6", backgroundColor: "rgba(139,92,246,.08)", borderWidth: 2, pointRadius: 2, tension: .25, yAxisID: "tokens", fill: true },
      { label: "Cost (USD)", data: billing.cost_usd || [], borderColor: "#f79009", backgroundColor: "transparent", borderWidth: 2, borderDash: [4, 3], pointRadius: 2, tension: .25, yAxisID: "costUsd" },
      { label: "Cost (CNY)", data: billing.cost_cny || [], borderColor: "#f04438", backgroundColor: "transparent", borderWidth: 2, borderDash: [6, 4], pointRadius: 2, tension: .25, yAxisID: "costCny" },
    ]
    : (trend.datasets || []).map((dataset, index) => ({ label: dataset.model, data: dataset.tokens, borderColor: colors[index % colors.length], backgroundColor: "transparent", borderWidth: 2, pointRadius: 2, tension: .25 }));
  return new window.Chart(canvas, {
    type: "line",
    data: { labels: trend.labels, datasets },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, usePointStyle: true } }, tooltip: { callbacks: { afterLabel: (context) => {
      const members = context.dataset.models || [];
      if (!members.length || members.length === 1) return "";
      const shown = members.slice(0, 6).join(", ");
      return `Models: ${shown}${members.length > 6 ? ` +${members.length - 6} more` : ""}`;
    } } } }, scales: billingView ? {
      x: { grid: { display: false } },
      tokens: { position: "left", beginAtZero: true, ticks: { callback: (value) => formatNumber(value, 0) } },
      costUsd: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, ticks: { callback: (value) => `$${Number(value).toFixed(2)}` } },
      costCny: { position: "right", display: false, beginAtZero: true, grid: { drawOnChartArea: false } },
    } : { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { callback: (value) => formatNumber(value, 0) } } } },
  });
}

function processDetail(scanId, requests) {
  const rows = sortNewest(requests.filter((row) => row.scan_id === scanId));
  openDrawer({ title: "LLM process", subtitle: scanId || "Legacy process", body: rows.length ? `<div class="page-stack"><div class="compact-grid"><div class="metric-card"><div class="metric-label">Requests</div><div class="metric-value">${rows.length}</div></div><div class="metric-card"><div class="metric-label">Tokens</div><div class="metric-value">${formatNumber(rows.reduce((sum, row) => sum + (row.usage?.total_tokens || 0), 0))}</div></div><div class="metric-card"><div class="metric-label">Failures</div><div class="metric-value">${rows.filter((row) => ["failed", "error"].includes(row.status)).length}</div></div></div><div class="event-list">${rows.map((row) => `<div class="event-row"><span>${formatDate(displayTimestamp(row))}</span><span>${badge(row.status || "pending")}</span><span>${modelIdentity({ name: row.actual_model || "-", model: row.actual_model || "", provider: row.provider || "" }, { compact: true, secondary: `${formatNumber(row.usage?.total_tokens || 0)} tokens · ${row.duration_seconds == null ? "pending" : formatDuration(row.duration_seconds)}` })}</span></div>`).join("")}</div></div>` : emptyState("No requests found") });
}

export function mountActivity(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(6);
  let logs = null;
  let scanJobs = null;
  let trend = null;
  let chart = null;
  let trendLoadedAt = 0;
  let page = 1;
  let trendGranularity = "4h";
  let trendGroupBy = "billing";
  const filters = { query: "", status: "", model: "", scan: "" };

  const renderTable = () => {
    const target = root.querySelector("#activityLogTable");
    if (!target) return;
    const result = renderLogRows(joinedRequests(logs), filters, page);
    page = result.safePage;
    target.innerHTML = result.html;
    bindTable();
  };

  const bindTable = () => {
    root.querySelector("#prevLogPage")?.addEventListener("click", () => { page -= 1; renderTable(); });
    root.querySelector("#nextLogPage")?.addEventListener("click", () => { page += 1; renderTable(); });
    root.querySelectorAll("[data-log-scan], [data-process-scan]").forEach((button) => button.addEventListener("click", () => processDetail(button.dataset.logScan ?? button.dataset.processScan, joinedRequests(logs))));
  };

  const render = ({ redrawTrend = false } = {}) => {
    const preservedTrendPanel = !redrawTrend ? root.querySelector("#usageTrendPanel") : null;
    const requests = joinedRequests(logs);
    const renderedRows = renderLogRows(requests, filters, page);
    root.innerHTML = `<div class="page-stack">
      <section class="panel"><header class="panel-header"><div><h2>Scan pipeline activity</h2><p>Preflight, worker, and scheduling activity before LLM requests begin</p></div></header><div class="panel-body">${renderPipelineActivity(scanJobs)}</div></section>
      <div class="equal-grid activity-summary-grid"><section class="panel"><header class="panel-header"><div><h2>Active LLM calls</h2><p>Only requests currently awaiting a provider response, grouped by scan_id</p></div></header><div class="panel-body">${renderProcesses(requests)}</div></section><section class="panel"><header class="panel-header"><div><h2>Stale / orphan requests</h2><p>Requests with no response after ${Math.round(STALE_PENDING_MS / 60000)} min, or missing scan context</p></div></header><div class="panel-body">${renderStalePanel(requests)}</div></section></div>
      <section class="panel" id="usageTrendPanel"><header class="panel-header"><div><h2>Usage trend</h2><p>${trendGroupBy === "billing" ? "Input, output, cache hit, and request cost · refreshed hourly" : "Token activity by provider or model · refreshed hourly"}</p></div><div class="panel-actions compact-controls"><select id="trendGranularity" aria-label="Trend range"><option value="4h" ${trendGranularity === "4h" ? "selected" : ""}>Hourly</option><option value="day" ${trendGranularity === "day" ? "selected" : ""}>30d</option></select><select id="trendGroupBy" aria-label="Trend grouping"><option value="billing" ${trendGroupBy === "billing" ? "selected" : ""}>Billing</option><option value="provider" ${trendGroupBy === "provider" ? "selected" : ""}>Provider</option><option value="model" ${trendGroupBy === "model" ? "selected" : ""}>Model</option></select></div></header><div class="panel-body"><div class="chart-wrap">${window.Chart ? '<canvas id="activityTrendChart"></canvas>' : emptyState("Chart library unavailable")}</div></div></section>
      <section class="panel"><header class="panel-header"><div><h2>Request activity</h2><p>Joined request, response, and model-switch records, newest first</p></div><div class="panel-actions"><input id="activitySearch" type="search" placeholder="Request or error" value="${escapeHtml(filters.query)}"><input id="activityScan" type="search" placeholder="scan_id or target" value="${escapeHtml(filters.scan)}"><input id="activityModel" type="search" placeholder="Model or provider" value="${escapeHtml(filters.model)}"><select id="activityStatus"><option value="">All statuses</option>${["pending_active","stale_no_response","orphan_request","success","partial","failed","cancelled","interrupted","error"].map((value) => `<option value="${value}" ${filters.status === value ? "selected" : ""}>${value}</option>`).join("")}</select></div></header><div class="panel-body" id="activityLogTable">${renderedRows.html}</div></section>
    </div>`;
    if (preservedTrendPanel) {
      root.querySelector("#usageTrendPanel")?.replaceWith(preservedTrendPanel);
    } else {
      chart = drawTrend(trend, chart, trendGroupBy);
    }
    bind();
  };

  const bind = () => {
    const filterInput = (selector, key) => root.querySelector(selector)?.addEventListener("input", debounce((event) => { filters[key] = event.target.value; page = 1; renderTable(); }, 120));
    filterInput("#activitySearch", "query"); filterInput("#activityScan", "scan"); filterInput("#activityModel", "model");
    root.querySelector("#activityStatus")?.addEventListener("change", (event) => { filters.status = event.target.value; page = 1; renderTable(); });
    root.querySelector("#trendGranularity")?.addEventListener("change", async (event) => {
      trendGranularity = event.target.value;
      trendLoadedAt = 0;
      trend = await api.trend(null, trendGranularity, "", trendGroupBy);
      trendLoadedAt = Date.now();
      render({ redrawTrend: true });
    });
    root.querySelector("#trendGroupBy")?.addEventListener("change", async (event) => {
      trendGroupBy = event.target.value;
      trendLoadedAt = 0;
      trend = await api.trend(null, trendGranularity, "", trendGroupBy);
      trendLoadedAt = Date.now();
      render({ redrawTrend: true });
    });
    bindTable();
  };

  const load = async (signal) => {
    const shouldRefreshTrend = !trend || Date.now() - trendLoadedAt >= TREND_REFRESH_MS;
    const [nextLogs, nextTrend, nextScanJobs] = await Promise.all([
      api.logs(signal, { limit: 1000, days: 2, joined: true }),
      shouldRefreshTrend ? api.trend(signal, trendGranularity, "", trendGroupBy) : Promise.resolve(null),
      api.smartBatchJobs(signal, 20).catch(() => scanJobs),
    ]);
    logs = nextLogs;
    scanJobs = nextScanJobs;
    if (nextTrend) {
      trend = nextTrend;
      trendLoadedAt = Date.now();
    }
    render({ redrawTrend: shouldRefreshTrend });
    setFreshness(new Date().toISOString());
  };
  const poller = new Poller(5000, load, (error) => {
    if (!logs) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  return () => { poller.stop(); chart?.destroy(); };
}
