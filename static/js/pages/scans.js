import { api } from "../api.js?v=20260702-batch-controls";
import { Poller } from "../poller.js";
import { badge, confirmAction, emptyState, errorState, modelIdentity, openDrawer, panel, progress, skeleton, toast } from "../components.js";
import { debounce, escapeHtml, formatBytes, formatDate, formatDuration, formatNumber, formatRate } from "../utils.js";

const ACTIVE_STATUS = new Set(["running", "retrying"]);
const DONE_STATUS = new Set(["success", "failed", "timeout"]);

function allTasks(data) {
  return (data.batches || []).flatMap((batch) => (batch.tasks || []).map((task) => ({ ...task, batch_id: batch.batch_id })));
}

function isRetryPending(task) {
  return task.is_retry_pending === true || (task.status === "pending" && Number(task.retry_count || 0) > 0);
}

function isAutoRequeuePending(task) {
  return task.is_auto_requeue_pending === true
    || (task.status === "pending" && Number(task.auto_requeue_count || 0) > 0 && Boolean(task.auto_requeue_at || task.next_retry_at));
}

function isQueuedPending(task) {
  return task.status === "pending" && !isRetryPending(task) && !isAutoRequeuePending(task);
}

function isDueAt(value) {
  if (!value) return false;
  const timestamp = new Date(value).getTime();
  return Boolean(timestamp) && timestamp <= Date.now();
}

function isRetryDue(task) {
  return task.status === "pending" && Boolean(task.next_retry_at) && isDueAt(task.next_retry_at);
}

function isActiveTask(task) {
  return ACTIVE_STATUS.has(task.status);
}

function taskStatus(task) {
  if (isAutoRequeuePending(task)) return "auto-requeue";
  return isRetryPending(task) ? "retry-pending" : task.status || "unknown";
}

function batchCounts(batch) {
  const summary = batch.summary || {};
  const tasks = batch.tasks || [];
  const count = (status) => summary[status] ?? tasks.filter((task) => task.status === status).length;
  return {
    total: summary.total_tasks ?? tasks.length,
    completed: summary.completed_tasks ?? tasks.filter((task) => DONE_STATUS.has(task.status)).length,
    pending: summary.pending ?? tasks.filter(isQueuedPending).length,
    running: summary.running ?? tasks.filter((task) => task.status === "running").length,
    retrying: summary.retrying ?? tasks.filter((task) => task.status === "retrying").length,
    retryPending: summary.retry_pending ?? tasks.filter(isRetryPending).length,
    autoRequeuePending: summary.auto_requeue_pending ?? tasks.filter(isAutoRequeuePending).length,
    autoRequeueAttempts: summary.auto_requeue_attempts_total ?? tasks.reduce((sum, task) => sum + Number(task.auto_requeue_count || 0), 0),
    success: summary.success ?? count("success"),
    failed: summary.failed ?? count("failed"),
    timeout: summary.timeout ?? count("timeout"),
    progress: summary.progress_percent ?? 0,
  };
}

function batchLifecycle(batch) {
  if (batch.lifecycle === "finished") return "history";
  if (batch.lifecycle === "active" || batch.status === "running" || batch.has_live_running_tasks) return "current";
  if (batch.lifecycle === "stale") return "current";
  if (["initialized", "planning"].includes(batch.status)) return "current";
  return "history";
}

function statusPills(counts) {
  return `<div class="scan-count-pills">
    <span class="scan-pill ok">Done ${counts.success}</span>
    <span class="scan-pill bad">Failed ${counts.failed + counts.timeout}</span>
    <span class="scan-pill run">Running ${counts.running + counts.retrying}</span>
    <span class="scan-pill wait">Queued ${counts.pending + counts.retryPending + counts.autoRequeuePending}</span>
  </div>`;
}

function batchHealth(counts) {
  if (counts.running + counts.retrying > 0) return { label: "running", tone: "success" };
  if (counts.failed + counts.timeout > 0) return { label: "needs review", tone: "warning" };
  if (counts.pending + counts.retryPending + counts.autoRequeuePending > 0) return { label: "queued", tone: "info" };
  if (counts.total && counts.completed >= counts.total) return { label: "complete", tone: "success" };
  return { label: "idle", tone: "info" };
}

function batchPreparationStage(batch) {
  const status = String(batch.status || "").toLowerCase();
  const counts = batchCounts(batch);
  const input = batch.input_source || {};
  const stage = String(input.preflight_stage || "").toLowerCase();
  const detail = String(input.preflight_detail || "").trim();
  if (["initialized", "planning"].includes(status) && counts.total === 0) {
    return {
      label: "preflight",
      tone: "info",
      detail: detail || (stage === "liveness_probe" ? "Running multi-proxy liveness probe" : "Validating DNS and restricted networks"),
    };
  }
  return null;
}

function compactTargetName(value = "") {
  const target = String(value || "");
  return target.length > 42 ? `${target.slice(0, 20)}…${target.slice(-18)}` : target;
}

function batchRow(batch, selectedId, { compact = false } = {}) {
  const counts = batchCounts(batch);
  const activeTarget = (batch.tasks || []).find(isActiveTask)?.target || "";
  const selected = batch.batch_id === selectedId ? "selected" : "";
  const waiting = counts.pending + counts.retryPending + counts.autoRequeuePending;
  const failed = counts.failed + counts.timeout;
  const preparation = batchPreparationStage(batch);
  const health = preparation || batchHealth(counts);
  const paused = batch.paused === true || batch.status === "paused";
  const addedAt = batch.submitted_at || batch.started_at || batch.created_at;
  return `<div class="batch-control-row"><button class="batch-summary-row ${selected} ${compact ? "compact" : ""}" type="button" data-batch-id="${escapeHtml(batch.batch_id)}">
    <div class="batch-summary-main">
      <div class="batch-summary-title"><strong>${escapeHtml(batch.label || "Scan Batch")}</strong> <span class="muted mono text-sm">${escapeHtml(batch.batch_id)}</span>${badge(health.label, health.tone)}${compact ? "" : badge(batch.monitor_state || batch.lifecycle || batch.status || "unknown")}</div>
      <div class="batch-summary-meta">${escapeHtml(batch.scan_mode || "-")} · ${preparation ? escapeHtml(preparation.detail) : `${counts.total} tasks`} · added ${formatDate(addedAt)}${activeTarget ? ` · active ${escapeHtml(compactTargetName(activeTarget))}` : ""}</div>
    </div>
    <div class="batch-summary-progress">
      <div class="progress-line"><strong>${formatNumber(counts.progress, 1)}%</strong>${progress(counts.progress)}</div>
      <div class="batch-health-strip">
        <span class="health-item ok"><strong>${counts.success}</strong> done</span>
        <span class="health-item bad"><strong>${failed}</strong> failed</span>
        <span class="health-item run"><strong>${counts.running + counts.retrying}</strong> running</span>
        <span class="health-item wait"><strong>${waiting}</strong> waiting</span>
      </div>
    </div>
  </button><div class="batch-row-actions"><button class="button secondary small" type="button" data-batch-pause="${escapeHtml(batch.batch_id)}" data-paused="${paused}">${paused ? "Resume" : "Pause"}</button><button class="button secondary small text-danger" type="button" data-batch-terminate="${escapeHtml(batch.batch_id)}">Terminate</button><button class="button ghost small text-danger" type="button" data-batch-delete="${escapeHtml(batch.batch_id)}">Delete</button></div></div>`;
}

function renderBatchList(batches, selectedId, mode) {
  if (!batches.length) {
    const title = mode === "current" ? "No current batches" : "No historical batches";
    return emptyState(title, "Smart Batch snapshots will appear here as soon as scans are planned.");
  }
  return `<div class="batch-summary-list">${batches.map((batch) => batchRow(batch, selectedId, { compact: mode === "current" })).join("")}</div>`;
}

function aggregateCounts(batches) {
  return batches.reduce((acc, batch) => {
    const counts = batchCounts(batch);
    acc.total += counts.total;
    acc.completed += counts.completed;
    acc.pending += counts.pending;
    acc.running += counts.running + counts.retrying;
    acc.retryPending += counts.retryPending;
    acc.autoRequeuePending += counts.autoRequeuePending;
    acc.autoRequeueAttempts += counts.autoRequeueAttempts;
    acc.success += counts.success;
    acc.failed += counts.failed;
    acc.timeout += counts.timeout;
    return acc;
  }, { total: 0, completed: 0, pending: 0, running: 0, retryPending: 0, autoRequeuePending: 0, autoRequeueAttempts: 0, success: 0, failed: 0, timeout: 0 });
}

function renderSubmitForm(draft) {
  return `<form id="scanSubmitForm" class="scan-submit-form">
    <label class="field wide"><span>Targets</span><textarea id="scanTargets" rows="8" placeholder="One target per line, for example:&#10;example.gov&#10;https://portal.example.gov">${escapeHtml(draft.targets)}</textarea></label>
    <div class="scan-form-grid">
      <label class="field"><span>Label</span><input id="scanLabel" placeholder="optional batch label" value="${escapeHtml(draft.label)}"></label>
      <label class="field"><span>Mode</span><select id="scanMode">${["redteam","deep","standard","quick","getshell"].map((mode) => `<option value="${mode}" ${draft.mode === mode ? "selected" : ""}>${mode}</option>`).join("")}</select></label>
      <label class="field"><span>Parallel</span><input id="scanParallel" type="number" min="1" max="4" value="${escapeHtml(draft.parallel)}"></label>
      <label class="field"><span>Timeout</span><input id="scanTimeout" type="number" min="0" max="14400" step="300" value="${escapeHtml(draft.timeout)}"><small class="field-help">0 disables the per-target deadline.</small></label>
    </div>
    <div class="scan-options-row">
      <label><input id="scanSingleTargets" type="checkbox" ${draft.single_targets ? "checked" : ""}> One scan per target</label>
      <label><input id="scanUseSocks5" type="checkbox" ${draft.use_socks5 ? "checked" : ""}> Use egress proxy</label>
      <label><input id="scanProbeLive" type="checkbox" ${draft.probe_live_before_queue ? "checked" : ""}> Probe live targets before queue</label>
      <label><input id="scanSkipDnsGuard" type="checkbox" ${draft.skip_dns_guard ? "checked" : ""}> Trusted list (skip DNS-resolve guard)</label>
      <label><input id="scanMonitor" type="checkbox" ${draft.monitor ? "checked" : ""}> Resource monitor</label>
      <label><input id="scanSkipScanned" type="checkbox" ${draft.skip_scanned ? "checked" : ""}> Skip scanned</label>
      <label><input id="scanDryRun" type="checkbox" ${draft.dry_run ? "checked" : ""}> Dry run only</label>
      <label class="danger-option"><input id="scanAllowPrivateTargets" type="checkbox" ${draft.allow_private_targets ? "checked" : ""}> Allow private/local targets</label>
    </div>
    <div class="scan-submit-footer">
      <div class="muted" id="scanSubmitPreview">Paste targets to preview the batch.</div>
      <div class="panel-actions"><button class="button secondary" type="button" id="scanPreviewButton">Preview</button><button class="button" type="submit">Start batch</button></div>
    </div>
  </form>`;
}

function formPayload(root) {
  return {
    targets: root.querySelector("#scanTargets")?.value || "",
    label: root.querySelector("#scanLabel")?.value || "",
    mode: root.querySelector("#scanMode")?.value || "redteam",
    parallel: Number(root.querySelector("#scanParallel")?.value || 4),
    timeout: Number(root.querySelector("#scanTimeout")?.value || 0),
    single_targets: root.querySelector("#scanSingleTargets")?.checked !== false,
    use_socks5: root.querySelector("#scanUseSocks5")?.checked !== false,
    monitor: root.querySelector("#scanMonitor")?.checked !== false,
    skip_scanned: root.querySelector("#scanSkipScanned")?.checked === true,
    dry_run: root.querySelector("#scanDryRun")?.checked === true,
    allow_private_targets: root.querySelector("#scanAllowPrivateTargets")?.checked === true,
    probe_live_before_queue: root.querySelector("#scanProbeLive")?.checked !== false,
    skip_dns_guard: root.querySelector("#scanSkipDnsGuard")?.checked !== false,
    probe_concurrency: 40,
    probe_proxy_quorum: 2,
    probe_max_proxy_nodes: 3,
    probe_keep_inconclusive: true,
  };
}

function restrictedTargetsPreview(items) {
  if (!items?.length) return "";
  const rows = items.slice(0, 10).map((item) => `${item.target} (${item.reason || "restricted"}${item.host ? `: ${item.host}` : ""})`);
  const more = items.length > 10 ? `; +${items.length - 10} more` : "";
  return ` Restricted targets blocked: ${rows.join("; ")}${more}`;
}

function renderTaskList(tasks, { limit = 10, emptyTitle = "No tasks", emptyDetail = "", compact = false } = {}) {
  if (!tasks.length) return emptyState(emptyTitle, emptyDetail);
  return `<div class="scan-task-list">${tasks.slice(0, limit).map((task) => {
    const scanId = task.scan_id || task.last_attempt_scan_id || "";
    const autoRequeueText = Number(task.auto_requeue_count || 0) > 0
      ? `<div class="auto-requeue-note">auto requeue ${formatNumber(task.auto_requeue_count || 0)}/${formatNumber(task.max_auto_requeues || 3)} · ${escapeHtml(task.auto_requeue_reason || task.retry_reason || "transient")} ${task.auto_requeue_at || task.next_retry_at ? `· next ${formatDate(task.auto_requeue_at || task.next_retry_at)}` : ""}</div>`
      : "";
    const retryText = task.next_retry_at && !autoRequeueText
      ? `<div class="auto-requeue-note">retry ${formatNumber(task.retry_count || 0)}/${formatNumber(task.max_retries || 0)} · ${escapeHtml(task.retry_reason || "pending")} · next ${formatDate(task.next_retry_at)}</div>`
      : "";
    if (compact) {
      const model = task.llm_model_primary || "awaiting model";
      const duration = task.duration_seconds == null ? "waiting" : formatDuration(task.duration_seconds);
      const tokens = Number(task.llm_usage?.total_tokens || 0);
      return `<div class="scan-task-row compact">
        <div class="scan-task-main">
          <div class="scan-task-title"><strong>${escapeHtml(task.target || "-")}</strong>${badge(taskStatus(task))}</div>
          ${autoRequeueText || retryText}
        </div>
        <div class="scan-task-compact-meta"><span>${escapeHtml(duration)}</span><span>${escapeHtml(model)}</span>${tokens ? `<span>${formatNumber(tokens)} tokens</span>` : ""}</div>
        <button class="button ghost small" type="button" ${scanId ? "" : "disabled"} data-scan-id="${escapeHtml(scanId)}" data-target="${escapeHtml(task.target || "")}">Inspect</button>
      </div>`;
    }
    return `<div class="scan-task-row">
      <div class="scan-task-main">
        <div class="scan-task-title"><strong>${escapeHtml(task.target || "-")}</strong>${badge(taskStatus(task))}</div>
        <div class="cell-secondary">${task.duration_seconds == null ? "Waiting to start" : formatDuration(task.duration_seconds)}${task.vulnerabilities_count ? ` · ${formatNumber(task.vulnerabilities_count)} findings` : ""}</div>
        ${autoRequeueText || retryText}
      </div>
      <div class="scan-task-side">
        <div>${modelIdentity({ name: task.llm_model_primary || "awaiting model", provider: task.llm_model_provider || "" }, { compact: true, secondary: `${formatNumber(task.llm_usage?.total_tokens || 0)} tokens` })}</div>
        <button class="button ghost small" type="button" ${scanId ? "" : "disabled"} data-scan-id="${escapeHtml(scanId)}" data-target="${escapeHtml(task.target || "")}">Inspect</button>
      </div>
    </div>`;
  }).join("")}</div>`;
}

function renderSelectedBatch(batch, filters) {
  if (!batch) return emptyState("No batch selected");
  const tasks = batch.tasks || [];
  const query = filters.query.toLowerCase();
  const filtered = tasks.filter((task) => {
    if (filters.status === "retry_pending" && !isRetryPending(task)) return false;
    if (filters.status === "auto_requeue" && !isAutoRequeuePending(task)) return false;
    if (filters.status && !["retry_pending", "auto_requeue"].includes(filters.status) && task.status !== filters.status) return false;
    return !query || `${task.target} ${task.scan_id} ${task.last_error} ${task.llm_model_primary}`.toLowerCase().includes(query);
  });
  const grouped = {
    running: filtered.filter(isActiveTask),
    pending: filtered.filter(isQueuedPending),
    retry: filtered.filter(isRetryPending),
    autoRequeue: filtered.filter(isAutoRequeuePending),
    success: filtered.filter((task) => task.status === "success"),
    failed: filtered.filter((task) => ["failed", "timeout"].includes(task.status)),
  };
  const counts = batchCounts(batch);
  const requestedParallel = Number(batch.parallel || 1);
  const effectiveParallel = Number(batch.effective_parallel || requestedParallel);
  const proxyLimit = Number(batch.proxy_capacity?.recommended_parallel || 0);
  const runningParallel = counts.running + counts.retrying;
  return `<div class="selected-batch">
    <div class="selected-batch-head">
      <div><h2>${escapeHtml(batch.batch_id)}</h2><p>${escapeHtml(batch.scan_mode || "-")} · ${counts.completed}/${counts.total} complete · updated ${formatDate(batch.updated_at)}</p></div>
      <div class="selected-batch-progress"><strong>${formatNumber(counts.progress, 1)}%</strong>${progress(counts.progress)}${statusPills(counts)}</div>
    </div>
    <form class="batch-parallel-control" data-batch-parallel-form="${escapeHtml(batch.batch_id)}">
      <label>Parallel <input name="parallel" type="number" min="1" max="32" value="${escapeHtml(requestedParallel)}"></label>
      <button class="button secondary small" type="submit">Apply</button>
      <span class="muted">requested ${escapeHtml(requestedParallel)} · effective ${escapeHtml(effectiveParallel)} · running ${escapeHtml(runningParallel)}${proxyLimit ? ` · model limit ${escapeHtml(proxyLimit)}` : ""}</span>
    </form>
    <div class="batch-filter-row"><select id="taskStatusFilter"><option value="">All statuses</option>${["pending","retry_pending","auto_requeue","running","retrying","success","failed","timeout"].map((value) => `<option value="${value}" ${filters.status === value ? "selected" : ""}>${value}</option>`).join("")}</select><input id="taskSearch" type="search" placeholder="Search selected batch" value="${escapeHtml(filters.query)}"></div>
    <div class="task-group-grid">
      ${panel("Running", `${grouped.running.length} active`, renderTaskList(grouped.running, { limit: 8, emptyTitle: "No running tasks" }))}
      ${panel("Pending", `${grouped.pending.length} queued`, renderTaskList(grouped.pending, { limit: 8, emptyTitle: "No queued tasks" }))}
      ${panel("Succeeded", `${grouped.success.length} complete`, renderTaskList(grouped.success, { limit: 8, emptyTitle: "No successes yet" }))}
      ${panel("Failed / retry", `${grouped.failed.length + grouped.retry.length + grouped.autoRequeue.length} need attention`, renderTaskList([...grouped.autoRequeue, ...grouped.retry, ...grouped.failed], { limit: 10, emptyTitle: "No failures or retries" }))}
    </div>
  </div>`;
}

function renderContainers(data) {
  const rows = data?.strix_containers || [];
  if (!rows.length) return emptyState("No scan containers", "Live Nscan sandbox containers will appear here.");
  return `<div class="table-scroll"><table class="data-table compact"><thead><tr><th>Container</th><th>State</th><th>Target / IP</th><th>Network</th><th>Container IP</th><th>PID</th><th>Traffic</th><th>Mapping</th><th>Started</th></tr></thead><tbody>${rows.map((item) => `
    <tr><td><div class="cell-primary">${escapeHtml(item.name || item.id)}</div><div class="cell-secondary mono">${escapeHtml(item.id)}</div></td>
    <td>${badge(item.orphan_container ? "orphan" : item.state || "unknown", item.orphan_container ? "warning" : undefined)}${item.orphan_reason ? `<div class="cell-secondary">${escapeHtml(item.orphan_reason)}</div>` : ""}</td>
    <td><div class="cell-primary">${escapeHtml(item.target || "-")}</div><div class="cell-secondary mono break-anywhere">${escapeHtml((item.target_ips || []).join(", ") || item.scan_id || "-")}</div></td>
    <td class="mono">${escapeHtml(item.network_mode || "-")}</td>
    <td class="mono">${escapeHtml(item.container_ip || "-")}</td>
    <td><div class="mono">${escapeHtml(item.pid || "-")}</div><div class="cell-secondary mono">scan ${escapeHtml(item.scanner_pid || "-")} ${item.scanner_pid_exists === false ? "missing" : ""}</div></td>
    <td><div class="cell-primary">RX ${escapeHtml(formatRate(item.net_rx_bps || 0))}</div><div class="cell-secondary">TX ${escapeHtml(formatRate(item.net_tx_bps || 0))} · ${escapeHtml(formatBytes((item.net_rx_bytes || 0) + (item.net_tx_bytes || 0)))}</div></td>
    <td><div>${badge(item.mapping_confidence || "unknown")}</div><div class="cell-secondary">${escapeHtml(item.mapping_source || "-")}</div></td>
    <td>${formatDate(item.started_at)}</td></tr>`).join("")}</tbody></table></div>`;
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

async function inspectScan(scanId, target) {
  openDrawer({ title: target || "Scan activity", subtitle: scanId, body: skeleton(3) });
  const body = document.getElementById("drawerBody");
  try {
    const data = await api.logs(undefined, { scan_id: scanId, limit: 300, days: 2, joined: true });
    const requests = sortNewest(data.joined?.requests || []);
    body.innerHTML = requests.length ? `<div class="page-stack"><div class="compact-grid">
      <div class="metric-card"><div class="metric-label">Requests</div><div class="metric-value">${requests.length}</div></div>
      <div class="metric-card"><div class="metric-label">Model switches</div><div class="metric-value">${requests.reduce((sum, row) => sum + (row.model_switches?.length || 0), 0)}</div></div>
    </div><div class="table-scroll"><table class="data-table"><thead><tr><th>Time</th><th>Model</th><th>Status</th><th>Duration</th><th>Tokens</th><th>Switches</th></tr></thead><tbody>${requests.map((row) => `
      <tr><td>${formatDate(displayTimestamp(row))}</td><td>${modelIdentity({ name: row.actual_model || "-", model: row.actual_model || "", provider: row.provider || row.proxy_slot || "" }, { compact: true, secondary: escapeHtml(row.provider || row.proxy_slot || "") })}</td><td>${badge(row.status || "pending")}</td><td>${row.duration_seconds == null ? "-" : formatDuration(row.duration_seconds)}</td><td>${formatNumber(row.usage?.total_tokens || 0)}</td><td>${row.model_switches?.length || 0}</td></tr>`).join("")}</tbody></table></div></div>` : emptyState("No LLM activity found", "The scan may not have reached an LLM request or logs may have rotated.");
  } catch (error) {
    body.innerHTML = errorState(error);
  }
}

export function mountScans(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(6);
  let data = null;
  let jobs = null;
  let containers = null;
  let containersError = null;
  let selectedId = "";
  const batchDetails = new Map();
  let loadingDetail = false;
  let advancedRuntimeOpen = false;
  let firstTelemetryLoad = true;
  const filters = { status: "", query: "" };
  const submitDraft = {
    targets: "",
    label: "",
    mode: "redteam",
    parallel: 2,
    timeout: 0,
    single_targets: true,
    use_socks5: true,
    monitor: true,
    skip_scanned: false,
    dry_run: false,
    allow_private_targets: false,
    probe_live_before_queue: true,
    skip_dns_guard: true,
  };

  function currentBatches() {
    return (data?.batches || []).filter((batch) => batchLifecycle(batch) === "current");
  }

  function historyBatches() {
    return (data?.batches || []).filter((batch) => batchLifecycle(batch) === "history");
  }

  function render() {
    if (!data) return;
    const current = currentBatches();
    if (selectedId && !current.some((batch) => batch.batch_id === selectedId)) selectedId = "";
    if (!selectedId && current[0]) selectedId = current[0].batch_id;
    const selectedSummary = current.find((batch) => batch.batch_id === selectedId) || current[0];
    const selectedDetail = selectedSummary ? batchDetails.get(selectedSummary.batch_id) : null;
    const selected = selectedSummary ? { ...selectedSummary, ...(selectedDetail || {}), tasks: selectedDetail?.tasks || [] } : null;
    const currentTasks = current.flatMap((batch) => ((batchDetails.get(batch.batch_id)?.tasks || batch.tasks || [])).map((task) => ({ ...task, batch_id: batch.batch_id })));
    const activeTasks = currentTasks.filter(isActiveTask);
    const queuedTasks = currentTasks.filter(isQueuedPending);
    const autoRequeueTasks = currentTasks.filter(isAutoRequeuePending);
    const dueRetryTasks = currentTasks.filter(isRetryDue);
    const failedTasks = currentTasks.filter((task) => ["failed", "timeout"].includes(task.status));
    const selectedTasks = selected?.tasks || [];
    const queueQuery = filters.query.toLowerCase();
    const queueTasks = selectedTasks.filter((task) => {
      if (filters.status === "running" && !isActiveTask(task)) return false;
      if (filters.status === "pending" && !isQueuedPending(task)) return false;
      if (filters.status === "retry" && !isRetryPending(task) && !isAutoRequeuePending(task)) return false;
      if (filters.status === "success" && task.status !== "success") return false;
      if (filters.status === "failed" && !["failed", "timeout"].includes(task.status)) return false;
      if (!filters.status && DONE_STATUS.has(task.status)) return false;
      return !queueQuery || `${task.target} ${task.status} ${task.llm_model_primary} ${task.last_error}`.toLowerCase().includes(queueQuery);
    }).sort((a, b) => Number(isActiveTask(b)) - Number(isActiveTask(a)));
    const summary = data.summary || {};
    const overallProgress = summary.overall_progress_percent ?? 0;
    const runningCount = activeTasks.length || summary.running_tasks || 0;
    const queuedCount = queuedTasks.length + autoRequeueTasks.length || (summary.pending_tasks || 0) + (summary.retry_pending_tasks || 0) + (summary.auto_requeue_pending_tasks || 0);
    const retryDueCount = dueRetryTasks.length || (summary.retry_due_tasks || 0) + (summary.auto_requeue_due_tasks || 0);
    const failedCount = failedTasks.length || (summary.failed_tasks || 0) + (summary.timeout_tasks || 0);
    const preflightBatches = current.filter((batch) => batchPreparationStage(batch));
    const containerSummary = containers?.summary || {};
    const orphanContainers = containerSummary.orphan_containers || 0;
    root.innerHTML = `<div class="page-stack scans-page">
      <div class="metrics-grid single-row scans-key-metrics">
        <div class="metric-card"><div class="metric-label">Current progress</div><div class="metric-value">${formatNumber(overallProgress, 1)}%</div><div class="metric-detail">${summary.total_tasks || 0} active-window tasks</div></div>
        <div class="metric-card"><div class="metric-label">Running</div><div class="metric-value">${runningCount}</div><div class="metric-detail">${preflightBatches.length ? `${preflightBatches.length} in target safety preflight` : `${current.length} current batches`}</div></div>
        <div class="metric-card ${retryDueCount ? "warning" : ""}"><div class="metric-label">Queued</div><div class="metric-value">${queuedCount}</div><div class="metric-detail">${retryDueCount} ready to retry</div></div>
        <div class="metric-card"><div class="metric-label">Succeeded</div><div class="metric-value">${summary.successful_tasks || 0}</div><div class="metric-detail">Current active batches</div></div>
        <div class="metric-card ${failedCount ? "warning" : ""}"><div class="metric-label">Failed</div><div class="metric-value">${failedCount}</div><div class="metric-detail">${summary.timeout_tasks || 0} timed out</div></div>
      </div>

      ${panel("Active Scans", "Batches currently running or queued for execution", renderBatchList(current, selectedId, "current"), "", "scan-current-panel")}

      <section class="panel"><header class="panel-header"><div><h2>Targets for selected scan</h2><p>${selected ? `${loadingDetail ? "loading detail…" : `${queueTasks.length} targets shown`} · ${escapeHtml(selected.scan_mode || "-")}` : "Select a batch"}</p></div><div class="panel-actions compact-controls"><select id="taskStatusFilter"><option value="">All</option>${[["running","Running"],["pending","Queued"],["retry","Retry"],["success","Succeeded"],["failed","Failed"]].map(([value, label]) => `<option value="${value}" ${filters.status === value ? "selected" : ""}>${label}</option>`).join("")}</select><input id="taskSearch" type="search" placeholder="Search targets" value="${escapeHtml(filters.query)}"></div></header><div class="panel-body compact-queue-body">${loadingDetail ? skeleton(2) : selected && batchPreparationStage(selected) ? emptyState("Queue preflight", escapeHtml(selected.input_source?.preflight_detail || "Validating target safety and running multi-proxy liveness checks before tasks are created.")) : selectedDetail ? renderTaskList(queueTasks, { limit: 50, compact: true, emptyTitle: "No matching targets", emptyDetail: "Change the filter or select another batch." }) : emptyState("Select a batch", "Task detail is loaded on demand.")}</div></section>

      <details class="panel advanced-panel scans-advanced"><summary>Create new scan</summary><div class="advanced-content page-stack">
        ${renderSubmitForm(submitDraft)}
      </div></details>

      <details class="panel advanced-panel scans-advanced" ${advancedRuntimeOpen ? "open" : ""}><summary>Advanced runtime details</summary><div class="advanced-content page-stack">
        ${panel("Docker scan containers", `${containers ? `${containerSummary.strix_running || 0} running · ${orphanContainers} orphan` : "Loading telemetry"}`, containersError ? errorState(containersError) : containers ? renderContainers(containers) : skeleton(2))}
        ${jobs?.jobs?.length ? panel("Recent dashboard submissions", "Batches launched from this console", `<div class="batch-summary-list">${jobs.jobs.slice(0, 6).map((job) => `<div class="job-row"><div><strong>${escapeHtml(job.job_id)}</strong><div class="cell-secondary">${job.target_count} targets · PID ${escapeHtml(job.pid || "-")} · ${formatDate(job.submitted_at)}</div></div>${badge(job.process_alive ? "running" : job.status || "submitted")}</div>`).join("")}</div>`) : ""}
      </div></details>
    </div>`;
    bind();
  }

  function bind() {
    root.querySelector(".scans-advanced")?.addEventListener("toggle", (event) => {
      advancedRuntimeOpen = event.currentTarget.open;
    });
    root.querySelectorAll("[data-batch-id]").forEach((button) => button.addEventListener("click", async () => {
      if (!currentBatches().some((batch) => batch.batch_id === button.dataset.batchId)) {
        window.location.hash = "#scanHistory";
        return;
      }
      selectedId = button.dataset.batchId;
      await loadBatchDetail(selectedId);
    }));
    root.querySelectorAll("[data-scan-id]").forEach((button) => button.addEventListener("click", () => inspectScan(button.dataset.scanId, button.dataset.target)));
    root.querySelector("#taskStatusFilter")?.addEventListener("change", (event) => {
      filters.status = event.target.value;
      render();
    });
    root.querySelector("#taskSearch")?.addEventListener("input", debounce((event) => {
      filters.query = event.target.value;
      render();
    }, 120));
    root.querySelector("#scanPreviewButton")?.addEventListener("click", previewSubmission);
    root.querySelector("#scanSubmitForm")?.addEventListener("submit", submitScan);
    root.querySelectorAll("[data-batch-parallel-form]").forEach((form) => form.addEventListener("submit", updateBatchParallel));
    root.querySelectorAll("[data-batch-pause]").forEach((button) => button.addEventListener("click", controlBatchPause));
    root.querySelectorAll("[data-batch-terminate]").forEach((button) => button.addEventListener("click", controlBatchTerminate));
    root.querySelectorAll("[data-batch-delete]").forEach((button) => button.addEventListener("click", controlBatchDelete));
    root.querySelector("#scanSubmitForm")?.addEventListener("input", () => {
      Object.assign(submitDraft, formPayload(root));
    });
  }

  async function controlBatchPause(event) {
    const button = event.currentTarget;
    const batchId = button.dataset.batchPause;
    const paused = button.dataset.paused !== "true";
    button.disabled = true;
    try {
      await api.setBatchPaused(batchId, paused);
      toast(`${batchId} ${paused ? "pause requested" : "resumed"}`);
      await load(undefined, { includeContainers: false });
    } catch (error) { toast(error.message, "error"); button.disabled = false; }
  }

  async function controlBatchTerminate(event) {
    const batchId = event.currentTarget.dataset.batchTerminate;
    const accepted = await confirmAction({ title: "Terminate batch", message: `Stop ${batchId}, its active scanner processes, and its labeled sandbox containers? Reports and completed results are preserved.`, confirmLabel: "Terminate", danger: true });
    if (!accepted) return;
    event.currentTarget.disabled = true;
    try { await api.terminateBatch(batchId); toast(`${batchId} terminated`); await load(undefined, { includeContainers: true }); }
    catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
  }

  async function controlBatchDelete(event) {
    const batchId = event.currentTarget.dataset.batchDelete;
    const batch = (data.batches || []).find((item) => item.batch_id === batchId);
    const active = batchLifecycle(batch || {}) === "current";
    const accepted = await confirmAction({ title: "Delete batch from dashboard", message: `${active ? "The active batch will be terminated first. " : ""}Remove ${batchId} from Dashboard state? Scan reports, history, targets, and completed evidence remain on disk.`, confirmLabel: active ? "Terminate & delete" : "Delete", danger: true });
    if (!accepted) return;
    event.currentTarget.disabled = true;
    try {
      if (active) await api.terminateBatch(batchId);
      await api.deleteBatch(batchId);
      toast(`${batchId} removed from Dashboard; reports preserved`);
      await load(undefined, { includeContainers: true });
    } catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
  }

  async function updateBatchParallel(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const batchId = form.dataset.batchParallelForm;
    const parallel = Number(form.elements.parallel?.value || 0);
    try {
      const result = await api.setBatchParallel(batchId, parallel);
      if (result.status !== "accepted") {
        throw new Error("Parallel control backend is pending a safe proxy restart");
      }
      toast(`Parallel ${result.status}: requested ${result.requested_parallel}, effective ${result.effective_parallel}`);
      await load(undefined, { includeContainers: false });
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function loadBatchDetail(batchId, signal, { force = false } = {}) {
    if (!batchId || (!force && batchDetails.has(batchId))) {
      render();
      return;
    }
    loadingDetail = true;
    render();
    try {
      const detail = await api.batch(batchId, signal);
      batchDetails.set(batchId, detail);
    } catch (error) {
      if (error.name !== "AbortError") toast(error.message, "error");
    } finally {
      loadingDetail = false;
      render();
    }
  }

  async function previewSubmission() {
    const preview = root.querySelector("#scanSubmitPreview");
    try {
      const result = await api.previewSmartBatchJob(formPayload(root));
      const blocked = restrictedTargetsPreview(result.rejected_targets || []);
      preview.textContent = `${result.target_count} accepted targets · ${result.restricted_target_count || 0} blocked · ${result.options.mode} · parallel ${result.options.parallel} · egress ${result.options.use_socks5 ? "on" : "off"} · live probe ${result.options.probe_live_before_queue ? `on (${result.options.probe_proxy_quorum}/${result.options.probe_max_proxy_nodes} proxies)` : "off"}.${blocked}`;
      toast(result.restricted_target_count ? "Preview found restricted targets" : "Batch preview is valid", result.restricted_target_count ? "warning" : "success");
    } catch (error) {
      preview.textContent = error.message;
      toast(error.message, "error");
    }
  }

  async function submitScan(event) {
    event.preventDefault();
    const payload = formPayload(root);
    const dryRunText = payload.dry_run ? " as a dry run" : "";
    const privateText = payload.allow_private_targets ? " Private/local targets are explicitly allowed for this run." : "";
    const dnsText = payload.skip_dns_guard ? " DNS-resolve safety blocking is skipped for this trusted list." : "";
    const probeText = payload.probe_live_before_queue ? ` A multi-proxy live probe (${payload.probe_proxy_quorum}/${payload.probe_max_proxy_nodes}) runs before queueing.` : "";
    const confirmed = await confirmAction({
      title: "Start Smart Batch",
      message: `Start this batch${dryRunText} with mode ${payload.mode}, parallel ${payload.parallel}, and egress ${payload.use_socks5 ? "enabled" : "disabled"}?${probeText}${dnsText}${privateText}`,
      confirmLabel: "Start batch",
      danger: payload.allow_private_targets,
    });
    if (!confirmed) return;
    try {
      const result = await api.submitSmartBatchJob(payload);
      toast(`Batch submitted: PID ${result.pid}`);
      submitDraft.targets = "";
      submitDraft.label = "";
      await load(undefined, { includeContainers: false });
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function load(signal, { includeContainers = false } = {}) {
    const shouldLoadContainers = includeContainers || firstTelemetryLoad || advancedRuntimeOpen;
    firstTelemetryLoad = false;
    const containersRequest = shouldLoadContainers
      ? api.containers(signal).then((value) => ({ value }), (error) => ({ error }))
      : Promise.resolve({ value: containers });
    const [batchData, jobData] = await Promise.all([
      api.batches(signal, 60, { includeFinished: false, includeTasks: false }),
      api.smartBatchJobs(signal, 20).catch(() => ({ jobs: [] })),
    ]);
    data = batchData;
    jobs = jobData;
    render();
    setFreshness(data.generated_at);
    if (selectedId) await loadBatchDetail(selectedId, signal, { force: true });
    const telemetry = await containersRequest;
    if (telemetry.error) {
      if (telemetry.error.name === "AbortError") throw telemetry.error;
      containersError = telemetry.error;
    } else {
      containers = telemetry.value;
      containersError = null;
    }
    render();
    setFreshness(containers?.generated_at || data.generated_at, Boolean(containersError));
  }

  const poller = new Poller(5000, load, (error) => {
    if (!data) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  return () => poller.stop();
}

export function mountScanHistory(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(5);
  let data = null;
  let scanned = null;
  const batchDetails = new Map();
  let loadingDetail = false;
  let selectedId = "";
  const filters = { status: "", query: "" };
  const historyFilters = { query: "", lifecycle: "history" };
  const scannedFilters = { query: "", page: 1 };

  function renderScannedTargets() {
    if (!scanned) return skeleton(3);
    const items = scanned.items || [];
    if (!items.length) return emptyState("No scanned targets found", "History files are indexed automatically.");
    return `<div class="scanned-target-list">${items.map((item) => {
      const sources = item.sources || [];
      return `<article class="scanned-target-row">
        <div class="scanned-target-main">
          <strong class="break-anywhere">${escapeHtml(item.target)}</strong>
          <div class="cell-secondary">${sources.length ? `${sources.length} history source${sources.length > 1 ? "s" : ""}` : "history registry"} · recorded ${formatDate(item.last_seen)}</div>
        </div>
        <div class="scanned-source-stack">
          ${sources.slice(0, 3).map((source) => `<span class="source-chip" title="${escapeHtml(source)}">${escapeHtml(source.split("/").slice(-2).join("/"))}</span>`).join("")}
          ${sources.length > 3 ? `<span class="source-chip muted-chip">+${sources.length - 3}</span>` : ""}
        </div>
      </article>`;
    }).join("")}</div><div class="pagination-row"><span class="muted">${formatNumber(scanned.total || 0, 0)} scanned targets · page ${scanned.page} of ${scanned.pages}</span><div class="panel-actions"><button class="button secondary small" type="button" data-scanned-page="${scanned.page - 1}" ${scanned.page <= 1 ? "disabled" : ""}>Previous</button><button class="button secondary small" type="button" data-scanned-page="${scanned.page + 1}" ${scanned.page >= scanned.pages ? "disabled" : ""}>Next</button></div></div>`;
  }

  function filteredHistory() {
    const batches = (data?.batches || []).filter((batch) => {
      if (historyFilters.lifecycle === "current") return batchLifecycle(batch) === "current";
      if (historyFilters.lifecycle === "all") return true;
      return batchLifecycle(batch) === "history";
    });
    const query = historyFilters.query.toLowerCase();
    if (!query) return batches;
    return batches.filter((batch) => {
      const haystack = [
        batch.batch_id,
        batch.scan_mode,
        batch.status,
        batch.lifecycle,
      ].join(" ").toLowerCase();
      return haystack.includes(query);
    });
  }

  function render() {
    if (!data) return;
    const batches = filteredHistory();
    if (selectedId && !batches.some((batch) => batch.batch_id === selectedId)) selectedId = "";
    if (!selectedId && batches[0]) selectedId = batches[0].batch_id;
    const selectedSummary = batches.find((batch) => batch.batch_id === selectedId) || batches[0];
    const selectedDetail = selectedSummary ? batchDetails.get(selectedSummary.batch_id) : null;
    const selected = selectedSummary ? { ...selectedSummary, ...(selectedDetail || {}), tasks: selectedDetail?.tasks || [] } : null;
    const counts = aggregateCounts(batches);
    const progressPercent = counts.total ? (counts.completed / counts.total) * 100 : 0;
    const detailQuery = filters.query.toLowerCase();
    const detailTasks = (selected?.tasks || []).filter((task) => {
      if (filters.status === "retry" && !isRetryPending(task) && !isAutoRequeuePending(task)) return false;
      if (filters.status && filters.status !== "retry" && task.status !== filters.status) return false;
      return !detailQuery || `${task.target} ${task.status} ${task.llm_model_primary} ${task.last_error}`.toLowerCase().includes(detailQuery);
    }).sort((a, b) => {
      const rank = { failed: 0, timeout: 0, retrying: 1, running: 1, pending: 2, success: 3 };
      return (rank[a.status] ?? 4) - (rank[b.status] ?? 4);
    });
    root.innerHTML = `<div class="page-stack scans-page">
      <div class="metrics-grid history-key-metrics">
        <div class="metric-card"><div class="metric-label">Batches</div><div class="metric-value">${batches.length}</div><div class="metric-detail">${historyFilters.lifecycle} view</div></div>
        <div class="metric-card"><div class="metric-label">Scanned targets</div><div class="metric-value">${formatNumber(scanned?.total || 0)}</div><div class="metric-detail">Deduplicated history registry</div></div>
        <div class="metric-card"><div class="metric-label">Progress</div><div class="metric-value">${formatNumber(progressPercent, 1)}%</div><div class="metric-detail">${counts.completed}/${counts.total} tasks complete</div></div>
        <div class="metric-card"><div class="metric-label">Succeeded</div><div class="metric-value">${counts.success}</div><div class="metric-detail">Across listed batches</div></div>
        <div class="metric-card ${counts.failed ? "warning" : ""}"><div class="metric-label">Failed</div><div class="metric-value">${counts.failed}</div><div class="metric-detail">${counts.timeout} timed out</div></div>
      </div>

      <section class="panel scan-history-panel"><header class="panel-header"><div><h2>Batch history</h2><p>One row per batch: state, completion, failures, running tasks, and queue size</p></div><div class="panel-actions"><select id="historyLifecycleFilter"><option value="history" ${historyFilters.lifecycle === "history" ? "selected" : ""}>Historical only</option><option value="current" ${historyFilters.lifecycle === "current" ? "selected" : ""}>Current only</option><option value="all" ${historyFilters.lifecycle === "all" ? "selected" : ""}>All batches</option></select><input id="historyBatchSearch" type="search" placeholder="Search batch, target, scan_id, error" value="${escapeHtml(historyFilters.query)}"></div></header><div class="panel-body">${renderBatchList(batches, selectedId, "history")}</div></section>

      <section class="panel"><header class="panel-header"><div><h2>Targets for selected batch</h2><p>${selected ? `${escapeHtml(selected.batch_id)} · ${loadingDetail ? "loading detail…" : `${detailTasks.length} targets shown`}` : "Select a batch"}</p></div><div class="panel-actions compact-controls"><select id="taskStatusFilter"><option value="">All</option>${[["success","Succeeded"],["failed","Failed"],["timeout","Timed out"],["running","Running"],["pending","Queued"],["retry","Retry"]].map(([value, label]) => `<option value="${value}" ${filters.status === value ? "selected" : ""}>${label}</option>`).join("")}</select><input id="taskSearch" type="search" placeholder="Search targets" value="${escapeHtml(filters.query)}"></div></header><div class="panel-body">${loadingDetail ? skeleton(2) : selectedDetail ? renderTaskList(detailTasks, { limit: 100, emptyTitle: "No matching results", emptyDetail: "Change the filter or select another batch." }) : emptyState("Select a batch", "Task detail is loaded on demand.")}</div></section>

      <details class="panel advanced-panel"><summary>Scanned targets (Deduplicated registry)</summary><div class="advanced-content page-stack">
        <section class="panel scanned-targets-panel"><header class="panel-header"><div><h2>Scanned targets</h2><p>Deduplicated registry across current, report, and legacy 0.8.3 history files</p></div><div class="panel-actions"><input id="scannedTargetSearch" type="search" placeholder="Search scanned targets" value="${escapeHtml(scannedFilters.query)}"></div></header><div class="panel-body">${renderScannedTargets()}</div></section>
      </div></details>
    </div>`;
    bind();
  }

  function bind() {
    root.querySelectorAll("[data-batch-id]").forEach((button) => button.addEventListener("click", async () => {
      selectedId = button.dataset.batchId;
      await loadBatchDetail(selectedId);
    }));
    root.querySelectorAll("[data-scan-id]").forEach((button) => button.addEventListener("click", () => inspectScan(button.dataset.scanId, button.dataset.target)));
    root.querySelector("#taskStatusFilter")?.addEventListener("change", (event) => {
      filters.status = event.target.value;
      render();
    });
    root.querySelector("#taskSearch")?.addEventListener("input", debounce((event) => {
      filters.query = event.target.value;
      render();
    }, 120));
    root.querySelector("#scannedTargetSearch")?.addEventListener("input", debounce(async (event) => {
      scannedFilters.query = event.target.value;
      scannedFilters.page = 1;
      await loadScannedTargets();
    }, 180));
    root.querySelectorAll("[data-scanned-page]").forEach((button) => button.addEventListener("click", async () => {
      scannedFilters.page = Number(button.dataset.scannedPage) || 1;
      await loadScannedTargets();
    }));
    root.querySelector("#historyLifecycleFilter")?.addEventListener("change", (event) => {
      historyFilters.lifecycle = event.target.value;
      selectedId = "";
      render();
    });
    root.querySelector("#historyBatchSearch")?.addEventListener("input", debounce((event) => {
      historyFilters.query = event.target.value;
      selectedId = "";
      render();
    }, 160));
  }

  async function loadScannedTargets(signal) {
    scanned = await api.scannedTargets(signal, { query: scannedFilters.query, page: scannedFilters.page, page_size: 50 });
    render();
  }

  async function loadBatchDetail(batchId, signal) {
    if (!batchId || batchDetails.has(batchId)) {
      render();
      return;
    }
    loadingDetail = true;
    render();
    try {
      const detail = await api.batch(batchId, signal);
      batchDetails.set(batchId, detail);
    } catch (error) {
      if (error.name !== "AbortError") toast(error.message, "error");
    } finally {
      loadingDetail = false;
      render();
    }
  }

  async function load(signal) {
    [data, scanned] = await Promise.all([
      api.batches(signal, 100, { includeFinished: true, includeTasks: false }),
      api.scannedTargets(signal, { query: scannedFilters.query, page: scannedFilters.page, page_size: 50 }),
    ]);
    const batches = filteredHistory();
    if (selectedId && !batches.some((batch) => batch.batch_id === selectedId)) selectedId = "";
    if (!selectedId && batches[0]) selectedId = batches[0].batch_id;
    render();
    setFreshness(data.generated_at);
    if (selectedId) await loadBatchDetail(selectedId, signal);
  }

  // Changed to 60s for history because it's heavy and changes infrequently.
  const poller = new Poller(60000, load, (error) => {
    if (!data) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  return () => poller.stop();
}
