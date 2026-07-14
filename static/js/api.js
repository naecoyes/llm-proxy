class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  if (response.status === 401) {
    window.location.assign("/");
    throw new ApiError("Session expired", 401, {});
  }
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    if (response.status === 403) showAccessDenied(payload);
    const message = payload?.detail || payload?.message || response.statusText || "Request failed";
    throw new ApiError(message, response.status, payload);
  }
  return payload;
}

function showAccessDenied(payload) {
  const detail = typeof payload === "string" ? payload : payload?.detail || "This source address is not allowed.";
  document.body.innerHTML = `<main class="error-state" style="min-height:100vh"><div><h1>Access denied</h1><p>${detail}</p></div></main>`;
}

const jsonBody = (body) => ({ body: JSON.stringify(body) });

export const api = {
  summary: (signal, includeTelemetry = true) => request(`/proxy/dashboard/summary?include_telemetry=${includeTelemetry}`, { signal }),
  badges: (signal) => request("/proxy/dashboard/badges", { signal }),
  status: (signal, scanMode = "redteam") => request(`/proxy/status${scanMode ? `?scan_mode=${encodeURIComponent(scanMode)}` : ""}`, { signal }),
  resources: (signal) => request("/proxy/system/resources", { signal }),
  egressUsage: (signal) => request("/proxy/egress/usage", { signal }),
  batches: (signal, limit = 20, options = {}) => request(`/proxy/smart-batch/status?${new URLSearchParams({
    limit,
    include_finished: options.includeFinished ?? true,
    include_tasks: options.includeTasks ?? true,
  })}`, { signal }),
  scannedTargets: (signal, params = {}) => request(`/proxy/scanned-targets?${new URLSearchParams({ page: 1, page_size: 50, ...params })}`, { signal }),
  assetsSummary: (signal) => request("/proxy/assets/summary", { signal }),
  assetsScopeSummary: (signal) => request("/proxy/assets/scope-summary", { signal }),
  assets: (signal, params = {}) => request(`/proxy/assets?${new URLSearchParams({ page: 1, page_size: 50, ...params })}`, { signal }),
  asset: (assetId, signal) => request(`/proxy/assets/${encodeURIComponent(assetId)}`, { signal }),
  assetGroups: (signal) => request("/proxy/asset-groups", { signal }),
  assetsExportUrl: (params = {}) => `/proxy/assets/export?${new URLSearchParams(params)}`,
  targetQuarantine: (signal, params = {}) => request(`/proxy/target-ingest/quarantine?${new URLSearchParams({ page: 1, page_size: 50, ...params })}`, { signal }),
  replayAssetSpool: () => request("/proxy/assets/spool/replay", { method: "POST" }),
  smartBatchJobs: (signal, limit = 50) => request(`/proxy/smart-batch/jobs?limit=${limit}`, { signal }),
  smartBatchJobsHealth: (signal) => request("/proxy/smart-batch/jobs/health-summary", { signal }),
  previewSmartBatchJob: (body) => request("/proxy/smart-batch/jobs/preview", { method: "POST", ...jsonBody(body) }),
  submitSmartBatchJob: (body) => request("/proxy/smart-batch/jobs", { method: "POST", ...jsonBody(body) }),
  terminateSmartBatchJob: (jobId) => request(`/proxy/smart-batch/jobs/${encodeURIComponent(jobId)}/terminate`, { method: "POST" }),
  resumeSmartBatchJob: (jobId) => request(`/proxy/smart-batch/jobs/${encodeURIComponent(jobId)}/resume`, { method: "POST" }),
  smartBatchWorkers: (signal) => request("/proxy/smart-batch/jobs/runtime-summary", { signal }),
  findingsSummary: (signal) => request("/proxy/vulnerabilities/summary", { signal }),
  findingsHistory: (signal, days = 30, sample = "raw") => request(`/proxy/vulnerabilities/history?${new URLSearchParams({ days, sample })}`, { signal }),
  findingsBootstrap: (signal, params = {}) => request(`/proxy/vulnerabilities/bootstrap?${new URLSearchParams({ page: 1, page_size: 50, status: "needs-review", sort: "legacy", order: "asc", ...params })}`, { signal }),
  findings: (signal, params = {}) => request(`/proxy/vulnerabilities?${new URLSearchParams({ page: 1, page_size: 50, ...params })}`, { signal }),
  finding: (recordId, signal) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}`, { signal }),
  findingContent: (recordId, signal) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}/content`, { signal }),
  reportGeneratorStatus: (signal) => request("/proxy/report-generator/status", { signal }),
  sendFindingToReportGenerator: (recordId) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}/report-generator`, { method: "POST" }),
  syncFindingReportGeneratorDraft: (recordId) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}/report-generator/sync`, { method: "POST" }),
  generateFindingReportGeneratorFields: (recordId) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}/report-generator/generate`, { method: "POST" }),
  findingTargets: (signal) => request("/proxy/vulnerabilities/targets", { signal }),
  findingReports: (signal) => request("/proxy/vulnerability-reports", { signal }),
  findingReport: (reportId, signal) => request(`/proxy/vulnerability-reports/${encodeURIComponent(reportId)}`, { signal }),
  refreshFindings: () => request("/proxy/vulnerabilities/refresh", { method: "POST" }),
  updateFindingState: (recordId, actions) => request(`/proxy/vulnerabilities/${encodeURIComponent(recordId)}/state`, { method: "PATCH", ...jsonBody(actions) }),
  bulkFindingState: (recordIds, actions) => request("/proxy/vulnerabilities/bulk-state", { method: "POST", ...jsonBody({ record_ids: recordIds, actions }) }),
  autocleanFindings: () => request("/proxy/vulnerabilities/autoclean", { method: "POST", ...jsonBody({}) }),
  batch: (batchId, signal) => request(`/proxy/smart-batch/status/${encodeURIComponent(batchId)}`, { signal }),
  setBatchParallel: (batchId, parallel) => request(`/proxy/smart-batch/status/${encodeURIComponent(batchId)}/parallel`, { method: "POST", ...jsonBody({ parallel }) }),
  setBatchPaused: (batchId, paused) => request(`/proxy/smart-batch/status/${encodeURIComponent(batchId)}/pause`, { method: "POST", ...jsonBody({ paused }) }),
  terminateBatch: (batchId) => request(`/proxy/smart-batch/status/${encodeURIComponent(batchId)}/terminate`, { method: "POST" }),
  deleteBatch: (batchId) => request(`/proxy/smart-batch/status/${encodeURIComponent(batchId)}`, { method: "DELETE" }),
  runtime: (signal, checkNodes = false) => request(`/proxy/nscan-runtime/status?check_nodes=${checkNodes}`, { signal }),
  containers: (signal) => request("/proxy/docker/containers", { signal }),
  cleanupOrphanContainers: (dryRun = false) => request("/proxy/docker/orphan-containers/cleanup", { method: "POST", ...jsonBody({ dry_run: dryRun }) }),
  security: (signal) => request("/proxy/security/status", { signal }),
  usage: (signal) => request("/proxy/usage", { signal }),
  trend: (signal, granularity = "4h", model = "", groupBy = "provider") => request(`/proxy/usage/trend?granularity=${encodeURIComponent(granularity)}&group_by=${encodeURIComponent(groupBy)}${model ? `&model=${encodeURIComponent(model)}` : ""}`, { signal }),
  logs: (signal, params = {}) => request(`/proxy/logs?${new URLSearchParams({ limit: 200, days: 2, joined: true, ...params })}`, { signal }),
  config: (signal) => request("/proxy/config", { signal }),
  saveConfig: (body) => request("/proxy/config", { method: "PUT", ...jsonBody(body) }),
  logout: () => request("/proxy/security/logout", { method: "POST" }),
  updatePin: (pin) => request("/proxy/security/pin", { method: "PUT", ...jsonBody({ pin }) }),
  addIp: (ip) => request("/proxy/ip-whitelist/add", { method: "POST", ...jsonBody({ ip }) }),
  removeIp: (ip) => request("/proxy/ip-whitelist/remove", { method: "POST", ...jsonBody({ ip }) }),
  checkModels: () => request("/proxy/check"),
  model: (name, signal) => request(`/proxy/models/${encodeURIComponent(name)}`, { signal }),
  addModel: (body) => request("/proxy/models/add", { method: "POST", ...jsonBody(body) }),
  updateModel: (name, body) => request(`/proxy/models/${encodeURIComponent(name)}`, { method: "PUT", ...jsonBody(body) }),
  deleteModel: (name) => request(`/proxy/models/${encodeURIComponent(name)}`, { method: "DELETE" }),
  toggleModel: (name, enabled) => request(`/proxy/models/${encodeURIComponent(name)}/${enabled ? "enable" : "disable"}`, { method: "POST" }),
  testModel: (name) => request(`/proxy/models/${encodeURIComponent(name)}/test`, { method: "POST" }),
  refreshModelReasoningCapabilities: () => request("/proxy/models/reasoning-capabilities/refresh", { method: "POST" }),
  setRoutingMode: (mode) => request("/proxy/models/routing-mode", { method: "POST", ...jsonBody({ mode }) }),
  setEgressEnabled: (enabled) => request("/proxy/nscan-runtime/proxy-enabled", { method: "POST", ...jsonBody({ enabled }) }),
  setEgressStartup: (enabled) => request("/proxy/nscan-runtime/proxy-startup-enabled", { method: "POST", ...jsonBody({ enabled }) }),
  setNodeEnabled: (tag, enabled) => request(`/proxy/nscan-runtime/nodes/${encodeURIComponent(tag)}/enabled`, { method: "POST", ...jsonBody({ enabled }) }),
  addProxyNode: (body) => request("/proxy/nscan-runtime/nodes", { method: "POST", ...jsonBody(body) }),
  testProxyNode: (body) => request("/proxy/nscan-runtime/nodes/test", { method: "POST", ...jsonBody(body) }),
  updateProxyNode: (tag, body) => request(`/proxy/nscan-runtime/nodes/${encodeURIComponent(tag)}`, { method: "PUT", ...jsonBody(body) }),
  deleteProxyNode: (tag) => request(`/proxy/nscan-runtime/nodes/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  restartEgress: () => request("/proxy/nscan-runtime/proxy-restart", { method: "POST" }),
  checkEgressIp: () => request("/proxy/nscan-runtime/egress-check", { method: "POST" }),
};

export { ApiError };
