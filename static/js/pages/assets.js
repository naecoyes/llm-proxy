import { api } from "../api.js";
import { badge, emptyState, errorState, openDrawer, panel, skeleton, toast } from "../components.js";
import { debounce, escapeHtml, formatDate, formatNumber } from "../utils.js";

const DEFAULT_FILTERS = {
  query: "",
  scan_status: "",
  probe_status: "",
  source: "",
  platform: "",
  group: "",
  scope_status: "",
  sort: "last_seen",
  page: 1,
  page_size: 50,
};

function statusCount(map = {}, ...keys) {
  return keys.reduce((sum, key) => sum + Number(map?.[key] || 0), 0);
}

function renderSummary(summary = {}) {
  const scan = summary.scan_status || {};
  const probe = summary.probe_status || {};
  const scope = summary.scope || {};
  return `<div class="metrics-grid single-row compact-metrics">
    <article class="metric-card"><div class="metric-label">Assets</div><div class="metric-value">${formatNumber(summary.total || 0, 0)}</div><div class="metric-detail">unique targets</div></article>
    <article class="metric-card"><div class="metric-label">Scanned</div><div class="metric-value">${formatNumber(statusCount(scan, "success", "completed", "succeeded"), 0)}</div><div class="metric-detail">database first, files fallback</div></article>
    <article class="metric-card"><div class="metric-label">Unscanned</div><div class="metric-value">${formatNumber(scan.unscanned || 0, 0)}</div><div class="metric-detail">ready for queueing</div></article>
    <article class="metric-card"><div class="metric-label">Live probe</div><div class="metric-value">${formatNumber(probe.alive || 0, 0)}</div><div class="metric-detail">last known alive</div></article>
    <article class="metric-card"><div class="metric-label">In scope</div><div class="metric-value">${formatNumber(scope.in_scope || 0, 0)}</div><div class="metric-detail">high-confidence admission</div></article>
    <article class="metric-card"><div class="metric-label">Scope review</div><div class="metric-value">${formatNumber(scope.scope_review_required || 0, 0)}</div><div class="metric-detail">stored, never auto-scanned</div></article>
    <article class="metric-card"><div class="metric-label">Findings refs</div><div class="metric-value">${formatNumber(summary.findings || 0, 0)}</div><div class="metric-detail">linked evidence</div></article>
    <article class="metric-card"><div class="metric-label">DB state</div><div class="metric-value">WAL</div><div class="metric-detail">SQLite shadow store</div></article>
  </div>`;
}

function renderFilters(filters, groups = {}) {
  const groupItems = groups.items || [];
  const platforms = [...new Set(groupItems.map((item) => item.platform).filter(Boolean))].sort();
  return `<div class="table-toolbar">
    <input id="assetSearch" type="search" placeholder="Search target or IP" value="${escapeHtml(filters.query)}">
    <select id="assetScanStatus">
      <option value="">All scan states</option>
      ${["unscanned", "success", "completed", "failed", "timeout", "running", "pending"].map((value) => `<option value="${value}" ${filters.scan_status === value ? "selected" : ""}>${value}</option>`).join("")}
    </select>
    <select id="assetProbeStatus">
      <option value="">All probe states</option>
      ${["unknown", "alive", "dead"].map((value) => `<option value="${value}" ${filters.probe_status === value ? "selected" : ""}>${value}</option>`).join("")}
    </select>
    <select id="assetScopeStatus">
      <option value="">All scope states</option>
      ${[["in_scope", "In scope"], ["scope_review_required", "Review required"], ["out_of_scope", "Out of scope"]].map(([value, label]) => `<option value="${value}" ${filters.scope_status === value ? "selected" : ""}>${label}</option>`).join("")}
    </select>
    <select id="assetPlatform">
      <option value="">All platforms</option>
      ${platforms.map((value) => `<option value="${escapeHtml(value)}" ${filters.platform === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
    </select>
    <select id="assetGroup">
      <option value="">All groups</option>
      ${groupItems.map((item) => `<option value="${escapeHtml(item.group_key)}" ${filters.group === item.group_key ? "selected" : ""}>${escapeHtml(item.label || item.platform || item.group_key)} (${formatNumber(item.asset_count || 0, 0)})</option>`).join("")}
    </select>
    <select id="assetSort">
      <option value="last_seen" ${filters.sort === "last_seen" ? "selected" : ""}>Last seen</option>
      <option value="last_scanned" ${filters.sort === "last_scanned" ? "selected" : ""}>Last scanned</option>
      <option value="findings" ${filters.sort === "findings" ? "selected" : ""}>Findings</option>
      <option value="target" ${filters.sort === "target" ? "selected" : ""}>Target</option>
    </select>
    <a class="button secondary small" href="${api.assetsExportUrl({ ...filters, format: "csv" })}">Export CSV</a>
  </div>`;
}

function renderAssetTable(data = {}) {
  const rows = data.items || [];
  if (!rows.length) return emptyState("No assets match this filter", "Imported history, probes, and batch snapshots will appear here.");
  return `<div class="table-wrap"><table class="data-table assets-table">
    <thead><tr><th>Target</th><th>Scope</th><th>Addresses</th><th>Probe</th><th>Scan</th><th>Findings</th><th>Last seen</th><th></th></tr></thead>
    <tbody>${rows.map((item) => `<tr>
      <td><strong class="break-anywhere">${escapeHtml(item.target)}</strong><div class="cell-secondary">${escapeHtml(item.target_type || "target")}${item.root_domain ? ` · ${escapeHtml(item.root_domain)}` : ""}</div></td>
      <td>${item.scope_status ? `${badge(item.scope_status)}${item.scope_category ? `<div class="cell-secondary">${escapeHtml(item.scope_category)}</div>` : ""}` : '<span class="muted">not evaluated</span>'}</td>
      <td class="break-anywhere">${escapeHtml(item.addresses || "-")}</td>
      <td>${badge(item.last_probe_status || "unknown")}</td>
      <td>${badge(item.last_scan_status || "unscanned")}${item.platforms ? `<div class="cell-secondary">${escapeHtml(item.platforms)}</div>` : ""}</td>
      <td>${formatNumber(item.finding_count || 0, 0)}</td>
      <td>${formatDate(item.last_seen)}</td>
      <td><button class="button ghost small" type="button" data-asset-id="${item.id}">Details</button></td>
    </tr>`).join("")}</tbody>
  </table></div>`;
}

function renderPagination(data = {}, filters = {}) {
  const page = Number(data.page || 1);
  const pages = Number(data.pages || 1);
  return `<div class="pagination-row">
    <div class="muted">${formatNumber(data.total || 0, 0)} assets · page ${page}/${pages}</div>
    <div class="panel-actions">
      <button class="button secondary small" id="assetPrevPage" type="button" ${page <= 1 ? "disabled" : ""}>Previous</button>
      <button class="button secondary small" id="assetNextPage" type="button" ${page >= pages ? "disabled" : ""}>Next</button>
    </div>
  </div>`;
}

function detailList(items = [], formatter) {
  if (!items.length) return emptyState("No records");
  return `<div class="detail-list">${items.slice(0, 80).map(formatter).join("")}</div>`;
}

function renderDetail(detail) {
  return `<div class="drawer-stack">
    ${panel("Scope", "Derived pre-scan admission decision", detail.scope ? `<div class="detail-row"><strong>${badge(detail.scope.scope_status || "unknown")}</strong><span>${escapeHtml(detail.scope.category || "no category")} · ${escapeHtml(detail.scope.confidence || "")}</span><span>${escapeHtml(detail.scope.reason || "")}</span></div>` : emptyState("Not evaluated", "The asset is stored, but has not passed through the scope gate yet."))}
    ${panel("Groups", "Platform/source grouping", detailList(detail.groups || [], (item) => `<div class="detail-row"><strong>${escapeHtml(item.label || item.platform || item.group_key)}</strong><span>${escapeHtml(item.group_key || "")} · ${formatDate(item.member_last_seen)}</span></div>`))}
    ${panel("Addresses", "Known DNS/IP observations", detailList(detail.addresses, (item) => `<div class="detail-row"><strong>${escapeHtml(item.ip)}</strong><span>${escapeHtml(item.source || "")} · ${formatDate(item.last_seen)}</span></div>`))}
    ${panel("Scans", "Batch and task history", detailList(detail.scans, (item) => `<div class="detail-row"><strong>${escapeHtml(item.batch_id || "-")}</strong><span>${badge(item.status || "unknown")} ${escapeHtml(item.scan_mode || "")} · ${formatDate(item.ended_at || item.started_at)}</span><span>${escapeHtml(item.model_name || "")}${item.total_tokens ? ` · ${formatNumber(item.total_tokens, 0)} tokens` : ""}</span></div>`))}
    ${panel("Attempts", "Retries, model attribution, and last errors", detailList(detail.attempts, (item) => `<div class="detail-row"><strong>${escapeHtml(item.batch_id || "-")} #${formatNumber(item.attempt_no || 0, 0)}</strong><span>${badge(item.status || "unknown")} ${escapeHtml(item.model_name || "")}${item.provider ? ` · ${escapeHtml(item.provider)}` : ""}</span><span class="break-anywhere">${item.total_tokens ? `${formatNumber(item.total_tokens, 0)} tokens · ` : ""}${escapeHtml(item.error || "")}</span></div>`))}
    ${panel("Findings", "Linked evidence references", detailList(detail.findings, (item) => `<div class="detail-row"><strong>${escapeHtml(item.title || item.finding_id || "finding")}</strong><span>${badge(item.severity || "UNKNOWN")} ${escapeHtml(item.source || "")}</span><span class="break-anywhere">${escapeHtml(item.report_path || "")}</span></div>`))}
    ${panel("Artifacts", "External files are referenced, not copied", detailList(detail.artifacts, (item) => `<div class="detail-row"><strong>${escapeHtml(item.artifact_type || "artifact")}</strong><span>${escapeHtml(item.root_id || "")} · ${formatDate(item.created_at)}</span><span class="break-anywhere">${escapeHtml(item.path || "")}</span></div>`))}
  </div>`;
}

export function mountAssets({ root, setFreshness, setRefreshHandler }) {
  let controller = null;
  let filters = { ...DEFAULT_FILTERS };
  let summary = null;
  let assets = null;
  let groups = null;
  let loadingTable = false;

  async function openAsset(assetId) {
    try {
      const detail = await api.asset(assetId);
      openDrawer({
        title: detail.target || "Asset detail",
        subtitle: `${detail.target_type || "target"} · ${detail.last_scan_status || "unscanned"}`,
        body: renderDetail(detail),
      });
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function render() {
    if (!summary || !assets) {
      root.innerHTML = skeleton(3);
      return;
    }
    root.innerHTML = `<div class="page-stack">
      ${renderSummary(summary)}
      ${panel(
        "Asset inventory",
        "Imported history, probes, live batches, attempts, and finding references",
        `${renderFilters(filters, groups)}${loadingTable ? '<div class="muted">Loading table…</div>' : ""}<div id="assetsTableRegion">${renderAssetTable(assets)}${renderPagination(assets, filters)}</div>`
      )}
    </div>`;
    bind(assets);
  }

  async function loadInitial() {
    controller?.abort();
    controller = new AbortController();
    render();
    try {
      [summary, assets, groups] = await Promise.all([
        api.assetsSummary(controller.signal),
        api.assets(controller.signal, filters),
        api.assetGroups(controller.signal),
      ]);
      setFreshness(summary.generated_at || assets.generated_at);
      render();
    } catch (error) {
      if (error.name !== "AbortError") root.innerHTML = errorState(error);
    }
  }

  async function loadAssetsOnly() {
    controller?.abort();
    controller = new AbortController();
    loadingTable = true;
    render();
    try {
      assets = await api.assets(controller.signal, filters);
      setFreshness(assets.generated_at);
    } catch (error) {
      if (error.name !== "AbortError") toast(error.message, "error");
    } finally {
      loadingTable = false;
      render();
    }
  }

  async function load() {
    return summary ? loadAssetsOnly() : loadInitial();
  }

  const debouncedSearch = debounce(() => {
    filters.page = 1;
    filters.query = root.querySelector("#assetSearch")?.value || "";
    load();
  }, 220);

  function bind(data) {
    root.querySelector("#assetSearch")?.addEventListener("input", debouncedSearch);
    root.querySelector("#assetScanStatus")?.addEventListener("change", (event) => { filters.scan_status = event.target.value; filters.page = 1; load(); });
    root.querySelector("#assetProbeStatus")?.addEventListener("change", (event) => { filters.probe_status = event.target.value; filters.page = 1; load(); });
    root.querySelector("#assetScopeStatus")?.addEventListener("change", (event) => { filters.scope_status = event.target.value; filters.page = 1; load(); });
    root.querySelector("#assetPlatform")?.addEventListener("change", (event) => { filters.platform = event.target.value; filters.group = ""; filters.page = 1; load(); });
    root.querySelector("#assetGroup")?.addEventListener("change", (event) => { filters.group = event.target.value; filters.platform = ""; filters.page = 1; load(); });
    root.querySelector("#assetSort")?.addEventListener("change", (event) => { filters.sort = event.target.value; filters.page = 1; load(); });
    root.querySelector("#assetPrevPage")?.addEventListener("click", () => { filters.page = Math.max(1, filters.page - 1); load(); });
    root.querySelector("#assetNextPage")?.addEventListener("click", () => { filters.page = Math.min(Number(data.pages || 1), filters.page + 1); load(); });
    root.querySelectorAll("[data-asset-id]").forEach((button) => button.addEventListener("click", () => openAsset(button.dataset.assetId)));
  }

  setRefreshHandler(async () => {
    [summary, groups] = await Promise.all([api.assetsSummary(), api.assetGroups()]);
    await loadAssetsOnly();
  });
  loadInitial();
  return () => controller?.abort();
}
