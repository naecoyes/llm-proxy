import { api } from "../api.js";
import { badge, confirmAction, emptyState, errorState, metric, openDrawer, panel, skeleton, toast } from "../components.js";
import { debounce, escapeHtml, formatNumber } from "../utils.js";

const severityTone = { CRITICAL: "danger", HIGH: "warning", MEDIUM: "warning", LOW: "success", INFO: "info", UNKNOWN: "info" };
const VULN_COPY_PROMPT = `You are a senior security engineer and vulnerability reproduction analysis expert. Please perform a security verification analysis on the following vulnerability to determine whether it is a false positive. All non-data-deletion operations are within the authorized scope.

Focus your analysis on:

1. Whether the vulnerability description is logically consistent
2. Whether there is a possibility of misjudgment (configuration issues, normal permission behavior, cache/business logic misunderstanding, etc.)
3. Whether real attack conditions exist
4. Whether the impact scope is exaggerated or misunderstood
5. Actual testing verification is required; do not judge solely based on the report content

Testing requirements:

- Use proxy 127.0.0.1:8080 for all test requests
- Analyze actual traffic through Burp Suite packet capture

Output requirements:

- Whether it is a false positive (Yes / No / Uncertain)
- Basis for judgment
- Actual testing process and results

Vulnerability content to analyze:
`;

function fullNumber(value = 0) {
  return new Intl.NumberFormat("en-US").format(Number(value) || 0);
}

function safeMarkdown(markdown = "") {
  const lines = String(markdown).replaceAll("\r\n", "\n").split("\n");
  const output = [];
  let code = false;
  let list = false;
  for (const raw of lines) {
    if (raw.trim().startsWith("```")) {
      if (list) { output.push("</ul>"); list = false; }
      output.push(code ? "</code></pre>" : "<pre><code>");
      code = !code;
      continue;
    }
    const line = escapeHtml(raw);
    if (code) { output.push(`${line}\n`); continue; }
    if (line.startsWith("### ")) output.push(`<h3>${line.slice(4)}</h3>`);
    else if (line.startsWith("## ")) output.push(`<h2>${line.slice(3)}</h2>`);
    else if (line.startsWith("# ")) output.push(`<h1>${line.slice(2)}</h1>`);
    else if (/^[-*] /.test(line)) {
      if (!list) { output.push("<ul>"); list = true; }
      output.push(`<li>${line.slice(2)}</li>`);
    } else {
      if (list) { output.push("</ul>"); list = false; }
      if (!line.trim()) output.push("<br>");
      else if (line.startsWith("&gt; ")) output.push(`<blockquote>${line.slice(5)}</blockquote>`);
      else output.push(`<p>${line.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")}</p>`);
    }
  }
  if (list) output.push("</ul>");
  if (code) output.push("</code></pre>");
  return output.join("");
}

function stateBadges(item) {
  const labels = [];
  if (item.state?.unread) labels.push(badge("Unread", "info"));
  if (item.state?.marked) labels.push(badge("Marked", "warning"));
  if (item.state?.starred) labels.push(badge("Verified", "success"));
  if (item.state?.verified === false) labels.push(badge("False positive", "danger"));
  if (item.state?.verified === true && !item.state?.starred) labels.push(badge("Reviewed", "success"));
  if (item.state?.archived) labels.push(badge("Archived", "info"));
  return labels.join(" ");
}

function rowActions(item) {
  const archived = item.state?.archived;
  const starred = item.state?.starred;
  return `<div class="finding-row-actions" aria-label="Finding actions">
    <button class="finding-action-pill finding-open" type="button" data-record-id="${item.record_id}">Open</button>
    <button class="finding-action-pill" type="button" data-row-action="star" data-record-id="${item.record_id}">${starred ? "Unverify" : "Verify"}</button>
    <button class="finding-action-pill" type="button" data-row-action="archive" data-record-id="${item.record_id}">${archived ? "Restore" : "Archive"}</button>
  </div>`;
}

function renderMetrics(summary) {
  return `<div class="metrics-grid findings-metrics single-row">
    ${metric("Total", fullNumber(summary.total), `${fullNumber(summary.targets)} targets`)}
    ${metric("Critical", fullNumber(summary.critical), "Immediate review", summary.critical ? "critical" : "")}
    ${metric("High", fullNumber(summary.high), "High-impact findings", summary.high ? "warning" : "")}
    ${metric("Unread", fullNumber(summary.unread), `${fullNumber(summary.archived)} archived`)}
    ${metric("Verified", fullNumber(summary.verified), "Confirmed findings")}
  </div>`;
}

function renderToolbar(summary, filters) {
  const sources = Object.keys(summary.sources || {}).sort();
  const sortValue = `${filters.sort}:${filters.order}`;
  return `<div class="findings-toolbar">
    <label class="search-field grow"><span class="sr-only">Search findings</span><input class="input" id="findingSearch" value="${escapeHtml(filters.q)}" placeholder="Search target, title, ID, or source"></label>
    <select class="select" id="findingSeverity" aria-label="Severity"><option value="">All severities</option>${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].map(value => `<option ${filters.severity === value ? "selected" : ""}>${value}</option>`).join("")}</select>
    <select class="select" id="findingStatus" aria-label="Review status"><option value="">All states</option>${[["needs-review", "Needs review"], ["unread", "Unread"], ["marked", "Marked"], ["verified", "Verified"], ["false-positive", "False positive"], ["archived", "Archived"], ["unarchived", "All unarchived"]].map(([value, label]) => `<option value="${value}" ${filters.status === value ? "selected" : ""}>${label}</option>`).join("")}</select>
    <select class="select" id="findingSource" aria-label="Source"><option value="">All sources</option>${sources.map(value => `<option value="${escapeHtml(value)}" ${filters.source === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}</select>
    <select class="select" id="findingSort" aria-label="Sort findings">
      ${[
        ["legacy:asc", "Legacy priority"],
        ["severity:asc", "Severity then CVSS"],
        ["cvss:desc", "CVSS high to low"],
        ["timestamp:desc", "Newest first"],
        ["timestamp:asc", "Oldest first"],
        ["verified_at:desc", "Verified recently"],
        ["target:asc", "Target A-Z"],
      ].map(([value, label]) => `<option value="${value}" ${sortValue === value ? "selected" : ""}>${label}</option>`).join("")}
    </select>
  </div>`;
}

function renderTable(data, selected) {
  if (!data.items?.length) return emptyState("No findings match these filters", "Adjust the filters or refresh the report index.");
  const rows = data.items.map(item => `<tr data-record-id="${item.record_id}" class="finding-row ${item.state?.unread ? "is-unread" : ""}" tabindex="0" role="button" aria-label="Open finding ${escapeHtml(item.title)}">
    <td><input class="finding-select" type="checkbox" value="${item.record_id}" ${selected.has(item.record_id) ? "checked" : ""} aria-label="Select ${escapeHtml(item.title)}"></td>
    <td>${badge(item.severity, severityTone[item.severity])}${item.is_high_value ? `<span class="high-value-mark" title="High value">★</span>` : ""}</td>
    <td><div class="cell-primary finding-target-id break-anywhere">${escapeHtml(item.target || "Unknown")}</div><div class="cell-secondary">${escapeHtml(item.id || "-")}</div></td>
    <td><strong class="finding-title-text break-anywhere">${escapeHtml(item.title)}</strong><div class="cell-secondary break-anywhere">${escapeHtml(item.source_file || "")}</div></td>
    <td><div>${escapeHtml(item.cvss || "-")}</div><div class="cell-secondary">${escapeHtml(item.timestamp || "-")}</div></td>
    <td><div class="finding-state-stack">${stateBadges(item)}${rowActions(item)}</div></td>
  </tr>`).join("");
  return `<div class="bulk-bar" ${selected.size ? "" : "hidden"}><strong>${selected.size} selected</strong><button class="button secondary small" data-bulk-action="read">Mark read</button><button class="button secondary small" data-bulk-action="verify">Verify</button><button class="button secondary small" data-bulk-action="archive">Archive</button></div>
    <div class="table-scroll"><table class="data-table findings-table"><thead><tr><th><input id="findingsSelectPage" type="checkbox" aria-label="Select this page"></th><th>Severity</th><th>Target</th><th>Finding</th><th>CVSS / Found</th><th>State / Actions</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="pagination-row"><button class="button secondary small" id="findingsPrevious" ${data.page <= 1 ? "disabled" : ""}>Previous</button><span>Page ${data.page} of ${data.pages} · ${fullNumber(data.total)} findings</span><button class="button secondary small" id="findingsNext" ${data.page >= data.pages ? "disabled" : ""}>Next</button></div>`;
}

function renderTargets(targets) {
  if (!targets.length) return emptyState("No target analysis available");
  return `<div class="table-scroll"><table class="data-table compact"><thead><tr><th>Target</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>${targets.map(item => `<tr><td><button class="link-button target-filter" data-target="${escapeHtml(item.target)}">${escapeHtml(item.target)}</button></td><td>${item.total}</td><td>${item.critical}</td><td>${item.high}</td><td>${item.medium}</td><td>${item.low}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderReports(reports) {
  if (!reports.length) return emptyState("No consolidated reports found");
  return `<div class="report-grid">${reports.map(report => `<button class="report-card" type="button" data-report-id="${report.report_id}"><strong>${escapeHtml(report.name.replace(/\.md$/i, "").replaceAll("_", " "))}</strong><span>${escapeHtml(report.name)}</span></button>`).join("")}</div>`;
}

function relatedFindingsSection(item, related = [], loading = false, error = "") {
  if (!item.target) return "";
  if (loading) {
    return `<section class="related-findings"><header><h3>Other findings on this target</h3><span>Loading...</span></header><div class="skeleton" style="height:90px"></div></section>`;
  }
  if (error) {
    return `<section class="related-findings"><header><h3>Other findings on this target</h3><span class="muted">Unavailable</span></header><div class="alert warning">${escapeHtml(error)}</div></section>`;
  }
  if (!related.length) {
    return `<section class="related-findings"><header><h3>Other findings on this target</h3><span class="muted">No other records</span></header>${emptyState("No other findings for this target")}</section>`;
  }
  return `<section class="related-findings">
    <header><h3>Other findings on this target</h3><span>${fullNumber(related.length)} shown</span></header>
    <div class="related-finding-list">${related.map((entry) => `<button class="related-finding-row" type="button" data-related-record-id="${escapeHtml(entry.record_id)}">
      <span>${badge(entry.severity, severityTone[entry.severity])}</span>
      <strong class="break-anywhere">${escapeHtml(entry.title || entry.id || "Finding")}</strong>
      <span class="related-finding-side"><small>${escapeHtml(entry.cvss ? `CVSS ${entry.cvss}` : entry.id || "")}</small><span class="related-finding-status">${stateBadges(entry)}</span></span>
    </button>`).join("")}</div>
  </section>`;
}

function findingDrawer(item, markdown = "", loading = false, related = [], relatedLoading = false, relatedError = "") {
  const reportActions = [];
  if (item.has_report) reportActions.push(`<a class="button secondary small" href="/proxy/vulnerabilities/${item.record_id}/content?download=true">Download Markdown</a>`);
  if (markdown) reportActions.push('<button class="button secondary small" type="button" data-copy-prompt>Copy prompt</button>');
  return `<div class="finding-detail">
    <div class="finding-detail-meta"><div>${badge(item.severity, severityTone[item.severity])} ${item.is_high_value ? badge("High value", "warning") : ""}</div><dl><dt>Target</dt><dd>${escapeHtml(item.target || "Unknown")}</dd><dt>ID</dt><dd>${escapeHtml(item.id || "-")}</dd><dt>CVSS</dt><dd>${escapeHtml(item.cvss || "-")}</dd><dt>Source</dt><dd>${escapeHtml(item.source_file || "-")}</dd><dt>Found</dt><dd>${escapeHtml(item.timestamp || "-")}</dd></dl></div>
    <div class="finding-actions"><button class="button secondary small" data-finding-action="star">${item.state?.starred ? "Unverify" : "Verify"}</button><button class="button secondary small" data-finding-action="mark">${item.state?.marked ? "Unmark" : "Mark"}</button><button class="button secondary small" data-finding-action="false-positive">False positive</button><button class="button secondary small" data-finding-action="archive">${item.state?.archived ? "Restore" : "Archive"}</button></div>
    <div class="finding-report-actions">${reportActions.join("")}</div>
    <article class="markdown-content">${loading ? '<div class="skeleton" style="height:220px"></div>' : markdown ? safeMarkdown(markdown) : emptyState("No report body linked", "The finding metadata remains available.")}</article>
    ${relatedFindingsSection(item, related, relatedLoading, relatedError)}
  </div>`;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

export function mountFindings({ root, setFreshness, setRefreshHandler, setTopbarActions }) {
  const filters = { page: 1, page_size: 50, q: "", severity: "", source: "", status: "needs-review", target: "", sort: "legacy", order: "asc" };
  const selected = new Set();
  let summary = null;
  let targets = [];
  let reports = [];
  let data = null;
  let activeTab = "findings";
  let controller = null;
  let pollTimer = null;
  let fullscreen = localStorage.getItem("nscan-findings-fullscreen") === "true";

  root.innerHTML = skeleton(4);
  function applyFullscreen() {
    document.body.classList.toggle("findings-fullscreen", fullscreen);
    localStorage.setItem("nscan-findings-fullscreen", String(fullscreen));
    const button = document.getElementById("findingsFullscreen");
    if (button) button.querySelector("span").textContent = fullscreen ? "Exit full view" : "Full view";
  }

  function renderActions() {
    setTopbarActions(`<button class="button secondary" id="findingsFullscreen" type="button"><span>${fullscreen ? "Exit full view" : "Full view"}</span></button><a class="button secondary" href="/proxy/vulnerabilities/export?format=csv">Export CSV</a><button class="button secondary" id="findingsAutoClean" type="button">Auto-clean</button>`);
    document.getElementById("findingsFullscreen")?.addEventListener("click", () => {
      fullscreen = !fullscreen;
      applyFullscreen();
    });
    document.getElementById("findingsAutoClean")?.addEventListener("click", async () => {
      const confirmed = await confirmAction({ title: "Auto-clean findings", message: "Archive likely low-value false positives and tag duplicates using the existing viewer rules?", confirmLabel: "Run auto-clean" });
      if (!confirmed) return;
      try { const result = await api.autocleanFindings(); toast(`Auto-clean archived ${result.auto_archived || 0} findings`); await loadAll(); } catch (error) { toast(error.message, "error"); }
    });
    applyFullscreen();
  }
  renderActions();

  function render() {
    renderActions();
    root.innerHTML = `<div class="page-stack findings-page">${renderMetrics(summary)}
      ${summary.index_error ? `<div class="alert warning">Index refresh warning: ${escapeHtml(summary.index_error)}</div>` : ""}
      <div class="view-tabs" role="tablist"><button class="view-tab ${activeTab === "findings" ? "active" : ""}" data-findings-tab="findings">Findings</button><button class="view-tab ${activeTab === "marked" ? "active" : ""}" data-findings-tab="marked">Marked</button><button class="view-tab ${activeTab === "verified" ? "active" : ""}" data-findings-tab="verified">Verified</button><button class="view-tab ${activeTab === "targets" ? "active" : ""}" data-findings-tab="targets">Target Analysis</button><button class="view-tab ${activeTab === "reports" ? "active" : ""}" data-findings-tab="reports">Reports</button></div>
      <div id="findingsTabContent">${activeTab === "findings" ? panel("Vulnerability findings", "Needs-review findings only; Verified and False positive findings are hidden", `${renderToolbar(summary, filters)}<div id="findingsTableRegion">${renderTable(data, selected)}</div>`, '<a class="button secondary small" href="#scans">Open scans</a>') : activeTab === "marked" ? panel("Marked findings", "Findings saved for focused review", `${renderToolbar(summary, filters)}<div id="findingsTableRegion">${renderTable(data, selected)}</div>`) : activeTab === "verified" ? panel("Verified findings", "Confirmed findings ordered by verification time, newest first", `${renderToolbar(summary, filters)}<div id="findingsTableRegion">${renderTable(data, selected)}</div>`) : activeTab === "targets" ? panel("Target analysis", "Finding counts grouped by target", renderTargets(targets)) : panel("Consolidated reports", "Existing Markdown reports referenced from the legacy report directory", renderReports(reports))}</div>
    </div>`;
    bindEvents();
  }

  async function loadList() {
    data = await api.findings(controller?.signal, filters);
    setFreshness(data.generated_at);
  }

  async function loadSummary() {
    summary = await api.findingsSummary(controller?.signal);
  }

  async function loadAll(manual = false) {
    controller?.abort();
    controller = new AbortController();
    try {
      if (manual) await api.refreshFindings();
      // Bootstrap: summary + first-page list in one request (was 4 separate parallel requests)
      const boot = await api.findingsBootstrap(controller.signal, {
        page: filters.page,
        page_size: filters.page_size || 50,
        q: filters.q || "",
        severity: filters.severity || "",
        status: filters.status || "needs-review",
        sort: filters.sort || "legacy",
        order: filters.order || "asc",
      });
      summary = boot.summary;
      data = boot.records;
      setFreshness(data.generated_at);
      // targets and reports are lazy — only load if we're already on those tabs
      if (activeTab === "targets" && !targets.length) {
        targets = await api.findingTargets(controller.signal).then(v => v.targets || []).catch(() => []);
      }
      if (activeTab === "reports" && !reports.length) {
        reports = await api.findingReports(controller.signal).then(v => v.reports || []).catch(() => []);
      }
      render();
    } catch (error) {
      if (error.name !== "AbortError") root.innerHTML = errorState(error);
    }
  }

  async function mutate(recordIds, actions, message) {
    try {
      await api.bulkFindingState(recordIds, actions);
      selected.clear();
      // Only reload summary + list (not targets/reports) — much cheaper than loadAll()
      [summary] = await Promise.all([api.findingsSummary(), loadList()]);
      render();
      toast(message);
    } catch (error) { toast(error.message, "error"); }
  }

  async function updateRowState(recordId, action) {
    const item = data?.items?.find(entry => entry.record_id === recordId) || await api.finding(recordId);
    const actions = action === "star"
      ? { star: !item.state?.starred }
      : { archive: !item.state?.archived };
    try {
      await api.updateFindingState(recordId, actions);
      // Only reload summary + list (not targets/reports)
      [summary] = await Promise.all([api.findingsSummary(), loadList()]);
      render();
      toast("Finding state updated");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function openFinding(recordId) {
    try {
      let item = await api.finding(recordId);
      openDrawer({
        title: item.title,
        subtitle: `${item.target || "Unknown"} · ${item.id || "-"}`,
        body: findingDrawer(item, "", true),
        onOpen: drawer => { drawer.classList.add("finding-detail-drawer"); bindDrawer(drawer, item); },
        onClose: () => document.getElementById("drawer")?.classList.remove("finding-detail-drawer"),
      });
      if (item.state?.unread) api.updateFindingState(recordId, { read: true }).catch(() => {});
      const content = item.has_report ? await api.findingContent(recordId) : { content: "" };
      item = await api.finding(recordId);
      const body = document.getElementById("drawerBody");
      body.innerHTML = findingDrawer(item, content.content || "", false, [], true);
      bindDrawer(document.getElementById("drawer"), item, content.content || "");
      try {
        const relatedData = item.target
          ? await api.findings(undefined, { target: item.target, page: 1, page_size: 13, sort: "legacy", order: "asc" })
          : { items: [] };
        const related = (relatedData.items || []).filter(entry => entry.record_id !== item.record_id).slice(0, 12);
        body.innerHTML = findingDrawer(item, content.content || "", false, related, false);
        bindDrawer(document.getElementById("drawer"), item, content.content || "");
      } catch (relatedError) {
        body.innerHTML = findingDrawer(item, content.content || "", false, [], false, relatedError.message || String(relatedError));
        bindDrawer(document.getElementById("drawer"), item, content.content || "");
      }
    } catch (error) { toast(error.message, "error"); }
  }

  function bindDrawer(drawer, item, markdown = "") {
    drawer.querySelectorAll("[data-finding-action]").forEach(button => button.addEventListener("click", async () => {
      const action = button.dataset.findingAction;
      const actions = action === "star" ? { star: !item.state.starred } : action === "mark" ? { mark: !item.state.marked } : action === "false-positive" ? { verified: false } : { archive: !item.state.archived };
      try { await api.updateFindingState(item.record_id, actions); toast("Finding state updated"); await openFinding(item.record_id); await loadAll(); } catch (error) { toast(error.message, "error"); }
    }));
    drawer.querySelector("[data-copy-prompt]")?.addEventListener("click", async () => {
      try { await copyText(VULN_COPY_PROMPT + markdown); toast("Verification prompt copied"); } catch (error) { toast(error.message, "error"); }
    });
    drawer.querySelectorAll("[data-related-record-id]").forEach(button => button.addEventListener("click", () => openFinding(button.dataset.relatedRecordId)));
  }

  async function openReport(reportId) {
    try {
      const report = await api.findingReport(reportId);
      openDrawer({
        title: report.filename,
        subtitle: "Consolidated vulnerability report",
        body: `<div class="finding-report-actions"><button class="button secondary small" type="button" data-copy-report>Copy report</button><a class="button secondary small" href="/proxy/vulnerability-reports/${reportId}?download=true">Download Markdown</a></div><article class="markdown-content">${safeMarkdown(report.content)}</article>`,
        onOpen: drawer => drawer.querySelector("[data-copy-report]")?.addEventListener("click", async () => {
          try { await copyText(report.content || ""); toast("Report copied"); } catch (error) { toast(error.message, "error"); }
        }),
      });
    } catch (error) { toast(error.message, "error"); }
  }

  function bindEvents() {
    root.querySelectorAll("[data-findings-tab]").forEach(button => button.addEventListener("click", async () => {
      activeTab = button.dataset.findingsTab;
      if (activeTab === "findings") {
        filters.status = "needs-review";
        filters.sort = "legacy";
        filters.order = "asc";
        filters.page = 1;
        selected.clear();
        await loadList();
      } else if (activeTab === "verified") {
        filters.status = "verified";
        filters.sort = "verified_at";
        filters.order = "desc";
        filters.page = 1;
        selected.clear();
        await loadList();
      } else if (activeTab === "marked") {
        filters.status = "marked";
        filters.sort = "legacy";
        filters.order = "asc";
        filters.page = 1;
        selected.clear();
        await loadList();
      } else if (activeTab === "targets" && !targets.length) {
        // Lazy-load targets only when tab is first opened
        targets = await api.findingTargets(controller?.signal).then(v => v.targets || []).catch(() => []);
      } else if (activeTab === "reports" && !reports.length) {
        // Lazy-load reports only when tab is first opened
        reports = await api.findingReports(controller?.signal).then(v => v.reports || []).catch(() => []);
      }
      render();
    }));
    const search = root.querySelector("#findingSearch");
    search?.addEventListener("input", debounce(async event => { filters.q = event.target.value; filters.page = 1; await loadList(); render(); }, 250));
    [["#findingSeverity", "severity"], ["#findingStatus", "status"], ["#findingSource", "source"]].forEach(([selector, key]) => root.querySelector(selector)?.addEventListener("change", async event => {
      filters[key] = event.target.value;
      if (key === "status") {
        activeTab = filters.status === "verified" ? "verified" : filters.status === "marked" ? "marked" : "findings";
        if (filters.status === "verified") {
          filters.sort = "verified_at";
          filters.order = "desc";
        }
      }
      filters.page = 1;
      await loadList();
      render();
    }));
    root.querySelector("#findingSort")?.addEventListener("change", async event => {
      const [sort, order] = event.target.value.split(":");
      filters.sort = sort || "timestamp";
      filters.order = order || "desc";
      filters.page = 1;
      await loadList();
      render();
    });
    root.querySelectorAll(".finding-row").forEach(row => {
      row.addEventListener("click", event => {
        if (event.target.closest("button, input, select, a")) return;
        openFinding(row.dataset.recordId);
      });
      row.addEventListener("keydown", event => {
        if (event.target.closest("button, input, select, a")) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openFinding(row.dataset.recordId);
        }
      });
    });
    root.querySelectorAll(".finding-open").forEach(button => button.addEventListener("click", () => openFinding(button.dataset.recordId)));
    root.querySelectorAll("[data-row-action]").forEach(button => button.addEventListener("click", event => { event.stopPropagation(); updateRowState(button.dataset.recordId, button.dataset.rowAction); }));
    root.querySelectorAll(".finding-select").forEach(input => input.addEventListener("change", event => { event.stopPropagation(); input.checked ? selected.add(input.value) : selected.delete(input.value); render(); }));
    root.querySelector("#findingsSelectPage")?.addEventListener("change", event => { data.items.forEach(item => event.target.checked ? selected.add(item.record_id) : selected.delete(item.record_id)); render(); });
    root.querySelector("#findingsPrevious")?.addEventListener("click", async () => { filters.page -= 1; await loadList(); render(); });
    root.querySelector("#findingsNext")?.addEventListener("click", async () => { filters.page += 1; await loadList(); render(); });
    root.querySelectorAll("[data-bulk-action]").forEach(button => button.addEventListener("click", async () => {
      const action = button.dataset.bulkAction;
      const confirmed = await confirmAction({ title: `Bulk ${action}`, message: `Apply this action to ${selected.size} selected findings?`, confirmLabel: "Apply", danger: action === "archive" });
      if (confirmed) await mutate([...selected], action === "read" ? { read: true } : action === "verify" ? { star: true } : { archive: true }, "Selected findings updated");
    }));
    root.querySelectorAll(".target-filter").forEach(button => button.addEventListener("click", async () => { filters.target = button.dataset.target; filters.status = "needs-review"; filters.page = 1; activeTab = "findings"; await loadList(); render(); }));
    root.querySelectorAll("[data-report-id]").forEach(button => button.addEventListener("click", () => openReport(button.dataset.reportId)));
  }

  setRefreshHandler(() => loadAll(true));
  loadAll();
  // 60s poll: only refresh summary+list (NOT targets/reports), avoiding full 4-request reload
  pollTimer = setInterval(() => { if (!document.hidden) Promise.all([loadSummary(), loadList()]).then(render).catch(() => {}); }, 60000);
  return () => {
    controller?.abort();
    clearInterval(pollTimer);
    document.body.classList.remove("findings-fullscreen");
  };
}
