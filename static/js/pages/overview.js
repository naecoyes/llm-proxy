import { api } from "../api.js";
import { Poller } from "../poller.js";
import { badge, emptyState, errorState, modelIdentity, progress, skeleton } from "../components.js";
import { escapeHtml, formatBytes, formatDate, formatDuration, formatNumber, formatRate, relativeTime } from "../utils.js";

function clamp(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}

function healthCopy(data) {
  if (data.health === "critical") return { label: "Attention required", heading: "Nscan needs attention", tone: "danger", detail: "One or more scan safety signals need action." };
  if (data.health === "warning") return { label: "Watch closely", heading: "Nscan is degraded", tone: "warning", detail: "Scanning can continue, but throughput or confidence is degraded." };
  return { label: "Protected", heading: "Nscan is protected", tone: "success", detail: "Scan egress, models, and host signals are inside the expected boundary." };
}

function activeCounts(data) {
  const scans = data.scans?.summary || {};
  return {
    total: scans.total_tasks || 0,
    running: scans.running_tasks || 0,
    pending: scans.pending_tasks || 0,
    retryPending: scans.retry_pending_tasks || 0,
    success: scans.successful_tasks || 0,
    failed: scans.failed_tasks || 0,
    timeout: scans.timeout_tasks || 0,
    progress: clamp(scans.overall_progress_percent || 0),
  };
}

function hostPressure(resources = {}) {
  if (!resources.available) return { value: 0, label: "Unknown", detail: "Resource monitor unavailable", tone: "warning" };
  const projectDisk = resources.disk?.project || {};
  const value = Math.max(resources.cpu?.percent || 0, resources.memory?.percent || 0, projectDisk.percent || 0);
  return {
    value,
    label: `${value.toFixed(0)}%`,
    detail: `CPU ${Number(resources.cpu?.percent || 0).toFixed(0)}% · MEM ${Number(resources.memory?.percent || 0).toFixed(0)}% · Disk ${Number(projectDisk.percent || 0).toFixed(0)}%`,
    tone: value >= 90 ? "danger" : value >= 75 ? "warning" : "success",
  };
}

function resourceTone(value) {
  const number = Number(value) || 0;
  if (number >= 90) return "danger";
  if (number >= 75) return "warning";
  return "success";
}

function renderResourceMeter(label, value, detail) {
  const percent = clamp(value);
  return `<div class="resource-meter ${resourceTone(percent)} overview-resource-meter">
    <header><span>${escapeHtml(label)}</span><strong>${formatNumber(percent, 0)}%</strong></header>
    ${progress(percent)}
    <p>${escapeHtml(detail)}</p>
  </div>`;
}

function renderHostResources(resources = {}) {
  if (!resources.available) {
    return `<section class="overview-card overview-resource-card">
      <header><div><h2>Host Resources</h2><p>Server pressure for the Nscan runtime</p></div></header>
      ${emptyState("Resource monitor unavailable", "Install psutil or check the service environment.")}
    </section>`;
  }
  const cpu = resources.cpu || {};
  const memory = resources.memory || {};
  const rootDisk = resources.disk?.root || {};
  const homeDisk = resources.disk?.project || {};
  const load = Array.isArray(cpu.load_avg) ? Number(cpu.load_avg[0] || 0) : 0;
  const logicalCores = Number(cpu.count_logical || 1) || 1;
  const loadPercent = clamp((load / logicalCores) * 100);
  return `<section class="overview-card overview-resource-card">
    <header>
      <div><h2>Host Resources</h2><p>CPU, memory, disk, and load for the 8888 Nscan host</p></div>
      <span class="muted">Updated ${escapeHtml(relativeTime(resources.generated_at))}</span>
    </header>
    <div class="overview-resource-grid">
      ${renderResourceMeter("CPU", cpu.percent || 0, `${cpu.count_logical || "-"} logical cores`)}
      ${renderResourceMeter("Memory", memory.percent || 0, `${formatBytes(memory.used || 0)} used / ${formatBytes(memory.total || 0)}`)}
      ${renderResourceMeter("Root disk /", rootDisk.percent || 0, `${formatBytes(rootDisk.used || 0)} used / ${formatBytes(rootDisk.total || 0)} · ${formatBytes(rootDisk.free || 0)} free`)}
      ${renderResourceMeter("Home disk /home", homeDisk.percent || 0, `${formatBytes(homeDisk.used || 0)} used / ${formatBytes(homeDisk.total || 0)} · ${formatBytes(homeDisk.free || 0)} free`)}
      ${renderResourceMeter("Load", loadPercent, `${load.toFixed(2)} load avg / ${logicalCores} cores`)}
    </div>
  </section>`;
}

function readinessItems(data, telemetryState) {
  const resources = hostPressure(data.resources || {});
  const bridge = data.egress_usage?.bridge || {};
  const bridgeRate = (Number(bridge.rx_bps) || 0) + (Number(bridge.tx_bps) || 0);
  return [
    {
      title: "Egress",
      value: data.egress?.enabled && data.egress?.boundary_ok ? "Protected" : "Check",
      detail: data.egress?.boundary_ok ? `${data.egress.active_nodes || 0}/${data.egress.total_nodes || 0} proxy nodes` : "Boundary mismatch",
      tone: data.egress?.enabled && data.egress?.boundary_ok ? "success" : "danger",
      href: "#egress",
    },
    {
      title: "Models",
      value: `${data.models?.eligible || 0} ready`,
      detail: `${data.models?.healthy || 0}/${data.models?.enabled || 0} healthy · ${escapeHtml(data.models?.routing_mode || "-")}`,
      tone: data.models?.eligible > 0 ? "success" : "danger",
      href: "#models",
    },
    {
      title: "Proxy traffic",
      value: telemetryState === "loading" ? "Sampling" : telemetryState === "error" ? "Unavailable" : formatRate(bridgeRate),
      detail: telemetryState === "ready" ? `RX ${formatRate(bridge.rx_bps || 0)} · TX ${formatRate(bridge.tx_bps || 0)}` : "Bridge/container telemetry",
      tone: telemetryState === "error" ? "warning" : "success",
      href: "#egress",
    },
    {
      title: "Host",
      value: resources.label,
      detail: resources.detail,
      tone: resources.tone,
      href: "#settings",
    },
    {
      title: "Access",
      value: data.security?.pin?.configured && data.security?.ip_whitelist?.configured ? "Locked" : "Review",
      detail: `${data.security?.ip_whitelist?.count || 0} allowed IPs · PIN ${data.security?.pin?.configured ? "set" : "missing"}`,
      tone: data.security?.pin?.configured && data.security?.ip_whitelist?.configured ? "success" : "warning",
      href: "#settings",
    },
  ];
}

function renderProgressRing(counts) {
  return `<div class="overview-ring" style="--value:${counts.progress}">
    <div class="overview-ring-inner">
      <strong>${formatNumber(counts.progress, 1)}%</strong>
      <span>${counts.success + counts.failed + counts.timeout}/${counts.total || 0} complete</span>
    </div>
  </div>`;
}

function alertPriority(alert = {}) {
  const title = String(alert.title || "").toLowerCase();
  if (alert.severity === "critical" || title.includes("egress") || title.includes("routing boundary")) return 10;
  if (title.includes("orphan")) return 20;
  if (title.includes("disk")) return 30;
  if (title.includes("retry")) return 40;
  if (title.includes("scan failures")) return 50;
  if (title.includes("model")) return 60;
  if (title.includes("stale")) return 70;
  return 90;
}

function sortedAlerts(alerts = []) {
  return [...alerts].sort((a, b) => alertPriority(a) - alertPriority(b));
}

function renderHero(data) {
  const health = healthCopy(data);
  const counts = activeCounts(data);
  const priorityAlerts = sortedAlerts(data.alerts || []);
  const nextAction = priorityAlerts[0]
    ? priorityAlerts[0].title
    : counts.running
      ? "Monitor active scans"
      : counts.pending
        ? "Waiting for scheduler"
        : "Ready for the next batch";
  return `<section class="overview-hero ${health.tone}">
    <div class="overview-hero-copy">
      <div class="overview-eyebrow">${badge(health.label, health.tone)} <span>Updated ${escapeHtml(relativeTime(data.generated_at))}</span></div>
      <h2>${escapeHtml(health.heading)}</h2>
      <p>${escapeHtml(health.detail)}</p>
      <div class="overview-action-line"><span>Next action</span><strong>${escapeHtml(nextAction)}</strong></div>
    </div>
    ${renderProgressRing(counts)}
    <div class="overview-hero-stats">
      <div><span>Running</span><strong>${counts.running}</strong></div>
      <div><span>Queued</span><strong>${counts.pending}</strong></div>
      <div><span>Failed</span><strong>${counts.failed + counts.timeout}</strong></div>
    </div>
  </section>`;
}

function renderScanFlow(data) {
  const counts = activeCounts(data);
  const total = Math.max(1, counts.total);
  const segments = [
    ["Succeeded", counts.success, "success"],
    ["Running", counts.running, "run"],
    ["Queued", counts.pending + counts.retryPending, "wait"],
    ["Failed", counts.failed + counts.timeout, "danger"],
  ];
  return `<section class="overview-card">
    <header><div><h2>Scan Flow</h2><p>Current active batch window</p></div><a class="button secondary small" href="#scans">Open Scans</a></header>
    <div class="flow-bar">${segments.map(([label, value, tone]) => `<span class="${tone}" style="width:${Math.max(2, (value / total) * 100)}%" title="${escapeHtml(label)}: ${value}"></span>`).join("")}</div>
    <div class="flow-legend">${segments.map(([label, value, tone]) => `<div><span class="legend-dot ${tone}"></span><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`).join("")}</div>
  </section>`;
}

function renderAlerts(data) {
  const alerts = [...(data.alerts || [])];
  const orphanContainers = data.egress_usage?.summary?.orphan_containers || data.scans?.containers?.orphan_containers || 0;
  const retryDue = (data.scans?.summary?.retry_due_tasks || 0) + (data.scans?.summary?.auto_requeue_due_tasks || 0);
  if (retryDue) {
    alerts.unshift({ severity: "warning", title: "Retry queue is due", detail: `${retryDue} retry/requeue task(s) are ready to run.` });
  }
  if (orphanContainers) {
    alerts.unshift({ severity: "warning", title: "Orphan scan containers", detail: `${orphanContainers} sandbox container(s) no longer match a live scanner process.` });
  }
  const priorityAlerts = sortedAlerts(alerts);
  return `<section class="overview-card">
    <header><div><h2>Priority Alerts</h2><p>Only conditions that affect safety or throughput</p></div></header>
    <div class="overview-alerts">${priorityAlerts.length ? priorityAlerts.slice(0, 4).map((alert) => `<div class="overview-alert ${escapeHtml(alert.severity || "info")}"><strong>${escapeHtml(alert.title)}</strong><p>${escapeHtml(alert.detail)}</p></div>`).join("") : '<div class="overview-alert success"><strong>No action required</strong><p>Safety boundary, model routing, and host pressure are currently acceptable.</p></div>'}</div>
  </section>`;
}

function renderActiveTasks(tasks = []) {
  return `<section class="overview-card">
    <header><div><h2>Now Running</h2><p>Live targets with model attribution</p></div><a class="button secondary small" href="#scanHistory">History</a></header>
    ${tasks.length ? `<div class="overview-task-list">${tasks.slice(0, 5).map((task) => {
      const seconds = task.duration_seconds || ((Date.now() - new Date(task.started_at || Date.now()).getTime()) / 1000);
      return `<div class="overview-task">
        <div><strong>${escapeHtml(task.target || "-")}</strong><span class="mono">${escapeHtml(task.scan_id || "-")}</span></div>
        <div>${modelIdentity({ name: task.llm_model_primary || task.proxy_model_alias || "awaiting request", provider: task.llm_model_provider || "" }, { compact: true, secondary: `${formatDuration(seconds)} · PID ${escapeHtml(task.strix_pid || "-")}` })}</div>
      </div>`;
    }).join("")}</div>` : emptyState("No live targets", "Submit or resume a batch from the Scans page.")}
  </section>`;
}

function renderReadiness(data, telemetryState) {
  return `<section class="overview-card overview-readiness-card">
    <header><div><h2>Readiness</h2><p>Scan-safe dependencies at a glance</p></div></header>
    <div class="readiness-grid">${readinessItems(data, telemetryState).map((item) => `<a class="readiness-item ${item.tone}" href="${item.href}">
      <span>${escapeHtml(item.title)}</span>
      <strong>${escapeHtml(item.value)}</strong>
      <p>${item.detail}</p>
    </a>`).join("")}</div>
  </section>`;
}

function renderOverview(data, telemetryState = "ready") {
  return `<div class="page-stack overview-page">
    ${renderHero(data)}
    ${renderHostResources(data.resources || {})}
    <div class="overview-main-grid">
      ${renderScanFlow(data)}
      ${renderAlerts(data)}
    </div>
    <div class="overview-main-grid">
      ${renderActiveTasks(data.scans?.active_tasks || [])}
      ${renderReadiness(data, telemetryState)}
    </div>
  </div>`;
}

export function mountOverview(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(4);
  let lastData = null;
  const load = async (signal) => {
    const data = await api.summary(signal, false);
    lastData = data;
    root.innerHTML = renderOverview(data, "loading");
    setFreshness(data.generated_at);
    try {
      const egressUsage = await api.egressUsage(signal);
      lastData = { ...data, egress_usage: egressUsage };
      root.innerHTML = renderOverview(lastData, "ready");
      setFreshness(egressUsage.generated_at || data.generated_at);
    } catch (error) {
      if (error.name === "AbortError") throw error;
      root.innerHTML = renderOverview(data, "error");
    }
  };
  const poller = new Poller(10000, load, (error) => {
    if (!lastData) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  return () => poller.stop();
}
