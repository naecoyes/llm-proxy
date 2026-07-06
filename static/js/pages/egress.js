import { api } from "../api.js";
import { Poller } from "../poller.js";
import { badge, closeDrawer, confirmAction, emptyState, errorState, openDrawer, panel, proxyNodeIdentity, skeleton, toast } from "../components.js";
import { escapeHtml, formatBytes, formatDate, formatRate } from "../utils.js";

const NODE_CHECK_STORAGE_KEY = "nscan.egress.lastNodeCheckAt";
const NODE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

function switchControl(id, checked, label, disabled = false, attributes = "") {
  return `<label class="switch" title="${escapeHtml(label)}"><input id="${id}" type="checkbox" ${checked ? "checked" : ""} ${disabled ? "disabled" : ""} ${attributes}><span class="switch-track"></span><span class="visually-hidden">${escapeHtml(label)}</span></label>`;
}

function shouldRunScheduledNodeCheck() {
  try {
    const last = Number(window.localStorage?.getItem(NODE_CHECK_STORAGE_KEY) || 0);
    return !last || Date.now() - last >= NODE_CHECK_INTERVAL_MS;
  } catch (_error) {
    return false;
  }
}

function rememberScheduledNodeCheck() {
  try {
    window.localStorage?.setItem(NODE_CHECK_STORAGE_KEY, String(Date.now()));
  } catch (_error) {
    // Ignore storage failures; backend also enforces the daily check interval after restart.
  }
}

function renderNodes(runtime) {
  const outbounds = runtime.egress?.outbounds || {};
  const nodes = outbounds.socks_nodes || [];
  if (!nodes.length) return emptyState("No SOCKS5 nodes configured");
  return `<div class="node-list">${nodes.map((node) => {
    const check = node.tcp_check;
    return `<div class="node-row"><div class="node-main"><div class="node-title">${proxyNodeIdentity(node)} ${node.in_auto_pool ? badge("active", "success") : badge("standby")}</div>
      <div class="node-meta"><span class="mono">${escapeHtml(`${node.server}:${node.server_port}`)}</span> · ${escapeHtml(node.region || "Unknown region")} · ${escapeHtml(node.username || "-")} · ${escapeHtml(node.password_masked || "")}</div>
      <div class="node-meta">${check ? `${check.reachable ? "Reachable" : "Unavailable"} · ${check.latency_ms || 0} ms` : "Connectivity not checked"}</div></div>
      <div class="node-actions"><button class="button ghost small" type="button" data-node-edit="${escapeHtml(node.tag)}">Edit</button><button class="button text-danger small" type="button" data-node-delete="${escapeHtml(node.tag)}">Delete</button>${switchControl(`node-${node.tag}`, node.in_auto_pool, `${node.in_auto_pool ? "Disable" : "Enable"} ${node.display_name}`, false, `data-node-tag="${escapeHtml(node.tag)}"`)}</div></div>`;
  }).join("")}</div>`;
}

export function parseProxyInput(raw) {
  const input = String(raw || "").trim();
  if (!input) return null;

  const uriMatch = input.match(/^socks5h?:\/\/([^:\s/@]+):([^\s@]+)@(\[[^\]]+\]|[^:\s/]+):(\d{1,5})\/?$/i);
  if (uriMatch) {
    return { server: uriMatch[3].replace(/^\[|\]$/g, ""), server_port: Number(uriMatch[4]), username: decodeURIComponent(uriMatch[1]), password: decodeURIComponent(uriMatch[2]) };
  }

  const parts = input.split(/\s+/).filter(Boolean);
  if (parts.length === 1) {
    const singleLine = parts[0].match(/^(\[[^\]]+\]|[^:]+):(\d{1,5}):([^:]+):(.+)$/);
    if (singleLine) parts.splice(0, 1, `${singleLine[1]}:${singleLine[2]}`, `${singleLine[3]}:${singleLine[4]}`);
  }
  if (parts.length !== 2) return null;

  const endpoint = parts[0].match(/^(\[[^\]]+\]|[^:]+):(\d{1,5})$/);
  const separator = parts[1].indexOf(":");
  if (!endpoint || separator < 1) return null;
  const serverPort = Number(endpoint[2]);
  if (serverPort < 1 || serverPort > 65535) return null;
  return {
    server: endpoint[1].replace(/^\[|\]$/g, ""),
    server_port: serverPort,
    username: parts[1].slice(0, separator),
    password: parts[1].slice(separator + 1),
  };
}

function suggestedProxyTag(server, port) {
  const safeServer = server.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `proxy-${safeServer || "node"}-${port}`.slice(0, 63);
}

function proxyNodeForm(node = null) {
  const editing = Boolean(node);
  return `<form id="proxyNodeForm" class="form-grid">
    ${editing ? "" : '<label class="field full"><span>Quick paste</span><textarea name="proxy_input" rows="3" placeholder="proxy.example.com:1080\nusername:password"></textarea><small class="field-help">Accepts host:port + username:password on separate lines, host:port:username:password, or a SOCKS5 URL.</small></label>'}
    <label class="field"><span>Tag</span><input name="tag" required ${editing ? "disabled" : ""} value="${escapeHtml(node?.tag || "")}" placeholder="proxy-region-1"></label>
    <label class="field"><span>Display name</span><input name="label" value="${escapeHtml(node?.display_name || "")}" placeholder="UAE-1"></label>
    <label class="field"><span>Region</span><input name="location" value="${escapeHtml(node?.region || "")}" placeholder="UAE"></label>
    <label class="field"><span>Server</span><input name="server" required value="${escapeHtml(node?.server || "")}" placeholder="proxy.example.com"></label>
    <label class="field"><span>SOCKS5 port</span><input name="server_port" type="number" min="1" max="65535" required value="${escapeHtml(node?.server_port || 1080)}"></label>
    <label class="field"><span>Username</span><input name="username" value="${escapeHtml(node?.username || "")}" autocomplete="off"></label>
    <label class="field full"><span>Password</span><input name="password" type="password" ${editing ? "" : "required"} autocomplete="new-password" placeholder="${editing ? "Leave blank to keep the current password" : "SOCKS5 password"}"></label>
    <label class="field"><span>Pool state</span><select name="enabled"><option value="true" ${node?.in_auto_pool !== false ? "selected" : ""}>Enabled</option><option value="false" ${node?.in_auto_pool === false ? "selected" : ""}>Standby</option></select></label>
    <div class="drawer-footer full"><button class="button secondary" type="button" data-close-drawer>Cancel</button><button class="button" type="submit">${editing ? "Save proxy" : "Test & add proxy"}</button></div>
  </form>`;
}

function proxyNodePayload(form, editing = false) {
  const values = Object.fromEntries(new FormData(form).entries());
  const payload = {
    tag: values.tag || "",
    label: values.label.trim(),
    location: values.location.trim(),
    server: values.server.trim(),
    server_port: Number(values.server_port),
    username: values.username.trim(),
    password: values.password,
    enabled: values.enabled === "true",
  };
  if (editing) delete payload.tag;
  return payload;
}

function renderWarnings(runtime) {
  const warnings = runtime.warnings || [];
  if (!warnings.length) return emptyState("No egress warnings", "Runtime, bridge, and Docker network checks are healthy.");
  return `<div class="alert-list">${warnings.map((warning) => `<div class="alert-item warning"><div><strong>Runtime warning</strong><p>${escapeHtml(warning)}</p></div></div>`).join("")}</div>`;
}

export function mountEgress(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(5);
  let runtime = null;
  let usage = null;
  let usageError = null;
  let lastExitCheck = null;
  let poller;

  const render = () => {
    const service = runtime.service || {};
    const egress = runtime.egress || {};
    const boundary = runtime.boundary || {};
    const docker = runtime.docker || {};
    const tun = egress.tun || {};
    const route = egress.route || {};
    const dns = egress.dns || {};
    const exit = lastExitCheck;
    const bridge = usage?.bridge || {};
    const usageSummary = usage?.summary || {};
    const orphanContainers = usageSummary.orphan_containers || 0;
    const bandwidthValue = usageError ? "Unavailable" : usage ? formatRate((bridge.rx_bps || 0) + (bridge.tx_bps || 0)) : "Loading...";
    const bandwidthDetail = usageError ? "Telemetry refresh failed" : usage ? `RX ${formatRate(bridge.rx_bps || 0)} · TX ${formatRate(bridge.tx_bps || 0)}` : "Sampling Docker and bridge traffic";
    const usageBody = usageError
      ? errorState(usageError)
      : usage
        ? `<dl class="kv-list compact-kv"><dt>Bridge</dt><dd class="mono">${escapeHtml(bridge.interface || "-")}</dd><dt>Total</dt><dd>RX ${escapeHtml(formatBytes(bridge.rx_bytes || 0))} · TX ${escapeHtml(formatBytes(bridge.tx_bytes || 0))}</dd><dt>Now</dt><dd>RX ${escapeHtml(formatRate(bridge.rx_bps || 0))} · TX ${escapeHtml(formatRate(bridge.tx_bps || 0))}</dd><dt>Containers</dt><dd>${usageSummary.strix_running || 0}/${usageSummary.strix_total || 0} running · ${orphanContainers} orphan</dd><dt>Per-node</dt><dd>${escapeHtml(usage?.proxy_pool?.per_node_traffic?.available ? "available" : "not enabled")}</dd></dl>`
        : skeleton(2);
    root.innerHTML = `<div class="page-stack">
      <div class="metrics-grid single-row">
        <div class="metric-card ${egress.enabled ? "" : "critical"}"><div class="metric-label">Egress service</div><div class="metric-value">${egress.enabled ? "On" : "Off"}</div><div class="metric-detail">${escapeHtml(service.active_state || "unknown")}</div></div>
        <div class="metric-card ${boundary.only_strix_bridge ? "" : "critical"}"><div class="metric-label">Routing boundary</div><div class="metric-value">${boundary.only_strix_bridge ? "Scoped" : "Mismatch"}</div><div class="metric-detail mono">${escapeHtml((tun.include_interface || []).join(", ") || "-")}</div></div>
        <div class="metric-card"><div class="metric-label">Active nodes</div><div class="metric-value">${egress.outbounds?.auto_pool?.length || 0}</div><div class="metric-detail">${egress.outbounds?.socks_nodes?.length || 0} configured</div></div>
        <div class="metric-card ${orphanContainers ? "warning" : ""}"><div class="metric-label">Docker network</div><div class="metric-value">${docker.available ? "Ready" : "Missing"}</div><div class="metric-detail mono">${escapeHtml(docker.network || "-")} · ${orphanContainers} orphan</div></div>
        <div class="metric-card ${usageError ? "warning" : ""}"><div class="metric-label">Proxy bandwidth</div><div class="metric-value">${escapeHtml(bandwidthValue)}</div><div class="metric-detail">${escapeHtml(bandwidthDetail)}</div></div>
        <div class="metric-card"><div class="metric-label">Verified exit IP</div><div class="metric-value mono" style="font-size:18px">${escapeHtml(exit?.exit_ip || "Not checked")}</div><div class="metric-detail">${exit?.checked_at ? formatDate(exit.checked_at) : "Requires an active scan container"}</div></div>
      </div>
      <section class="panel"><header class="panel-header"><div><h2>Egress controls</h2><p>Controls only sing-box traffic for the Nscan Docker bridge</p></div><div class="panel-actions"><button class="button secondary small" id="checkExitIp" type="button">Verify exit IP</button><button class="button secondary small" id="restartEgress" type="button">Restart service</button></div></header>
        <div class="panel-body"><div class="equal-grid"><div><h3>Current runtime</h3><div class="batch-row"><div class="batch-main"><div class="batch-title">sing-box service</div><div class="batch-meta">Start or stop proxy routing now</div></div>${switchControl("egressEnabled", egress.enabled, "Toggle current egress service", !service.control_available)}</div></div>
        <div><h3>Startup policy</h3><div class="batch-row"><div class="batch-main"><div class="batch-title">Start on boot</div><div class="batch-meta">Independent from current runtime state</div></div>${switchControl("egressStartup", service.startup_enabled, "Toggle egress startup", !service.control_available)}</div></div></div></div>
      </section>
      <div class="egress-status-grid">
        ${panel("Routing boundary", "Fail-closed transparent path for scan containers", `<dl class="kv-list"><dt>Expected bridge</dt><dd class="mono">${escapeHtml(boundary.expected_bridge_interface || "-")}</dd><dt>TUN interface</dt><dd class="mono">${escapeHtml(tun.interface_name || "-")}</dd><dt>auto_route</dt><dd>${badge(tun.auto_route ? "enabled" : "disabled")}</dd><dt>auto_redirect</dt><dd>${badge(tun.auto_redirect ? "enabled" : "disabled")}</dd><dt>strict_route</dt><dd>${badge(tun.strict_route ? "enabled" : "disabled")}</dd></dl>`)}
        ${panel("Route and DNS", "The final route and resolver stay inside the proxy path", `<dl class="kv-list"><dt>Route final</dt><dd class="mono">${escapeHtml(route.final || "-")}</dd><dt>DNS final</dt><dd class="mono">${escapeHtml(dns.final || "-")}</dd><dt>DNS strategy</dt><dd class="mono">${escapeHtml(dns.strategy || "-")}</dd><dt>Docker scope</dt><dd>${escapeHtml(docker.scope || "-")}</dd><dt>Attached containers</dt><dd>${docker.containers || 0}</dd></dl>`)}
        ${panel("Proxy usage", "Bridge counters for scan egress", usageBody, orphanContainers ? '<button class="button secondary small" id="cleanupOrphans" type="button">Clean orphans</button>' : "", "", "activity")}
      </div>
      ${panel("SOCKS5 proxy pool", "Configure nodes independently; credentials remain write-only", renderNodes(runtime), '<button class="button secondary small" id="checkNodes" type="button">Check nodes</button><button class="button small" id="addProxyNode" type="button">Add proxy</button>')}
      ${panel("Warnings", "Permission, config, Docker, or service issues", renderWarnings(runtime))}
    </div>`;
    bind();
  };

  const action = async (element, task, success) => {
    element.disabled = true;
    try {
      runtime = await task();
      toast(success);
      render();
    } catch (error) {
      toast(error.message, "error");
      render();
    }
  };

  const openProxyEditor = (tag = "") => {
    const node = (runtime.egress?.outbounds?.socks_nodes || []).find((item) => item.tag === tag) || null;
    openDrawer({ title: node ? "Edit proxy" : "Add proxy", subtitle: node?.tag || "SOCKS5 pool node", body: proxyNodeForm(node) });
    const form = document.getElementById("proxyNodeForm");
    form?.querySelector("[data-close-drawer]")?.addEventListener("click", closeDrawer);
    const quickInput = form?.elements.proxy_input;
    quickInput?.addEventListener("input", () => {
      const parsed = parseProxyInput(quickInput.value);
      if (!parsed) {
        quickInput.setCustomValidity(quickInput.value.trim() ? "Unrecognized proxy format" : "");
        return;
      }
      quickInput.setCustomValidity("");
      form.elements.server.value = parsed.server;
      form.elements.server_port.value = parsed.server_port;
      form.elements.username.value = parsed.username;
      form.elements.password.value = parsed.password;
      if (!form.elements.tag.value.trim()) form.elements.tag.value = suggestedProxyTag(parsed.server, parsed.server_port);
    });
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector('[type="submit"]');
      button.disabled = true;
      try {
        const payload = proxyNodePayload(form, Boolean(node));
        if (!node) {
          button.textContent = "Testing proxy...";
          const test = await api.testProxyNode(payload);
          if (!test.reachable) throw new Error(`Proxy test failed: ${test.error || "connection unavailable"}`);
          toast(`Proxy test passed · ${test.latency_ms || 0} ms`);
          button.textContent = "Adding proxy...";
        }
        runtime = node ? await api.updateProxyNode(node.tag, payload) : await api.addProxyNode(payload);
        toast(`${node?.tag || payload.tag} ${node ? "updated" : "added"}`);
        closeDrawer();
        render();
      } catch (error) {
        toast(error.message, "error");
        button.textContent = node ? "Save proxy" : "Test & add proxy";
        button.disabled = false;
      }
    });
  };

  const bind = () => {
    root.querySelector("#addProxyNode")?.addEventListener("click", () => openProxyEditor());
    root.querySelectorAll("[data-node-edit]").forEach((button) => button.addEventListener("click", () => openProxyEditor(button.dataset.nodeEdit)));
    root.querySelectorAll("[data-node-delete]").forEach((button) => button.addEventListener("click", async () => {
      const tag = button.dataset.nodeDelete;
      const accepted = await confirmAction({ title: "Delete proxy", message: `Delete ${tag} from sing-box? At least one active node must remain.`, confirmLabel: "Delete", danger: true });
      if (!accepted) return;
      button.disabled = true;
      try {
        runtime = await api.deleteProxyNode(tag);
        toast(`${tag} deleted`);
        render();
      } catch (error) {
        toast(error.message, "error");
        button.disabled = false;
      }
    }));
    root.querySelector("#egressEnabled")?.addEventListener("change", async (event) => {
      const enabled = event.target.checked;
      const accepted = await confirmAction({ title: `${enabled ? "Start" : "Stop"} egress service`, message: enabled ? "Start sing-box routing for Nscan scan containers?" : "Stopping egress can block or expose active scans. Continue?", confirmLabel: enabled ? "Start" : "Stop" });
      if (!accepted) { event.target.checked = !enabled; return; }
      await action(event.target, () => api.setEgressEnabled(enabled), `Egress ${enabled ? "started" : "stopped"}`);
    });
    root.querySelector("#egressStartup")?.addEventListener("change", (event) => action(event.target, () => api.setEgressStartup(event.target.checked), `Startup ${event.target.checked ? "enabled" : "disabled"}`));
    root.querySelectorAll("[data-node-tag]").forEach((input) => input.addEventListener("change", (event) => action(event.target, () => api.setNodeEnabled(event.target.dataset.nodeTag, event.target.checked), `${event.target.dataset.nodeTag} ${event.target.checked ? "enabled" : "disabled"}`)));
    root.querySelector("#restartEgress")?.addEventListener("click", async (event) => {
      const accepted = await confirmAction({ title: "Restart egress service", message: "This briefly interrupts scan container egress. Restart sing-box now?", confirmLabel: "Restart" });
      if (accepted) await action(event.currentTarget, () => api.restartEgress(), "Egress service restarted");
    });
    root.querySelector("#cleanupOrphans")?.addEventListener("click", async (event) => {
      const accepted = await confirmAction({
        title: "Clean orphan containers",
        message: "Stop and remove scan sandbox containers whose scanner process no longer exists? Active scanners are not touched.",
        confirmLabel: "Clean orphans",
        danger: true,
      });
      if (!accepted) return;
      event.currentTarget.disabled = true;
      try {
        const result = await api.cleanupOrphanContainers(false);
        const removed = (result.actions || []).filter((item) => item.removed).length;
        toast(`Cleaned ${removed}/${result.orphan_count || 0} orphan containers`);
        usage = await api.egressUsage();
        render();
      } catch (error) {
        toast(error.message, "error");
        event.currentTarget.disabled = false;
      }
    });
    root.querySelector("#checkNodes")?.addEventListener("click", async (event) => {
      event.currentTarget.disabled = true;
      try { runtime = await api.runtime(undefined, true); render(); toast("Node connectivity checked"); } catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
    });
    root.querySelector("#checkExitIp")?.addEventListener("click", async (event) => {
      event.currentTarget.disabled = true;
      try {
        lastExitCheck = await api.checkEgressIp();
        render();
        toast(lastExitCheck.available ? `Exit IP ${lastExitCheck.exit_ip}` : lastExitCheck.error, lastExitCheck.available ? "success" : "warning");
      } catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
    });
  };

  const load = async (signal) => {
    const usageRequest = api.egressUsage(signal).then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    const scheduledNodeCheck = shouldRunScheduledNodeCheck();
    runtime = await api.runtime(signal, scheduledNodeCheck);
    if (scheduledNodeCheck) rememberScheduledNodeCheck();
    usage = null;
    usageError = null;
    render();
    setFreshness(runtime.generated_at);
    const telemetry = await usageRequest;
    if (telemetry.error) {
      if (telemetry.error.name === "AbortError") throw telemetry.error;
      usageError = telemetry.error;
    } else {
      usage = telemetry.value;
    }
    render();
    setFreshness(usage?.generated_at || runtime.generated_at, Boolean(usageError));
  };
  poller = new Poller(15000, load, (error) => {
    if (!runtime) root.innerHTML = errorState(error);
    else setFreshness(null, true);
  }).start();
  setRefreshHandler(() => poller.run());
  return () => poller.stop();
}
