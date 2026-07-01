import { api } from "../api.js";
import { badge, confirmAction, errorState, skeleton, toast } from "../components.js";
import { escapeHtml } from "../utils.js";

function field(label, name, value, options = {}) {
  const type = options.type || "text";
  return `<label class="field ${options.full ? "full" : ""}">${escapeHtml(label)}<input name="${escapeHtml(name)}" type="${type}" value="${escapeHtml(value ?? "")}" ${options.min != null ? `min="${options.min}"` : ""}><span class="field-help">${escapeHtml(options.help || "")}</span></label>`;
}

function selectField(label, name, value, choices) {
  return `<label class="field">${escapeHtml(label)}<select name="${escapeHtml(name)}">${choices.map(([key, title]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? "selected" : ""}>${escapeHtml(title)}</option>`).join("")}</select></label>`;
}

function renderSettings(config, security) {
  const usage = config.usage || {};
  const schedule = config.schedule || {};
  const server = config.server || {};
  const failover = config.failover || {};
  const ips = security.ip_whitelist?.allowed_ips || server.allowed_ips || [];
  return `<form id="settingsForm" class="page-stack">
    <section class="panel"><header class="panel-header"><div><h2>Access control</h2><p>Global PIN session and source-IP whitelist for port 8888</p></div>${badge(security.pin?.configured && security.ip_whitelist?.configured ? "protected" : "attention", security.pin?.configured && security.ip_whitelist?.configured ? "success" : "warning")}</header>
      <div class="panel-body"><div class="equal-grid"><div><h3>Dashboard PIN</h3><p class="muted">The current PIN is never returned. A new PIN refreshes this browser's 30-day session.</p><div class="toolbar"><input id="newDashboardPin" type="password" autocomplete="new-password" placeholder="New PIN (4-64 characters)"><button class="button secondary" id="updatePin" type="button">Update PIN</button><button class="button ghost" id="logout" type="button">Sign out</button></div></div>
      <div><h3>Allowed source IPs</h3><div class="tag-row" id="allowedIpList">${ips.map((ip) => `<button class="badge info" type="button" data-remove-ip="${escapeHtml(ip)}" title="Remove ${escapeHtml(ip)}">${escapeHtml(ip)} ×</button>`).join("") || badge("not configured", "warning")}</div><div class="toolbar" style="margin-top:10px"><input id="newAllowedIp" inputmode="decimal" placeholder="192.168.0.120"><button class="button secondary" id="addAllowedIp" type="button">Add IP</button></div></div></div></div>
    </section>
    <section class="panel"><header class="panel-header"><div><h2>Usage limits</h2><p>Budget and token guardrails used by the model proxy</p></div></header><div class="panel-body"><div class="form-grid">
      ${field("Daily budget", "daily_budget", usage.daily_budget ?? 50, { type: "number", min: 0 })}${field("Monthly budget", "monthly_budget", usage.monthly_budget ?? 500, { type: "number", min: 0 })}
      ${field("Max tokens per day", "max_tokens_per_day", usage.max_tokens_per_day ?? 5000000, { type: "number", min: 0 })}${field("Max tokens per request", "max_tokens_per_request", usage.max_tokens_per_request ?? 100000, { type: "number", min: 0 })}
    </div></div></section>
    <section class="panel"><header class="panel-header"><div><h2>Schedule and concurrency</h2><p>Time-aware model strategy and process capacity</p></div></header><div class="panel-body"><div class="form-grid">
      ${field("Maximum worker threads", "max_threads", server.max_threads ?? 10, { type: "number", min: 1 })}${field("Peak parallel limit", "peak_parallel_limit", schedule.peak_parallel_limit ?? 3, { type: "number", min: 1 })}
      ${field("Peak strategy", "peak_strategy", schedule.peak_strategy ?? "minimax")}${field("Timezone", "timezone", schedule.timezone ?? "Asia/Dubai")}
      ${field("Priority hours", "mimo_priority_hours", (schedule.mimo_priority_hours || [0,1,2,3,4,5,6,7]).join(","), { help: "Comma-separated hours, 0-23." })}${selectField("Skip weekends", "peak_skip_weekends", String(schedule.peak_skip_weekends !== false), [["true","Yes"],["false","No"]])}
    </div></div></section>
    <section class="panel"><header class="panel-header"><div><h2>Failover</h2><p>Retry, cooldown, and fallback behavior</p></div></header><div class="panel-body"><div class="form-grid">
      ${field("Maximum retries", "max_retries", failover.max_retries ?? 5, { type: "number", min: 0 })}${field("Consecutive failure threshold", "max_consecutive_failures", failover.max_consecutive_failures ?? 5, { type: "number", min: 1 })}
      ${field("Recovery time (seconds)", "recovery_time", failover.recovery_time ?? 3600, { type: "number", min: 0 })}${selectField("Fallback to free models", "fallback_to_free", String(failover.fallback_to_free !== false), [["true","Enabled"],["false","Disabled"]])}
    </div></div></section>
    <section class="panel"><header class="panel-header"><div><h2>Advanced configuration</h2><p>Secrets remain write-only and are represented by configured flags and masked hints</p></div></header><div class="panel-body"><details class="advanced-panel"><summary>Open raw JSON configuration</summary><textarea id="configEditor" class="mono" rows="24" spellcheck="false">${escapeHtml(JSON.stringify(config, null, 2))}</textarea></details></div></section>
    <div class="sticky-save"><div><strong id="saveState">No unsaved changes</strong><div class="muted">Changes apply through the existing hot-reload path.</div></div><button class="button" id="saveSettings" type="submit" disabled>Save settings</button></div>
  </form>`;
}

export function mountSettings(context) {
  const { root, setFreshness, setRefreshHandler } = context;
  root.innerHTML = skeleton(5);
  let config = null;
  let security = null;
  let dirty = false;

  const setDirty = (value = true) => {
    dirty = value;
    const button = root.querySelector("#saveSettings");
    const state = root.querySelector("#saveState");
    if (button) button.disabled = !dirty;
    if (state) state.textContent = dirty ? "Unsaved changes" : "No unsaved changes";
  };

  const render = () => {
    root.innerHTML = renderSettings(config, security);
    bind();
  };

  const reload = async (signal) => {
    [config, security] = await Promise.all([api.config(signal), api.security(signal)]);
    setDirty(false);
    render();
    setFreshness(new Date().toISOString());
  };

  const save = async (form) => {
    let next;
    try { next = JSON.parse(root.querySelector("#configEditor").value); }
    catch (error) { toast(`Invalid advanced JSON: ${error.message}`, "error"); return; }
    const values = Object.fromEntries(new FormData(form).entries());
    next.usage = { ...(next.usage || {}), daily_budget: Number(values.daily_budget), monthly_budget: Number(values.monthly_budget), max_tokens_per_day: Number(values.max_tokens_per_day), max_tokens_per_request: Number(values.max_tokens_per_request) };
    next.schedule = { ...(next.schedule || {}), peak_parallel_limit: Number(values.peak_parallel_limit), peak_strategy: values.peak_strategy.trim(), timezone: values.timezone.trim(), mimo_priority_hours: values.mimo_priority_hours.split(",").map(Number).filter((value) => Number.isInteger(value) && value >= 0 && value <= 23), peak_skip_weekends: values.peak_skip_weekends === "true" };
    next.server = { ...(next.server || {}), max_threads: Number(values.max_threads) };
    next.failover = { ...(next.failover || {}), max_retries: Number(values.max_retries), max_consecutive_failures: Number(values.max_consecutive_failures), recovery_time: Number(values.recovery_time), fallback_to_free: values.fallback_to_free === "true" };
    const button = root.querySelector("#saveSettings");
    button.disabled = true;
    try { await api.saveConfig(next); toast("Configuration saved"); await reload(); }
    catch (error) { toast(error.message, "error"); button.disabled = false; }
  };

  const bind = () => {
    const form = root.querySelector("#settingsForm");
    form.addEventListener("input", (event) => { if (!event.target.closest("#newDashboardPin") && !event.target.closest("#newAllowedIp")) setDirty(true); });
    form.addEventListener("submit", (event) => { event.preventDefault(); save(form); });
    root.querySelector("#updatePin").addEventListener("click", async (event) => {
      const input = root.querySelector("#newDashboardPin");
      if (input.value.trim().length < 4) { toast("PIN must be at least four characters", "error"); return; }
      event.currentTarget.disabled = true;
      try { await api.updatePin(input.value.trim()); input.value = ""; toast("Dashboard PIN updated"); await reload(); }
      catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
    });
    root.querySelector("#logout").addEventListener("click", async () => { await api.logout(); window.location.assign("/"); });
    root.querySelector("#addAllowedIp").addEventListener("click", async (event) => {
      const input = root.querySelector("#newAllowedIp");
      if (!input.value.trim()) return;
      event.currentTarget.disabled = true;
      try { await api.addIp(input.value.trim()); toast("IP added to whitelist"); await reload(); }
      catch (error) { toast(error.message, "error"); event.currentTarget.disabled = false; }
    });
    root.querySelectorAll("[data-remove-ip]").forEach((button) => button.addEventListener("click", async () => {
      const ip = button.dataset.removeIp;
      const accepted = await confirmAction({ title: "Remove allowed IP", message: `Remove ${ip} from the port 8888 whitelist? This can lock out that client immediately.`, confirmLabel: "Remove" });
      if (!accepted) return;
      try { await api.removeIp(ip); toast(`${ip} removed`); await reload(); } catch (error) { toast(error.message, "error"); }
    }));
  };

  reload().catch((error) => { root.innerHTML = errorState(error); });
  setRefreshHandler(() => reload());
  return () => {};
}
