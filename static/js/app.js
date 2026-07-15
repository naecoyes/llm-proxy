import { api } from "./api.js?v=20260710-scan-freshness-v1";
import { closeDrawer, toast } from "./components.js?v=20260623-provider-ui";
import { Router } from "./router.js";
import { formatNumber, icon, relativeTime } from "./utils.js";
import { mountOverview } from "./pages/overview.js?v=20260709-overview-trend-narrow";
import { mountScans, mountScanHistory } from "./pages/scans.js?v=20260715-resumable-preflight-v1";
import { mountAssets } from "./pages/assets.js?v=20260701-assets-history";
import { mountFindings } from "./pages/findings.js?v=20260715-export-capability-v1";
import { mountEgress } from "./pages/egress.js";
import { mountModels } from "./pages/models.js?v=20260623-provider-ui";
import { mountActivity } from "./pages/activity.js?v=20260715-resumable-preflight-v1";
import { mountSettings } from "./pages/settings.js";

const routes = {
  overview: { title: "Overview", subtitle: "Live scan posture and operational alerts", icon: "overview", mount: mountOverview },
  scans: { title: "Scans", subtitle: "Submit batches and watch current scan tasks", icon: "scans", mount: mountScans },
  scanHistory: { title: "Scan History", subtitle: "Historical batch progress, successes, failures, and retries", icon: "history", mount: mountScanHistory },
  assets: { title: "Assets", subtitle: "Asset inventory, probe state, scans, and evidence links", icon: "assets", mount: mountAssets },
  findings: { title: "Findings", subtitle: "Vulnerabilities, targets, reports, and verification state", icon: "findings", mount: mountFindings },
  egress: { title: "Egress", subtitle: "Fail-closed proxy routing for scan containers", icon: "egress", mount: mountEgress },
  models: { title: "Models", subtitle: "Provider health, routing, limits, and credentials", icon: "models", mount: mountModels },
  activity: { title: "Activity", subtitle: "LLM processes, usage, requests, and model switches", icon: "activity", mount: mountActivity },
  settings: { title: "Settings", subtitle: "Access control, limits, schedules, and failover", icon: "settings", mount: mountSettings },
};

const shell = document.getElementById("appShell");
const root = document.getElementById("pageContent");
const nav = document.getElementById("primaryNav");
const freshness = document.getElementById("freshnessLabel");
const topbarActions = document.getElementById("topbarActions");
let cleanupCurrentPage = null;
let refreshHandler = () => {};
let extraActions = "";
let freshnessTimestamp = null;
let freshnessStale = false;

function renderNav() {
  nav.innerHTML = Object.entries(routes).map(([key, route]) => `<button class="nav-item" type="button" data-route="${key}" title="${route.title}">${icon(route.icon)}<span class="nav-label">${route.title}</span>${["scans", "assets", "findings", "models"].includes(key) ? `<span class="nav-badge" id="${key}NavBadge">-</span>` : ""}</button>`).join("");
  nav.querySelectorAll("[data-route]").forEach((button) => button.addEventListener("click", () => {
    router.navigate(button.dataset.route);
    shell.classList.remove("mobile-nav-open");
  }));
}

function renderTopbarActions() {
  topbarActions.innerHTML = `${extraActions}<button class="button secondary" id="refreshButton" type="button">${icon("refresh")}<span>Refresh</span></button>`;
  document.getElementById("refreshButton").addEventListener("click", async (event) => {
    event.currentTarget.disabled = true;
    try { await refreshHandler(); }
    catch (error) { toast(error.message, "error"); }
    finally { event.currentTarget.disabled = false; }
  });
}

function setTopbarActions(html = "") {
  extraActions = html;
  renderTopbarActions();
}

function setRefreshHandler(handler) {
  refreshHandler = handler || (() => {});
}

function setFreshness(timestamp, stale = false) {
  freshnessTimestamp = timestamp || freshnessTimestamp;
  freshnessStale = stale;
  updateFreshnessLabel();
}

function updateFreshnessLabel() {
  freshness.classList.toggle("stale", freshnessStale);
  if (freshnessStale) freshness.textContent = "Stale data";
  else freshness.textContent = freshnessTimestamp ? `Updated ${relativeTime(freshnessTimestamp)}` : "Loading";
}

function mountRoute(key, route) {
  cleanupCurrentPage?.();
  closeDrawer();
  cleanupCurrentPage = null;
  extraActions = "";
  freshnessTimestamp = null;
  freshnessStale = false;
  setRefreshHandler(() => {});
  renderTopbarActions();
  document.getElementById("pageTitle").textContent = route.title;
  document.getElementById("pageSubtitle").textContent = route.subtitle;
  nav.querySelectorAll("[data-route]").forEach((button) => button.classList.toggle("active", button.dataset.route === key));
  root.focus({ preventScroll: true });
  cleanupCurrentPage = route.mount({ root, setFreshness, setRefreshHandler, setTopbarActions }) || null;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("nscan-theme", theme);
  document.getElementById("themeToggle").innerHTML = icon(theme === "dark" ? "sun" : "moon");
}

function setupShell() {
  renderNav();
  renderTopbarActions();
  document.getElementById("sidebarCollapse").innerHTML = icon("collapse");
  document.getElementById("mobileMenu").innerHTML = icon("menu");
  document.getElementById("drawerClose").innerHTML = icon("close");
  const savedCollapsed = localStorage.getItem("nscan-sidebar-collapsed") === "true";
  shell.classList.toggle("sidebar-is-collapsed", savedCollapsed);
  document.getElementById("sidebarCollapse").addEventListener("click", () => {
    shell.classList.toggle("sidebar-is-collapsed");
    const collapsed = shell.classList.contains("sidebar-is-collapsed");
    localStorage.setItem("nscan-sidebar-collapsed", String(collapsed));
    document.getElementById("sidebarCollapse").innerHTML = icon(collapsed ? "expand" : "collapse");
  });
  document.getElementById("mobileMenu").addEventListener("click", () => shell.classList.add("mobile-nav-open"));
  document.getElementById("mobileOverlay").addEventListener("click", () => shell.classList.remove("mobile-nav-open"));
  document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  document.getElementById("drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !document.getElementById("drawer").hidden) closeDrawer(); });
  const preferred = localStorage.getItem("nscan-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  applyTheme(preferred);
  document.getElementById("themeToggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
}

async function updateNavBadges() {
  try {
    const summary = await api.badges();
    const scansBadge = document.getElementById("scansNavBadge");
    const assetsBadge = document.getElementById("assetsNavBadge");
    const modelsBadge = document.getElementById("modelsNavBadge");
    const findingsBadge = document.getElementById("findingsNavBadge");
    if (scansBadge) scansBadge.textContent = String(summary.scans ?? summary.active_scans ?? 0);
    if (assetsBadge) assetsBadge.textContent = formatNumber(summary.assets ?? summary.assets_total ?? 0, 0);
    if (modelsBadge) modelsBadge.textContent = String(summary.models ?? summary.models_healthy ?? 0);
    if (findingsBadge) findingsBadge.textContent = formatNumber(summary.findings ?? summary.vulnerabilities_total ?? 0, 0);
  } catch (_) {
    // The active page presents the actionable error state.
  }
}

setupShell();
const router = new Router(routes, mountRoute);
router.start();
updateNavBadges();
setInterval(() => { if (!document.hidden) updateNavBadges(); }, 30000);
setInterval(updateFreshnessLabel, 10000);
