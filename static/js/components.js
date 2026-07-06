import { escapeHtml, icon, statusTone } from "./utils.js";

const LOGO_RULES = [
  { tokens: ["anyrouter"], src: "/static/logos/anyrouter.svg", label: "AnyRouter" },
  { tokens: ["deepseek"], src: "/static/logos/deepseek.svg", label: "DeepSeek" },
  { tokens: ["opencode-go", "opencode"], src: "/static/logos/opencode.svg", label: "OpenCode Go" },
  { tokens: ["openai-proxy", "openai"], src: "/static/logos/opencode.svg", label: "OpenAI/GPT" },
  { tokens: ["volces", "volcengine", "ark", "huoshan", "byteplus"], src: "/static/logos/huoshan.png", label: "Volcengine" },
  { tokens: ["mimo", "xiaomi", "mino"], src: "/static/logos/mimo.png", label: "Mimo" },
  { tokens: ["nvidia", "nemotron"], src: "/static/logos/nvidia.svg", label: "NVIDIA" },
  { tokens: ["openrouter"], src: "/static/logos/openrouter.svg", label: "OpenRouter" },
  { tokens: ["minimax"], src: "/static/logos/minimax.svg", label: "MiniMax" },
  { tokens: ["silicon"], src: "/static/logos/silicon_en.jpg", label: "SiliconFlow" },
  { tokens: ["ucloud"], src: "/static/logos/ucloud.png", label: "UCloud" },
];

const REGION_CODES = [
  { code: "AE", tokens: ["uae", "united arab emirates", "emirates", "dubai", "abu dhabi"] },
  { code: "NG", tokens: ["nigeria", "lagos", "abuja"] },
  { code: "TR", tokens: ["turkey", "turkiye", "türkiye", "istanbul"] },
  { code: "GB", tokens: ["uk", "united kingdom", "britain", "great britain", "england", "london"] },
  { code: "US", tokens: ["us", "usa", "united states", "america"] },
  { code: "CN", tokens: ["china", "mainland china"] },
  { code: "HK", tokens: ["hong kong", "hk"] },
  { code: "SG", tokens: ["singapore", "sg"] },
  { code: "JP", tokens: ["japan", "tokyo"] },
  { code: "KR", tokens: ["korea", "seoul"] },
  { code: "DE", tokens: ["germany", "de"] },
  { code: "FR", tokens: ["france", "paris"] },
  { code: "NL", tokens: ["netherlands", "holland"] },
  { code: "CA", tokens: ["canada"] },
  { code: "AU", tokens: ["australia"] },
];

function normalizeModel(input = {}, provider = "") {
  if (typeof input === "string") return { name: input, model: input, provider };
  return input || {};
}

function logoInfo(input = {}) {
  const model = normalizeModel(input);
  const haystack = `${model.name || ""} ${model.model || ""} ${model.provider || ""} ${model.label || ""}`.toLowerCase();
  return LOGO_RULES.find((rule) => rule.tokens.some((token) => haystack.includes(token))) || null;
}

function fallbackLetters(input = {}) {
  const model = normalizeModel(input);
  const source = model.provider || model.name || model.model || "AI";
  const parts = String(source).split(/[^a-zA-Z0-9]+/).filter(Boolean);
  const letters = parts.length > 1 ? `${parts[0][0]}${parts[1][0]}` : String(source).slice(0, 2);
  return letters.toUpperCase();
}

function countryCodeFromText(...values) {
  const text = values.filter(Boolean).join(" ").toLowerCase();
  const rule = REGION_CODES.find((item) => item.tokens.some((token) => text.includes(token)));
  return rule?.code || "";
}

function flagEmoji(code) {
  const normalized = String(code || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(normalized)) return "";
  return [...normalized].map((char) => String.fromCodePoint(127397 + char.charCodeAt(0))).join("");
}

export function badge(label, tone = "") {
  return `<span class="badge ${tone || statusTone(label)}">${escapeHtml(label || "unknown")}</span>`;
}

export function metric(label, value, detail = "", tone = "") {
  return `<article class="metric-card ${tone}"><div class="metric-label">${escapeHtml(label)}</div><div class="metric-value">${escapeHtml(value)}</div><div class="metric-detail">${escapeHtml(detail)}</div></article>`;
}

export function panel(title, description, body, actions = "", classes = "", titleIcon = "") {
  const heading = titleIcon
    ? `<div class="panel-title-line">${icon(titleIcon, "panel-title-icon")}<h2>${escapeHtml(title)}</h2></div>`
    : `<h2>${escapeHtml(title)}</h2>`;
  return `<section class="panel ${classes}"><header class="panel-header"><div>${heading}${description ? `<p>${escapeHtml(description)}</p>` : ""}</div>${actions ? `<div class="panel-actions">${actions}</div>` : ""}</header><div class="panel-body">${body}</div></section>`;
}

export function emptyState(title, detail = "") {
  return `<div class="empty-state"><div><strong>${escapeHtml(title)}</strong>${detail ? `<p>${escapeHtml(detail)}</p>` : ""}</div></div>`;
}

export function errorState(error) {
  return `<div class="error-state"><div><strong>Unable to load this view</strong><p>${escapeHtml(error?.message || String(error))}</p></div></div>`;
}

export function skeleton(count = 4) {
  return `<div class="page-stack">${Array.from({ length: count }, () => '<div class="skeleton" style="height:96px"></div>').join("")}</div>`;
}

export function progress(value) {
  const width = Math.max(0, Math.min(100, Number(value) || 0));
  return `<div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${width}"><span style="width:${width}%"></span></div>`;
}

export function toast(message, type = "success", timeout = 3600) {
  const region = document.getElementById("toastRegion");
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  region.append(node);
  setTimeout(() => node.remove(), timeout);
}

export function confirmAction({ title = "Confirm action", message, confirmLabel = "Confirm", danger = true }) {
  const dialog = document.getElementById("confirmDialog");
  document.getElementById("confirmTitle").textContent = title;
  document.getElementById("confirmMessage").textContent = message;
  const accept = document.getElementById("confirmAccept");
  accept.textContent = confirmLabel;
  accept.className = `button ${danger ? "danger" : ""}`;
  return new Promise((resolve) => {
    const handler = () => {
      dialog.removeEventListener("close", handler);
      resolve(dialog.returnValue === "confirm");
    };
    dialog.addEventListener("close", handler);
    dialog.showModal();
  });
}

let drawerCleanup = null;
export function openDrawer({ title, subtitle = "", body, onOpen, onClose }) {
  const drawer = document.getElementById("drawer");
  const backdrop = document.getElementById("drawerBackdrop");
  document.getElementById("drawerTitle").textContent = title;
  document.getElementById("drawerSubtitle").textContent = subtitle;
  document.getElementById("drawerBody").innerHTML = body;
  drawer.hidden = false;
  backdrop.hidden = false;
  document.body.style.overflow = "hidden";
  drawerCleanup = onClose || null;
  requestAnimationFrame(() => {
    const focusable = drawer.querySelector("input, select, textarea, button");
    focusable?.focus();
    onOpen?.(drawer);
  });
}

export function closeDrawer() {
  const drawer = document.getElementById("drawer");
  const backdrop = document.getElementById("drawerBackdrop");
  drawer.hidden = true;
  backdrop.hidden = true;
  document.body.style.overflow = "";
  drawerCleanup?.();
  drawerCleanup = null;
}

export function button(label, { tone = "secondary", iconName = "", attrs = "" } = {}) {
  return `<button class="button ${tone}" type="button" ${attrs}>${iconName ? icon(iconName) : ""}<span>${escapeHtml(label)}</span></button>`;
}

export function modelLogo(input = {}, classes = "") {
  const model = normalizeModel(input);
  const logo = logoInfo(model);
  const label = logo?.label || model.provider || model.name || model.model || "Model";
  const fallback = fallbackLetters(model);
  const image = logo ? `<img class="logo-image" src="${escapeHtml(logo.src)}" alt="" loading="lazy" onerror="this.hidden=true;this.nextElementSibling.hidden=false">` : "";
  return `<span class="logo-mark ${classes}" title="${escapeHtml(label)}">${image}<span class="logo-fallback" ${logo ? "hidden" : ""}>${escapeHtml(fallback)}</span></span>`;
}

export function providerChip(input = {}) {
  const model = normalizeModel(input);
  const label = model.provider || "provider";
  return `<span class="provider-chip">${modelLogo(model, "mini")}<span>${escapeHtml(label)}</span></span>`;
}

export function modelIdentity(input = {}, { secondary = "", compact = false, title = "" } = {}) {
  const model = normalizeModel(input);
  const primary = title || model.name || model.actual_model || model.model || "awaiting model";
  return `<div class="identity-row model-identity ${compact ? "compact" : ""}">${modelLogo(model)}<div class="identity-copy"><div class="cell-primary break-anywhere">${escapeHtml(primary)}</div>${secondary ? `<div class="cell-secondary break-anywhere">${secondary}</div>` : ""}</div></div>`;
}

export function regionFlag(region = "", { label = "", className = "" } = {}) {
  const code = countryCodeFromText(region, label);
  const flag = flagEmoji(code);
  const text = label || region || "Unknown";
  return `<span class="flag-badge ${className}" title="${escapeHtml(text)}">${flag ? `<span class="flag-emoji" aria-hidden="true">${flag}</span>` : '<span class="flag-empty" aria-hidden="true"></span>'}<span>${escapeHtml(text)}</span></span>`;
}

export function proxyNodeIdentity(node = {}) {
  const region = node.region || "";
  const label = node.display_name || node.tag || "proxy node";
  const flag = regionFlag(region, { label: region || label });
  return `<div class="node-title-line">${flag}<span class="node-name">${escapeHtml(label)}</span></div>`;
}
