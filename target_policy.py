"""Strict UAE public-interest scope policy for Nscan target admission."""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCOPE_POLICY_VERSION = "nscan-uae-public-interest-v1"
SCOPE_STATUSES = {"in_scope", "scope_review_required", "out_of_scope"}
OFFICIAL_GOVERNMENT_SUFFIXES = {"gov.ae", "mil.ae", "abudhabi", "dubai"}
UAE_CANDIDATE_SUFFIXES = {
    "ae", "gov.ae", "mil.ae", "co.ae", "ac.ae", "sch.ae", "org.ae", "net.ae", "abudhabi", "dubai",
}
BLOCKED_COUNTRY_SUFFIXES = {"sa", "gov.sa", "ke", "go.ke", "gov.ke", "ac.ke", "co.ke", "or.ke"}
HOST_CLEAN_RE = re.compile(r"^\[|\]$")

CATEGORY_LABELS = {
    "government_entity": "Government entity",
    "public_utility_infrastructure": "Public utility / infrastructure",
    "state_owned_semi_government_holding": "State-owned / semi-government / holding",
    "foundation_charity_public_interest": "Foundation / charity / public-interest",
    "sovereign_fund_portfolio": "Sovereign fund / portfolio",
}
CATEGORY_ALIASES = {
    "official_government_entity": "government_entity",
    "government": "government_entity",
    "soe_semi_government_holding_company": "state_owned_semi_government_holding",
    "state_owned_enterprise": "state_owned_semi_government_holding",
    "charity_foundation_ngo_public_interest": "foundation_charity_public_interest",
    "foundation_charity_ngo": "foundation_charity_public_interest",
    "sovereign_fund_holding_portfolio": "sovereign_fund_portfolio",
    "sovereign_fund": "sovereign_fund_portfolio",
    "public_utility": "public_utility_infrastructure",
    "utility_infrastructure": "public_utility_infrastructure",
}
KNOWN_PUBLIC_UTILITY = ("dewa", "addc", "aadc", "taqa", "adnoc", "ewec", "etihadwe", "etihad-we", "rta", "adports", "ad-ports", "adairports", "etihadrail", "sewa")
KNOWN_SOE = ("adnoc", "adq", "mubadala", "masdar", "taqa", "etisalat", "eand", "emiratesgroup", "emirates-group", "enoc", "dpworld", "dp-world", "edgegroup", "edge-group", "emiratesglobalaluminium", "ega", "dubaiholding", "icd", "investmentcorporationofdubai", "adports", "adairports", "dnata", "flydubai", "dewa", "rta")
KNOWN_SOVEREIGN = ("mubadala", "adq", "icd", "dubaiholding", "dubai-holding", "emiratesinvestmentauthority", "adia", "aldar", "modon")
GOVERNMENT_TERMS = ("government", "ministry", "authority", "municipality", "police", "customs", "federal", "department", "council", "court", "judicial", "prosecution", "civil defence", "civil defense", "ruler's court", "executive office")
PUBLIC_INTEREST_TERMS = ("foundation", "charity", "humanitarian", "ngo", "red crescent", "public welfare", "endowment", "awqaf", "waqf", "zakat")
WEAK_COMMERCIAL_TERMS = ("holding", "investment", "fund", "bank", "airport", "ports", "energy")


def normalize_source(value: str | None) -> str:
    return str(value or "").strip().lower()


def normalize_platform(value: str | None) -> str:
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", str(value or "").strip().lower()).strip("-._")
    return cleaned[:80] or "unknown-platform"


def target_host(target: str) -> str:
    raw = str(target or "").strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return HOST_CLEAN_RE.sub("", host.strip().lower().rstrip("."))


def suffix_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith(f".{suffix}")


def _catalog_path() -> Path:
    configured = os.environ.get("NSCAN_SCOPE_CATALOG_PATH", "").strip()
    return Path(configured) if configured else Path(__file__).resolve().parent / "runtime" / "scope_catalog.json"


def _empty_catalog() -> dict[str, Any]:
    return {"version": "uninitialized", "policy_version": SCOPE_POLICY_VERSION, "items": []}


def load_scope_catalog() -> dict[str, Any]:
    path = _catalog_path()
    if not path.exists():
        return _empty_catalog()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_catalog()
    return payload if isinstance(payload, dict) and isinstance(payload.get("items"), list) else _empty_catalog()


def save_scope_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("scope catalog must contain an items list")
    items: list[dict[str, Any]] = []
    for raw in payload["items"]:
        if not isinstance(raw, dict):
            continue
        host = target_host(str(
            raw.get("host") or raw.get("target") or raw.get("domain")
            or raw.get("base_domain") or raw.get("asset") or ""
        ))
        category = str(raw.get("category") or raw.get("entity_category") or "").strip().lower()
        category = CATEGORY_ALIASES.get(category, category)
        if host and category in CATEGORY_LABELS and str(raw.get("confidence") or "high").lower() == "high":
            items.append({
                "host": host, "category": category, "confidence": "high",
                "reasons": [str(value) for value in raw.get("reasons", []) if str(value).strip()],
                "sample_subjects": [str(value) for value in raw.get("sample_subjects", []) if str(value).strip()][:5],
            })
    catalog = {
        "version": str(payload.get("version") or payload.get("generated_at") or "imported"),
        "generated_at": str(payload.get("generated_at") or ""),
        "source": str(payload.get("source") or "scopesentry"),
        "policy_version": SCOPE_POLICY_VERSION,
        "items": items,
    }
    path = _catalog_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)
    _catalog_item_for_host.cache_clear()
    return catalog


@lru_cache(maxsize=8192)
def _catalog_item_for_host(host: str) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    for item in load_scope_catalog().get("items", []):
        candidate = str(item.get("host") or "")
        if suffix_matches(host, candidate) and (best is None or len(candidate) > len(str(best.get("host") or ""))):
            best = item
    return best


def _certificate_subject(target: str, timeout: float = 1.5) -> str:
    """Read a peer subject with a bounded TLS handshake; errors are inconclusive."""
    parsed = urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target_host(target)
    port = parsed.port or 443
    if not host:
        return ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as tcp:
            context = ssl._create_unverified_context()  # scope evidence only
            with context.wrap_socket(tcp, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return ""
        from cryptography import x509
        return x509.load_der_x509_certificate(der).subject.rfc4514_string()
    except Exception:  # Certificate collection never grants admission on error.
        return ""


def _uae_link(host: str, subject: str, metadata: dict[str, str]) -> bool:
    text = f"{host} {subject} {metadata.get('country', '')} {metadata.get('region', '')}".lower()
    return any(suffix_matches(host, suffix) for suffix in UAE_CANDIDATE_SUFFIXES) or "c=ae" in text or "countryname=ae" in text


def _result(target: str, host: str, *, status: str, reason: str, category: str = "", confidence: str = "", evidence: list[str] | None = None, catalog_version: str = "", subject: str = "", metadata: dict[str, str] | None = None) -> dict[str, Any]:
    tags = [f"scope:{'in' if status == 'in_scope' else 'review_required' if status == 'scope_review_required' else 'out'}", f"scope:{reason}"]
    if category:
        tags.append(f"scope:{category}")
    return {
        "allowed": status == "in_scope", "scope_status": status, "reason": reason, "target": target, "host": host,
        "category": category, "category_label": CATEGORY_LABELS.get(category, ""), "confidence": confidence,
        "evidence": evidence or [], "catalog_version": catalog_version, "certificate_subject": subject, "tags": tags,
        "metadata": metadata or {},
    }


def classify_target_scope(target: str, *, source: str = "", allow_non_uae: bool = False, country: str = "", region: str = "", certificate_lookup: bool = True, certificate_subject: str | None = None) -> dict[str, Any]:
    """Strict scope decision. Source and non-UAE flags never bypass this gate."""
    del source, allow_non_uae
    host = target_host(target)
    metadata = {"country": str(country or ""), "region": str(region or "")}
    catalog = load_scope_catalog()
    version = str(catalog.get("version") or "uninitialized")
    if not host:
        return _result(target, host, status="out_of_scope", reason="invalid_host", catalog_version=version, metadata=metadata)
    item = _catalog_item_for_host(host)
    if item:
        return _result(target, host, status="in_scope", category=str(item["category"]), confidence="high", reason="curated_high_confidence", evidence=["curated_scope_catalog", *item.get("reasons", [])], catalog_version=version, subject="; ".join(item.get("sample_subjects", [])[:1]), metadata=metadata)
    suffix = next((value for value in OFFICIAL_GOVERNMENT_SUFFIXES if suffix_matches(host, value)), "")
    if suffix:
        return _result(target, host, status="in_scope", category="government_entity", confidence="high", reason="official_uae_suffix", evidence=[f"official_suffix:{suffix}"], catalog_version=version, metadata=metadata)
    subject = certificate_subject if certificate_subject is not None else (_certificate_subject(target) if certificate_lookup else "")
    text = f"{host} {subject}".lower()
    uae_link = _uae_link(host, subject, metadata)
    if uae_link:
        if any(token in text for token in KNOWN_PUBLIC_UTILITY):
            return _result(target, host, status="in_scope", category="public_utility_infrastructure", confidence="high", reason="known_uae_public_utility", evidence=["known_entity_brand", "uae_link"], catalog_version=version, subject=subject, metadata=metadata)
        if any(token in text for token in KNOWN_SOVEREIGN):
            return _result(target, host, status="in_scope", category="sovereign_fund_portfolio", confidence="high", reason="known_uae_sovereign_entity", evidence=["known_entity_brand", "uae_link"], catalog_version=version, subject=subject, metadata=metadata)
        if any(token in text for token in KNOWN_SOE):
            return _result(target, host, status="in_scope", category="state_owned_semi_government_holding", confidence="high", reason="known_uae_state_entity", evidence=["known_entity_brand", "uae_link"], catalog_version=version, subject=subject, metadata=metadata)
        if subject and any(term in text for term in PUBLIC_INTEREST_TERMS):
            return _result(target, host, status="in_scope", category="foundation_charity_public_interest", confidence="high", reason="certificate_public_interest_entity", evidence=["certificate_subject", "uae_link"], catalog_version=version, subject=subject, metadata=metadata)
        if subject and any(term in text for term in GOVERNMENT_TERMS):
            return _result(target, host, status="in_scope", category="government_entity", confidence="high", reason="certificate_government_entity", evidence=["certificate_subject", "uae_link"], catalog_version=version, subject=subject, metadata=metadata)
    if any(suffix_matches(host, suffix) for suffix in UAE_CANDIDATE_SUFFIXES) or any(term in text for term in WEAK_COMMERCIAL_TERMS) or any(marker in text for marker in ("c=ae", "countryname=ae", "dubai", "abu dhabi")):
        return _result(target, host, status="scope_review_required", reason="insufficient_entity_evidence", evidence=["uae_candidate_or_weak_evidence"], catalog_version=version, subject=subject, metadata=metadata)
    if any(suffix_matches(host, suffix) for suffix in BLOCKED_COUNTRY_SUFFIXES):
        return _result(target, host, status="out_of_scope", reason="non_uae_country_suffix", catalog_version=version, subject=subject, metadata=metadata)
    return _result(target, host, status="out_of_scope", reason="outside_target_definition", catalog_version=version, subject=subject, metadata=metadata)
