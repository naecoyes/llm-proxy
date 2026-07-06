"""Target scope policy for Nscan platform ingestion and Smart Batch jobs."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit


GENERIC_TLDS = {
    "com", "net", "org", "io", "ai", "app", "dev", "cloud", "tech", "site",
    "online", "info", "biz", "co", "me",
}
UAE_SUFFIXES = {"ae", "gov.ae", "co.ae", "ac.ae", "sch.ae", "org.ae", "net.ae"}
BLOCKED_COUNTRY_SUFFIXES = {"sa", "gov.sa", "ke", "go.ke", "gov.ke", "ac.ke", "co.ke", "or.ke"}
MANUAL_SOURCE = "manual"
HOST_CLEAN_RE = re.compile(r"^\[|\]$")


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


def classify_target_scope(
    target: str,
    *,
    source: str = "",
    allow_non_uae: bool = False,
    country: str = "",
    region: str = "",
) -> dict[str, Any]:
    """Return allow/block decision for automatic target ingestion.

    Generic TLDs are allowed by policy. Explicit non-UAE country/government
    suffixes are blocked unless the caller is a manual API override.
    """
    host = target_host(target)
    source_value = normalize_source(source)
    manual_override = source_value == MANUAL_SOURCE and bool(allow_non_uae)
    metadata = {"country": str(country or ""), "region": str(region or "")}
    if not host:
        return {
            "allowed": False,
            "reason": "invalid_host",
            "target": target,
            "host": host,
            "metadata": metadata,
        }
    if manual_override:
        return {
            "allowed": True,
            "reason": "manual_override",
            "target": target,
            "host": host,
            "metadata": metadata,
        }
    blocked_suffix = next((suffix for suffix in BLOCKED_COUNTRY_SUFFIXES if suffix_matches(host, suffix)), "")
    if blocked_suffix:
        return {
            "allowed": False,
            "reason": "non_uae_country_suffix",
            "blocked_suffix": blocked_suffix,
            "target": target,
            "host": host,
            "metadata": metadata,
        }
    uae_suffix = next((suffix for suffix in UAE_SUFFIXES if suffix_matches(host, suffix)), "")
    if uae_suffix:
        return {
            "allowed": True,
            "reason": "uae_suffix",
            "matched_suffix": uae_suffix,
            "target": target,
            "host": host,
            "metadata": metadata,
        }
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in GENERIC_TLDS:
        return {
            "allowed": True,
            "reason": "generic_tld",
            "matched_suffix": tld,
            "target": target,
            "host": host,
            "metadata": metadata,
        }
    return {
        "allowed": False,
        "reason": "unsupported_country_suffix",
        "target": target,
        "host": host,
        "metadata": metadata,
    }
