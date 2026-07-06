#!/usr/bin/env python3
"""Narrow root helper for changing sing-box selector pool membership."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


CONFIG_PATH = Path("/etc/sing-box/config.json")
SERVICE_NAME = "sing-box"
VALID_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VALID_SERVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


def fail(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read sing-box config: {exc}")


def write_atomic(config: dict, mode: int) -> None:
    payload = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".config.json.nscan-", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, CONFIG_PATH)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def restart_service() -> subprocess.CompletedProcess[str]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        fail("systemctl command not found")
    return subprocess.run(  # noqa: S603
        [systemctl, "restart", SERVICE_NAME],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def selector_from(outbounds: list[dict]) -> dict:
    selector = next(
        (
            item
            for item in outbounds
            if item.get("tag") in {"proxy-auto", "proxy-selector"}
            and isinstance(item.get("outbounds"), list)
        ),
        None,
    )
    if selector is None:
        fail("proxy selector not found")
    return selector


def read_payload() -> dict:
    try:
        payload = json.load(sys.stdin)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON payload: {exc}", 2)
    if not isinstance(payload, dict):
        fail("payload must be an object", 2)
    return payload


def clean_text(payload: dict, name: str, maximum: int, required: bool = False) -> str:
    value = str(payload.get(name) or "").strip()
    if required and not value:
        fail(f"{name} is required", 2)
    if len(value) > maximum or "\n" in value or "\r" in value:
        fail(f"invalid {name}", 2)
    return value


def commit(config: dict, original: bytes, mode: int) -> None:
    write_atomic(config, mode)
    restarted = restart_service()
    if restarted.returncode != 0:
        CONFIG_PATH.write_bytes(original)
        os.chmod(CONFIG_PATH, mode)
        restart_service()
        fail("sing-box restart failed; configuration rolled back")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"enable", "disable", "upsert", "delete"}:
        fail("usage: nscan-egress-node-control NODE_TAG enable|disable|upsert|delete", 2)
    node_tag, action = sys.argv[1:]
    if not VALID_TAG.fullmatch(node_tag):
        fail("invalid node tag", 2)

    config = load_config()
    outbounds = config.get("outbounds") or []
    socks_order = [
        str(item.get("tag") or "")
        for item in outbounds
        if item.get("type") == "socks" and item.get("tag")
    ]
    selector = selector_from(outbounds)
    original = CONFIG_PATH.read_bytes()
    original_mode = CONFIG_PATH.stat().st_mode & 0o777

    if action == "upsert":
        payload = read_payload()
        server = clean_text(payload, "server", 253, required=True)
        if not VALID_SERVER.fullmatch(server):
            fail("invalid server", 2)
        try:
            server_port = int(payload.get("server_port"))
        except (TypeError, ValueError):
            fail("invalid server_port", 2)
        if not 1 <= server_port <= 65535:
            fail("invalid server_port", 2)
        existing = next((item for item in outbounds if item.get("type") == "socks" and item.get("tag") == node_tag), None)
        password = clean_text(payload, "password", 512)
        if existing is None and not password:
            fail("password is required for a new node", 2)
        node = existing or {"type": "socks", "tag": node_tag, "version": "5"}
        node.update(
            {
                "server": server,
                "server_port": server_port,
                "username": clean_text(payload, "username", 256),
                "label": clean_text(payload, "label", 128),
                "location": clean_text(payload, "location", 64),
                "version": "5",
            }
        )
        if password:
            node["password"] = password
        if existing is None:
            selector_index = outbounds.index(selector)
            outbounds.insert(selector_index, node)
            socks_order.append(node_tag)
        selected = [str(tag) for tag in selector["outbounds"]]
        enabled = bool(payload.get("enabled", True))
        if enabled and node_tag not in selected:
            selected.append(node_tag)
        if not enabled:
            selected = [tag for tag in selected if tag != node_tag]
        if not selected:
            fail("at least one SOCKS node must remain enabled", 2)
        selector["outbounds"] = [tag for tag in socks_order if tag in set(selected)]
        commit(config, original, original_mode)
        print(json.dumps({"ok": True, "action": "upsert", "node": node_tag, "enabled": enabled}))
        return

    if node_tag not in socks_order:
        fail("unknown SOCKS node", 2)

    if action == "delete":
        selected = [str(tag) for tag in selector["outbounds"] if str(tag) != node_tag]
        if not selected:
            fail("at least one SOCKS node must remain enabled", 2)
        config["outbounds"] = [
            item for item in outbounds
            if not (item.get("type") == "socks" and item.get("tag") == node_tag)
        ]
        selector["outbounds"] = selected
        commit(config, original, original_mode)
        print(json.dumps({"ok": True, "action": "delete", "node": node_tag}))
        return

    previous = list(selector["outbounds"])
    selected = set(str(tag) for tag in previous)
    if action == "enable":
        selected.add(node_tag)
    else:
        selected.discard(node_tag)
    updated = [tag for tag in socks_order if tag in selected]
    if not updated:
        fail("at least one SOCKS node must remain enabled", 2)
    if updated == previous:
        print(json.dumps({"ok": True, "changed": False, "node": node_tag, "enabled": action == "enable"}))
        return

    selector["outbounds"] = updated
    commit(config, original, original_mode)

    print(json.dumps({"ok": True, "changed": True, "node": node_tag, "enabled": action == "enable"}))


if __name__ == "__main__":
    main()
