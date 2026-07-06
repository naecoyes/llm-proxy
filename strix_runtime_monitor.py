"""Nscan runtime and egress proxy monitoring helpers."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SING_BOX_CONFIG = "/etc/sing-box/config.json"
DEFAULT_SING_BOX_SERVICE = "sing-box"
DEFAULT_DOCKER_NETWORK = "strix-egress"
DEFAULT_BRIDGE_INTERFACE = "br-strix"
DEFAULT_NODE_CONTROL_HELPER = "/usr/local/sbin/nscan-egress-node-control"
DEFAULT_NODE_METADATA = "/var/lib/nscan/nscan-node-metadata.json"
COMMAND_TIMEOUT_SECONDS = 8
NODE_CHECK_INTERVAL_SECONDS = int(os.environ.get("STRIX_EGRESS_NODE_CHECK_INTERVAL_SECONDS", "86400"))
PROXY_REGION_NETWORKS = (
    (ipaddress.ip_network("85.237.211.0/24"), "UAE"),
    (ipaddress.ip_network("212.115.103.0/24"), "Turkey"),
    (ipaddress.ip_network("82.25.35.0/24"), "UK"),
    (ipaddress.ip_network("109.107.55.0/24"), "Nigeria"),
)
VALID_PROXY_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NODE_CHECK_CACHE: dict[str, dict[str, Any]] = {}
_NODE_CHECK_CACHE_LOCK = threading.Lock()


def get_strix_runtime_status(check_nodes: bool = False) -> dict[str, Any]:
    """Return a redacted view of Nscan runtime and egress proxy state."""
    config_path = os.environ.get("STRIX_EGRESS_SING_BOX_CONFIG", DEFAULT_SING_BOX_CONFIG)
    service_name = os.environ.get("STRIX_EGRESS_SERVICE", DEFAULT_SING_BOX_SERVICE)
    docker_network = os.environ.get("STRIX_DOCKER_NETWORK", DEFAULT_DOCKER_NETWORK)

    warnings: list[str] = []
    config, config_error = read_sing_box_config(config_path)
    if config_error:
        warnings.append(config_error)

    service = get_service_status(service_name)
    metadata = read_node_metadata()
    egress = parse_sing_box_config(config, check_nodes=check_nodes, metadata=metadata) if config else empty_egress_config()
    egress["enabled"] = bool(service.get("enabled"))
    docker = get_docker_network_status(docker_network)
    boundary = build_runtime_boundary(egress, docker_network)

    return {
        "generated_at": now_iso(),
        "service": service,
        "control": {
            "can_control": service.get("control_available", False),
            "method": service.get("control_method") or "unavailable",
            "node_control_available": Path(DEFAULT_NODE_CONTROL_HELPER).is_file(),
            "requires": "systemctl start/stop sing-box, normally via narrow sudoers for the dashboard user",
        },
        "config": {
            "path": config_path,
            "readable": bool(config),
            "error": config_error,
        },
        "egress": egress,
        "docker": docker,
        "boundary": boundary,
        "warnings": warnings + service.get("warnings", []) + docker.get("warnings", []) + egress.get("warnings", []),
    }


def set_strix_egress_node_enabled(node_tag: str, enabled: bool) -> dict[str, Any]:
    """Add or remove one SOCKS node from the automatic selector pool."""
    if not VALID_PROXY_TAG.fullmatch(node_tag):
        raise ValueError("invalid proxy node tag")
    helper_path = os.environ.get("STRIX_EGRESS_NODE_HELPER", DEFAULT_NODE_CONTROL_HELPER)
    if not Path(helper_path).is_file():
        raise RuntimeError(f"proxy node control helper not installed: {helper_path}")

    current = get_strix_runtime_status(check_nodes=False)
    nodes = current.get("egress", {}).get("outbounds", {}).get("socks_nodes", [])
    known_tags = {str(node.get("tag") or "") for node in nodes}
    if node_tag not in known_tags:
        raise ValueError("unknown proxy node tag")
    pool = current.get("egress", {}).get("outbounds", {}).get("auto_pool", [])
    if not enabled and node_tag in pool and len(pool) <= 1:
        raise ValueError("at least one SOCKS node must remain enabled")

    result = run_command(
        [helper_path, node_tag, "enable" if enabled else "disable"],
        allow_sudo=True,
    )
    status = get_strix_runtime_status(check_nodes=False)
    status["last_action"] = {
        "action": "enable-node" if enabled else "disable-node",
        "node": node_tag,
        "ok": result["ok"],
        "returncode": result["returncode"],
        "stdout": trim_output(result["stdout"]),
        "stderr": trim_output(result["stderr"]),
        "method": "sudo-n",
    }
    if not result["ok"]:
        status.setdefault("warnings", []).append(
            f"failed to update proxy node {node_tag}: {trim_output(result['stderr'] or result['stdout'])}"
        )
    return status


def upsert_strix_egress_node(node_tag: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create or update one SOCKS5 node through the root-owned narrow helper."""
    if not VALID_PROXY_TAG.fullmatch(node_tag):
        raise ValueError("invalid proxy node tag")
    helper_path = os.environ.get("STRIX_EGRESS_NODE_HELPER", DEFAULT_NODE_CONTROL_HELPER)
    if not Path(helper_path).is_file():
        raise RuntimeError(f"proxy node control helper not installed: {helper_path}")
    result = run_command(
        [helper_path, node_tag, "upsert"],
        allow_sudo=True,
        input_text=json.dumps(payload),
    )
    if not result["ok"]:
        raise RuntimeError(trim_output(result["stderr"] or result["stdout"]))
    clear_node_check_cache(node_tag)
    return get_strix_runtime_status(check_nodes=False)


def test_strix_egress_node(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify SOCKS5 negotiation, credentials, and an outbound CONNECT before saving."""
    server = str(payload.get("server") or "").strip()
    username = str(payload.get("username") or "")
    password = str(payload.get("password") or "")
    try:
        server_port = int(payload.get("server_port"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid server_port") from exc
    if not server or not 1 <= server_port <= 65535:
        raise ValueError("invalid proxy server or port")

    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    if len(username_bytes) > 255 or len(password_bytes) > 255:
        raise ValueError("SOCKS5 username and password must be at most 255 bytes")

    started = time.time()
    try:
        with socket.create_connection((server, server_port), timeout=5) as connection:
            connection.settimeout(5)
            method = b"\x02" if username_bytes or password_bytes else b"\x00"
            connection.sendall(b"\x05\x01" + method)
            version, selected_method = _recv_exact(connection, 2)
            if version != 5 or selected_method == 0xFF:
                raise OSError("SOCKS5 authentication method rejected")
            if selected_method == 2:
                connection.sendall(
                    b"\x01"
                    + bytes([len(username_bytes)])
                    + username_bytes
                    + bytes([len(password_bytes)])
                    + password_bytes
                )
                auth_version, auth_status = _recv_exact(connection, 2)
                if auth_version != 1 or auth_status != 0:
                    raise OSError("SOCKS5 username or password rejected")
            elif selected_method != 0:
                raise OSError(f"unsupported SOCKS5 authentication method: {selected_method}")

            # A successful CONNECT proves the proxy can establish external traffic,
            # not merely that its TCP listener is open.
            connection.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 443))
            reply_version, reply_status, _, address_type = _recv_exact(connection, 4)
            if reply_version != 5 or reply_status != 0:
                raise OSError(f"SOCKS5 outbound CONNECT failed (code {reply_status})")
            if address_type == 1:
                _recv_exact(connection, 4)
            elif address_type == 3:
                _recv_exact(connection, _recv_exact(connection, 1)[0])
            elif address_type == 4:
                _recv_exact(connection, 16)
            else:
                raise OSError("invalid SOCKS5 reply address type")
            _recv_exact(connection, 2)
    except (OSError, TimeoutError) as exc:
        return {
            "reachable": False,
            "latency_ms": round((time.time() - started) * 1000, 1),
            "error": str(exc),
        }
    return {
        "reachable": True,
        "latency_ms": round((time.time() - started) * 1000, 1),
        "error": "",
    }


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection")
        chunks.extend(chunk)
    return bytes(chunks)


def delete_strix_egress_node(node_tag: str) -> dict[str, Any]:
    """Delete one SOCKS5 node while preserving at least one active route."""
    if not VALID_PROXY_TAG.fullmatch(node_tag):
        raise ValueError("invalid proxy node tag")
    helper_path = os.environ.get("STRIX_EGRESS_NODE_HELPER", DEFAULT_NODE_CONTROL_HELPER)
    if not Path(helper_path).is_file():
        raise RuntimeError(f"proxy node control helper not installed: {helper_path}")
    result = run_command([helper_path, node_tag, "delete"], allow_sudo=True)
    if not result["ok"]:
        raise RuntimeError(trim_output(result["stderr"] or result["stdout"]))
    clear_node_check_cache(node_tag)
    return get_strix_runtime_status(check_nodes=False)


def set_strix_egress_enabled(enabled: bool) -> dict[str, Any]:
    """Start or stop the configured sing-box service, then return fresh status."""
    action = "start" if enabled else "stop"
    service_name = os.environ.get("STRIX_EGRESS_SERVICE", DEFAULT_SING_BOX_SERVICE)
    result = run_service_command(action, service_name, allow_sudo=True)
    status = get_strix_runtime_status(check_nodes=False)
    status["last_action"] = {
        "action": action,
        "ok": result["ok"],
        "returncode": result["returncode"],
        "stdout": trim_output(result["stdout"]),
        "stderr": trim_output(result["stderr"]),
        "method": result.get("method"),
    }
    if not result["ok"]:
        status.setdefault("warnings", []).append(
            f"failed to {action} {service_name}: {trim_output(result['stderr'] or result['stdout'])}"
        )
    return status


def set_strix_egress_startup_enabled(enabled: bool) -> dict[str, Any]:
    """Enable or disable service startup independently from current runtime state."""
    action = "enable" if enabled else "disable"
    service_name = os.environ.get("STRIX_EGRESS_SERVICE", DEFAULT_SING_BOX_SERVICE)
    result = run_service_command(action, service_name, allow_sudo=True)
    status = get_strix_runtime_status(check_nodes=False)
    status["last_action"] = {
        "action": action,
        "ok": result["ok"],
        "returncode": result["returncode"],
        "stdout": trim_output(result["stdout"]),
        "stderr": trim_output(result["stderr"]),
        "method": result.get("method"),
    }
    if not result["ok"]:
        status.setdefault("warnings", []).append(
            f"failed to {action} startup for {service_name}: {trim_output(result['stderr'] or result['stdout'])}"
        )
    return status


def restart_strix_egress() -> dict[str, Any]:
    service_name = os.environ.get("STRIX_EGRESS_SERVICE", DEFAULT_SING_BOX_SERVICE)
    result = run_service_command("restart", service_name, allow_sudo=True)
    status = get_strix_runtime_status(check_nodes=False)
    status["last_action"] = {
        "action": "restart",
        "ok": result["ok"],
        "returncode": result["returncode"],
        "stdout": trim_output(result["stdout"]),
        "stderr": trim_output(result["stderr"]),
        "method": result.get("method"),
    }
    if not result["ok"]:
        status.setdefault("warnings", []).append(
            f"failed to restart {service_name}: {trim_output(result['stderr'] or result['stdout'])}"
        )
    return status


def read_sing_box_config(path: str) -> tuple[dict[str, Any] | None, str | None]:
    config_path = Path(path)
    try:
        return json.loads(config_path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, f"sing-box config not found: {path}"
    except PermissionError:
        result = run_command(["cat", path], allow_sudo=True)
        if result["ok"]:
            try:
                return json.loads(result["stdout"]), None
            except json.JSONDecodeError as exc:
                return None, f"sing-box config is not valid JSON: {exc}"
        return None, f"cannot read sing-box config: {trim_output(result['stderr'] or result['stdout'])}"
    except json.JSONDecodeError as exc:
        return None, f"sing-box config is not valid JSON: {exc}"
    except OSError as exc:
        return None, f"cannot read sing-box config: {exc}"


def read_node_metadata() -> dict[str, Any]:
    try:
        value = json.loads(Path(DEFAULT_NODE_METADATA).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return {}


def parse_sing_box_config(config: dict[str, Any], check_nodes: bool = False, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    inbounds = config.get("inbounds") or []
    outbounds = config.get("outbounds") or []
    route = config.get("route") or {}
    dns = config.get("dns") or {}

    tun_inbound = next((item for item in inbounds if item.get("type") == "tun"), {})
    include_interface = tun_inbound.get("include_interface") or []
    socks_nodes = []
    outbound_tags = {str(item.get("tag") or "") for item in outbounds}
    region_counts: dict[str, int] = {}
    metadata = metadata or {}

    for outbound in outbounds:
        if outbound.get("type") != "socks":
            continue
        server = str(outbound.get("server") or "")
        node_metadata = metadata.get(str(outbound.get("tag") or ""), {})
        region = str(node_metadata.get("location") or infer_proxy_region(server) or "")
        if region:
            region_counts[region] = region_counts.get(region, 0) + 1
        display_name = str(
            node_metadata.get("label")
            or (f"{region}-{region_counts[region]}" if region else "")
            or outbound.get("tag")
            or server
        )
        node = {
            "tag": outbound.get("tag") or "",
            "display_name": display_name,
            "region": region,
            "server": server,
            "server_port": outbound.get("server_port"),
            "username": outbound.get("username") or "",
            "password_masked": mask_secret(str(outbound.get("password") or "")),
            "version": outbound.get("version") or "5",
        }
        socks_nodes.append(node)

    if not socks_nodes and metadata:
        for tag, node_metadata in metadata.items():
            if not isinstance(node_metadata, dict):
                continue
            server = str(
                node_metadata.get("server")
                or node_metadata.get("host")
                or node_metadata.get("ip")
                or ""
            )
            region = str(node_metadata.get("location") or infer_proxy_region(server) or "")
            if region:
                region_counts[region] = region_counts.get(region, 0) + 1
            socks_nodes.append(
                {
                    "tag": str(tag),
                    "display_name": str(
                        node_metadata.get("label")
                        or (f"{region}-{region_counts[region]}" if region else "")
                        or tag
                    ),
                    "region": region,
                    "server": server,
                    "server_port": node_metadata.get("server_port")
                    or node_metadata.get("port"),
                    "username": str(node_metadata.get("username") or ""),
                    "password_masked": mask_secret(str(node_metadata.get("password") or "")),
                    "version": str(node_metadata.get("version") or "5"),
                    "metadata_only": True,
                }
            )

    selector = next(
        (item for item in outbounds if item.get("tag") in {"proxy-auto", "proxy-selector"} and item.get("outbounds")),
        {},
    )
    proxy_pool = list(selector.get("outbounds") or [])
    display_name_by_tag = {str(node.get("tag") or ""): str(node.get("display_name") or "") for node in socks_nodes}
    auto_actions: list[dict[str, Any]] = []
    warnings: list[str] = []
    for node in socks_nodes:
        node["in_auto_pool"] = node.get("tag") in proxy_pool
        if node.get("server") and node.get("server_port"):
            cache_key = node_check_cache_key(node)
            with _NODE_CHECK_CACHE_LOCK:
                cached_check = _NODE_CHECK_CACHE.get(cache_key)
            if check_nodes:
                if cached_check and not node_check_is_due(cached_check):
                    tcp_check = dict(cached_check)
                else:
                    tcp_check = check_tcp(str(node["server"]), int(node["server_port"]))
                    tcp_check["checked_at"] = now_iso()
                    with _NODE_CHECK_CACHE_LOCK:
                        _NODE_CHECK_CACHE[cache_key] = dict(tcp_check)
                enrich_node_check_schedule(tcp_check)
                node["tcp_check"] = tcp_check
                if node["in_auto_pool"] and not tcp_check.get("reachable", False):
                    action = auto_disable_unreachable_node(str(node.get("tag") or ""), tcp_check)
                    auto_actions.append(action)
                    if action.get("ok"):
                        node["in_auto_pool"] = False
                        if node.get("tag") in proxy_pool:
                            proxy_pool.remove(node.get("tag"))
                    else:
                        warnings.append(
                            f"failed to auto-disable unavailable SOCKS node {node.get('tag')}: "
                            f"{trim_output(action.get('stderr') or action.get('stdout') or action.get('error') or '')}"
                        )
            else:
                if cached_check:
                    tcp_check = dict(cached_check)
                    enrich_node_check_schedule(tcp_check)
                    node["tcp_check"] = tcp_check

    return {
        "enabled": False,
        "node_check_interval_seconds": NODE_CHECK_INTERVAL_SECONDS,
        "auto_actions": auto_actions,
        "warnings": warnings,
        "mode": "sing-box tun",
        "tun": {
            "tag": tun_inbound.get("tag") or "",
            "interface_name": tun_inbound.get("interface_name") or "",
            "address": tun_inbound.get("address") or [],
            "include_interface": include_interface,
            "auto_route": bool(tun_inbound.get("auto_route")),
            "auto_redirect": bool(tun_inbound.get("auto_redirect")),
            "strict_route": bool(tun_inbound.get("strict_route")),
        },
        "route": {
            "final": route.get("final") or "",
            "auto_detect_interface": bool(route.get("auto_detect_interface")),
        },
        "dns": {
            "final": dns.get("final") or "",
            "strategy": dns.get("strategy") or "",
        },
        "outbounds": {
            "total": len(outbounds),
            "tags": sorted(tag for tag in outbound_tags if tag),
            "auto_selector": selector.get("tag") or "",
            "auto_pool": proxy_pool,
            "auto_pool_display": [display_name_by_tag.get(str(tag), str(tag)) for tag in proxy_pool],
            "socks_nodes": socks_nodes,
        },
    }


def node_check_cache_key(node: dict[str, Any]) -> str:
    """Bind a cached result to both the node tag and its current endpoint."""
    return "\0".join(
        (
            str(node.get("tag") or ""),
            str(node.get("server") or ""),
            str(node.get("server_port") or ""),
        )
    )


def clear_node_check_cache(node_tag: str) -> None:
    """Discard checks after a node is edited or deleted."""
    prefix = f"{node_tag}\0"
    with _NODE_CHECK_CACHE_LOCK:
        stale_keys = [key for key in _NODE_CHECK_CACHE if key.startswith(prefix)]
        for key in stale_keys:
            _NODE_CHECK_CACHE.pop(key, None)


def node_check_is_due(cached_check: dict[str, Any], now: float | None = None) -> bool:
    """Return true when a cached node connectivity result is older than the daily check interval."""
    checked_at = cached_check.get("checked_at")
    if not checked_at:
        return True
    try:
        checked = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return True
    return (time.time() if now is None else now) - checked >= NODE_CHECK_INTERVAL_SECONDS


def enrich_node_check_schedule(tcp_check: dict[str, Any]) -> None:
    """Attach check cadence metadata used by the dashboard."""
    tcp_check["check_interval_seconds"] = NODE_CHECK_INTERVAL_SECONDS
    checked_at = tcp_check.get("checked_at")
    if not checked_at:
        return
    try:
        checked = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return
    tcp_check["next_check_at"] = datetime.fromtimestamp(
        checked.timestamp() + NODE_CHECK_INTERVAL_SECONDS,
        timezone.utc,
    ).isoformat()


def auto_disable_unreachable_node(node_tag: str, tcp_check: dict[str, Any]) -> dict[str, Any]:
    """Remove an unavailable SOCKS node from the automatic selector pool."""
    helper_path = os.environ.get("STRIX_EGRESS_NODE_HELPER", DEFAULT_NODE_CONTROL_HELPER)
    action = {
        "action": "auto-disable-node",
        "node": node_tag,
        "reason": tcp_check.get("error") or "unreachable",
        "latency_ms": tcp_check.get("latency_ms"),
        "ok": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    if not Path(helper_path).is_file():
        action["error"] = f"proxy node control helper not installed: {helper_path}"
        return action
    result = run_command([helper_path, node_tag, "disable"], allow_sudo=True)
    action.update(
        {
            "ok": result["ok"],
            "returncode": result["returncode"],
            "stdout": trim_output(result["stdout"]),
            "stderr": trim_output(result["stderr"]),
        }
    )
    return action


def empty_egress_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "mode": "sing-box tun",
        "tun": {
            "tag": "",
            "interface_name": "",
            "address": [],
            "include_interface": [],
            "auto_route": False,
            "auto_redirect": False,
            "strict_route": False,
        },
        "route": {"final": "", "auto_detect_interface": False},
        "dns": {"final": "", "strategy": ""},
        "outbounds": {
            "total": 0,
            "tags": [],
            "auto_selector": "",
            "auto_pool": [],
            "auto_pool_display": [],
            "socks_nodes": [],
        },
    }


def get_service_status(service_name: str) -> dict[str, Any]:
    active = run_service_command("is-active", service_name, allow_sudo=True)
    enabled = run_service_command("is-enabled", service_name, allow_sudo=True)
    control_probe = run_service_command("is-active", service_name, allow_sudo=False)

    active_state = trim_output(active["stdout"]) or "unknown"
    enabled_state = trim_output(enabled["stdout"]) or "unknown"
    return {
        "name": service_name,
        "active_state": active_state,
        "enabled_state": enabled_state,
        "enabled": active_state == "active",
        "startup_enabled": enabled_state == "enabled",
        "control_available": shutil.which("systemctl") is not None,
        "control_method": active.get("method"),
        "direct_systemctl_ok": control_probe["ok"] or control_probe["returncode"] in {0, 3},
        "warnings": collect_service_warnings(active, enabled),
    }


def get_docker_network_status(network_name: str) -> dict[str, Any]:
    if not shutil.which("docker"):
        return {
            "network": network_name,
            "available": False,
            "warnings": ["docker command not found"],
        }
    result = run_command(["docker", "network", "inspect", network_name], allow_sudo=False)
    if not result["ok"]:
        return {
            "network": network_name,
            "available": False,
            "warnings": [f"docker network inspect failed: {trim_output(result['stderr'] or result['stdout'])}"],
        }
    try:
        networks = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        return {
            "network": network_name,
            "available": False,
            "warnings": [f"docker network inspect returned invalid JSON: {exc}"],
        }
    network = networks[0] if networks else {}
    options = network.get("Options") or {}
    containers = network.get("Containers") or {}
    return {
        "network": network_name,
        "available": True,
        "id": network.get("Id") or "",
        "driver": network.get("Driver") or "",
        "scope": network.get("Scope") or "",
        "bridge_name": options.get("com.docker.network.bridge.name") or "",
        "containers": len(containers),
        "warnings": [],
    }


def build_runtime_boundary(egress: dict[str, Any], docker_network: str) -> dict[str, Any]:
    include_interface = egress.get("tun", {}).get("include_interface") or []
    expected_bridge = os.environ.get("STRIX_EGRESS_BRIDGE", DEFAULT_BRIDGE_INTERFACE)
    proxy_env = {
        key: mask_url_secret(value)
        for key, value in os.environ.items()
        if key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    }
    return {
        "expected_docker_network": docker_network,
        "expected_bridge_interface": expected_bridge,
        "include_interface": include_interface,
        "only_strix_bridge": include_interface == [expected_bridge],
        "host_proxy_env": proxy_env,
        "host_proxy_env_empty": not bool(proxy_env),
        "note": "Egress proxy control targets sing-box TUN for Nscan Docker bridge traffic only; it does not change LLM provider routing.",
    }


def run_service_command(action: str, service_name: str, allow_sudo: bool) -> dict[str, Any]:
    if not shutil.which("systemctl"):
        return {
            "ok": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "systemctl command not found",
            "method": "unavailable",
        }
    args = ["systemctl", action, service_name]
    result = run_command(args, allow_sudo=False)
    result["method"] = "direct"
    if service_status_is_acceptable(action, result):
        return result
    if allow_sudo and os.environ.get("STRIX_RUNTIME_ALLOW_SUDO", "1") != "0":
        sudo_result = run_command(args, allow_sudo=True)
        sudo_result["method"] = "sudo-n"
        return sudo_result
    return result


def service_status_is_acceptable(action: str, result: dict[str, Any]) -> bool:
    if result["ok"]:
        return True
    if action == "is-active" and result["returncode"] in {3, 4}:
        return True
    if action == "is-enabled" and result["returncode"] in {1, 3, 4}:
        return True
    return False


def collect_service_warnings(*results: dict[str, Any]) -> list[str]:
    warnings = []
    for result in results:
        stderr = trim_output(result.get("stderr") or "")
        if stderr and result.get("returncode") not in {0, 1, 3, 4}:
            warnings.append(stderr)
    return warnings


def run_command(
    args: list[str], allow_sudo: bool, input_text: str | None = None
) -> dict[str, Any]:
    command = list(args)
    if allow_sudo:
        if not shutil.which("sudo"):
            return {
                "ok": False,
                "returncode": 127,
                "stdout": "",
                "stderr": "sudo command not found",
            }
        command = ["sudo", "-n", *command]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            input=input_text,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": 124,
            "stdout": "",
            "stderr": f"command timed out: {' '.join(command)}",
        }
    except OSError as exc:
        return {
            "ok": False,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def check_tcp(host: str, port: int) -> dict[str, Any]:
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=2.5):
            pass
    except OSError as exc:
        return {
            "reachable": False,
            "latency_ms": round((time.time() - started) * 1000, 1),
            "error": str(exc),
        }
    return {
        "reachable": True,
        "latency_ms": round((time.time() - started) * 1000, 1),
        "error": "",
    }


def infer_proxy_region(server: str) -> str:
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        return ""
    for network, region in PROXY_REGION_NETWORKS:
        if address in network:
            return region
    return ""


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}***{value[-2:]}"


def mask_url_secret(value: str) -> str:
    if "://" not in value or "@" not in value:
        return value
    scheme, rest = value.split("://", 1)
    credentials, host = rest.split("@", 1)
    if ":" in credentials:
        username, _password = credentials.split(":", 1)
        return f"{scheme}://{username}:***@{host}"
    return f"{scheme}://***@{host}"


def trim_output(value: str, limit: int = 240) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
