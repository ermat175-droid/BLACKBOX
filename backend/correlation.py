"""Correlation Engine.

Turns a flat list of normalized events into a connected incident graph:

    nodes  - processes, http requests, network connections
    edges  - parent_of   (process -> child process, by pid/parent_pid)
             spawned_by   (http request -> process it triggered, by time)
             connected_to (process -> outbound network connection)

The engine is deliberately explicit: every edge records *why* it was
drawn (the matching rule and the evidence), so a reconstruction can be
explained and audited rather than trusted blindly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable
from urllib.parse import unquote

# How long after an HTTP request a spawned process may appear and still be
# attributed to that request (seconds).
HTTP_SPAWN_WINDOW_S = 5.0

# Process names that are the web server itself, not attacker-spawned work.
WEB_SERVER_NAMES = {"apache2", "httpd", "nginx", "php-fpm", "node", "python3"}


def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["timestamp"])


def _node_id(event: dict) -> str:
    return event["event_id"]


def _process_node(event: dict) -> dict:
    p = event["process"]
    return {
        "id": _node_id(event),
        "kind": "process",
        "label": p["name"],
        "pid": p["pid"],
        "parent_pid": p["parent_pid"],
        "command_line": p["command_line"],
        "timestamp": event["timestamp"],
        "container": event.get("hostname"),
    }


def _http_node(event: dict) -> dict:
    h = event["http"]
    return {
        "id": _node_id(event),
        "kind": "http_request",
        "label": f"{h['method']} {h['path']}",
        "status": h["status"],
        "source_ip": event["network"]["source_ip"],
        "timestamp": event["timestamp"],
        "container": event.get("hostname"),
    }


def _network_node(event: dict) -> dict:
    n = event["network"]
    dst = f"{n['destination_ip']}:{n['destination_port']}"
    return {
        "id": _node_id(event),
        "kind": "network",
        "label": dst,
        "destination_ip": n["destination_ip"],
        "destination_port": n["destination_port"],
        "protocol": n["protocol"],
        "pid": event["process"]["pid"],
        "timestamp": event["timestamp"],
        "container": event.get("hostname"),
    }


def _edge(src: str, dst: str, kind: str, reason: str) -> dict:
    return {"source": src, "target": dst, "kind": kind, "reason": reason}


def _shares_command(decoded_path: str, command_line: str) -> bool:
    """True if the request path carried the process command (web shell).

    Compares on a distinctive slice of the command so that a short,
    common command does not match unrelated requests.
    """
    cmd = command_line.strip()
    # drop a leading "sh -c" / "/bin/sh -c" wrapper to reach the payload
    for prefix in ("/bin/sh -c", "sh -c", "/bin/bash -c", "bash -c"):
        if cmd.startswith(prefix):
            cmd = cmd[len(prefix):]
            break
    # strip residual separators and quoting around the real command
    cmd = cmd.strip().lstrip("-").strip().strip("\"'").strip()
    probe = cmd[:24]
    return len(probe) >= 4 and probe in decoded_path


def correlate(events: Iterable[dict]) -> dict[str, Any]:
    """Build an incident graph from normalized events.

    Returns {"nodes": [...], "edges": [...], "roots": [node_id, ...]}.
    """

    events = sorted(events, key=_ts)

    processes = [e for e in events if e["event_type"] == "process_created"]
    https = [e for e in events if e["event_type"] == "http_request"]
    networks = [e for e in events if e["event_type"] == "network_connection"]

    nodes: list[dict] = []
    edges: list[dict] = []

    # --- process nodes, indexed by (container, pid) ---
    proc_by_pid: dict[tuple[str | None, int], dict] = {}
    for e in processes:
        node = _process_node(e)
        nodes.append(node)
        if node["pid"] is not None:
            proc_by_pid[(node["container"], node["pid"])] = e

    # parent_of edges, within the same container
    for e in processes:
        p = e["process"]
        if p["parent_pid"] is None:
            continue
        parent = proc_by_pid.get((e.get("hostname"), p["parent_pid"]))
        if parent is not None:
            edges.append(_edge(
                _node_id(parent), _node_id(e), "parent_of",
                f"parent_pid {p['parent_pid']} == pid of {parent['process']['name']}",
            ))

    for req in https:
        nodes.append(_http_node(req))

    # --- spawned_by edges ---
    # A process is attributed to an HTTP request only when its *parent* is
    # the web server (so it was spawned while handling a request), and then
    # to the most recent request before it in the same container. This
    # avoids the false matches a pure time window produces when many
    # requests (e.g. blind SQLi) happen in the same seconds.
    https_by_container: dict[str | None, list[dict]] = {}
    for req in https:
        https_by_container.setdefault(req.get("hostname"), []).append(req)

    for e in processes:
        if e["process"].get("parent_name") not in WEB_SERVER_NAMES:
            continue
        proc_t = _ts(e)
        container = e.get("hostname")

        cmd = (e["process"].get("command_line") or "").strip()

        in_window = []
        for req in https_by_container.get(container, []):
            delta = (proc_t - _ts(req)).total_seconds()
            # allow a small negative slack: Apache logs at 1s resolution,
            # so the triggering request can share the process's second.
            if -1.0 <= delta <= HTTP_SPAWN_WINDOW_S:
                in_window.append(req)

        if not in_window:
            continue

        # Strongest signal: the request that carried the command (e.g. a
        # web shell ?c=<cmd>) — its decoded path contains the command line.
        content_match = None
        if cmd:
            for req in in_window:
                decoded = unquote(req["http"].get("path") or "")
                if _shares_command(decoded, cmd):
                    content_match = req
                    break

        if content_match is not None:
            candidate, how = content_match, "carried the command"
        else:
            # Fall back to the most recent request in the window.
            candidate = max(in_window, key=_ts)
            how = (f"spawned by web server "
                   f"{(proc_t - _ts(candidate)).total_seconds():.2f}s after it")

        edges.append(_edge(
            _node_id(candidate), _node_id(e), "spawned_by",
            f"{e['process']['name']} {how}",
        ))

    # --- network nodes + connected_to edges ---
    for net in networks:
        nodes.append(_network_node(net))
        pid = net["process"]["pid"]
        container = net.get("hostname")
        proc = proc_by_pid.get((container, pid)) if pid is not None else None
        if proc is not None:
            edges.append(_edge(
                _node_id(proc), _node_id(net), "connected_to",
                f"network connection from pid {pid} "
                f"({proc['process']['name']})",
            ))

    # roots: nodes that are never a target of an edge
    targets = {e["target"] for e in edges}
    roots = [n["id"] for n in nodes if n["id"] not in targets]

    return {"nodes": nodes, "edges": edges, "roots": roots}
