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

    # --- http request nodes + spawned_by edges ---
    for req in https:
        nodes.append(_http_node(req))
        req_t = _ts(req)
        container = req.get("hostname")

        # candidate processes: same container, started within the window
        # after the request, that are not the web server itself.
        best = None
        for e in processes:
            if e.get("hostname") != container:
                continue
            name = e["process"]["name"]
            if name in WEB_SERVER_NAMES:
                continue
            delta = (_ts(e) - req_t).total_seconds()
            if 0 <= delta <= HTTP_SPAWN_WINDOW_S:
                if best is None or _ts(e) < _ts(best):
                    best = e
        if best is not None:
            edges.append(_edge(
                _node_id(req), _node_id(best), "spawned_by",
                f"process started {(_ts(best) - req_t).total_seconds():.2f}s "
                f"after request, same container",
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
