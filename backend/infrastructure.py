"""Infrastructure discovery and impact (blast radius).

BLACKBOX's default view is attacker-centric (what processes ran). This
module reframes it to the *defender's* view the ORTAQ theme asks for: the
target's own infrastructure, discovered from telemetry, with each asset's
compromise state lit up from the reconstruction.

``discover`` builds an asset map — the web service, datastores, sensitive
files, the host, egress — purely from observed events, and marks each asset
normal / touched / compromised based on the reconstructed attack. ``impact``
turns the same evidence into a blast-radius summary: what was actually
reached (root, secrets, data out), proven from the kernel rather than
assumed.

Pure functions over (events, reconstruction); no I/O, fully testable.
"""

from __future__ import annotations

from typing import Any, Iterable

from backend.correlation import WEB_SERVER_NAMES

# Destination ports that identify a backing datastore/cache.
DATASTORE_PORTS = {
    6379: "Redis", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch",
    5672: "RabbitMQ", 2379: "etcd",
}

# Protected paths whose read means a secret was reached (mirrors reconstruction).
SECRET_PATHS = ("/root/", "/etc/shadow", "/etc/sudoers", "flag")

# Asset status, worst-to-best (used to keep the strongest status).
STATUS_RANK = {"compromised": 3, "touched": 2, "normal": 1}


def _proc(e: dict) -> dict:
    return e.get("process") or {}


def _net(e: dict) -> dict:
    return e.get("network") or {}


def _is_private(ip: str | None) -> bool:
    if not ip:
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "::1")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def _bump(asset: dict, status: str) -> None:
    if STATUS_RANK[status] > STATUS_RANK[asset["status"]]:
        asset["status"] = status


def _stage_keys(recon: dict) -> set[str]:
    return {s["key"] for s in recon.get("stages", [])}


def _evidence_ids(recon: dict, key: str) -> list[str]:
    for s in recon.get("stages", []):
        if s["key"] == key:
            return list(s["evidence"])
    return []


def discover(events: Iterable[dict], recon: dict) -> dict[str, Any]:
    """Build the target's asset map with per-asset compromise state."""
    events = list(events)
    stages = _stage_keys(recon)

    hostname = next((e.get("hostname") for e in events if e.get("hostname")), "target")
    host_id = f"host:{hostname}"
    assets: dict[str, dict] = {
        host_id: {
            "id": host_id, "type": "host", "label": hostname,
            "status": "normal", "techniques": [], "evidence": [],
        }
    }
    links: list[dict] = []

    def ensure(aid: str, atype: str, label: str) -> dict:
        if aid not in assets:
            assets[aid] = {
                "id": aid, "type": atype, "label": label,
                "status": "normal", "techniques": [], "evidence": [],
            }
        return assets[aid]

    def link(src: str, dst: str) -> None:
        pair = {"source": src, "target": dst}
        if pair not in links:
            links.append(pair)

    # --- web service(s): web-server processes observed ---
    service_names = set()
    for e in events:
        if e["event_type"] != "process_created":
            continue
        p = _proc(e)
        for cand in (p.get("name"), p.get("parent_name")):
            if cand in WEB_SERVER_NAMES:
                service_names.add(cand)
    for name in sorted(service_names):
        sid = f"service:{name}"
        a = ensure(sid, "service", f"{name} (web app)")
        link(host_id, sid)

    primary_service = next(iter(sorted(service_names)), None)
    primary_sid = f"service:{primary_service}" if primary_service else host_id

    # --- datastores and external egress, from outbound connections ---
    for e in events:
        if e["event_type"] != "network_connection":
            continue
        n = _net(e)
        ip, port = n.get("destination_ip"), n.get("destination_port")
        if port in DATASTORE_PORTS:
            sid = f"store:{DATASTORE_PORTS[port]}:{port}"
            a = ensure(sid, "datastore", f"{DATASTORE_PORTS[port]} :{port}")
            a["evidence"].append(e["event_id"])
            _bump(a, "touched")
            link(primary_sid, sid)
        elif not _is_private(ip):
            eid = f"egress:{ip}:{port}"
            a = ensure(eid, "egress", f"{ip}:{port}")
            a["evidence"].append(e["event_id"])
            _bump(a, "touched")
            link(primary_sid, eid)

    # --- sensitive files reached (from process command lines) ---
    for e in events:
        if e["event_type"] != "process_created":
            continue
        cmd = _proc(e).get("command_line") or ""
        for marker in ("/root/", "/etc/shadow", "/etc/sudoers"):
            if marker in cmd:
                # one asset per concrete-ish path token
                token = _first_path(cmd, marker)
                sid = f"secret:{token}"
                a = ensure(sid, "secret", token)
                a["evidence"].append(e["event_id"])
                link(primary_sid, sid)

    # --- root/privilege asset ---
    priv_id = "priv:root"

    # --- apply compromise state from the reconstruction ---
    if "webshell_rce" in stages or "ssti" in stages:
        for sid in [f"service:{n}" for n in service_names] or [host_id]:
            a = assets.get(sid)
            if a:
                _bump(a, "compromised")
                _merge_tech(a, recon, ("ssti", "webshell_rce"))
        _bump(assets[host_id], "compromised")

    if "sensitive_access" in stages:
        for a in assets.values():
            if a["type"] == "secret":
                _bump(a, "compromised")
                _merge_tech(a, recon, ("sensitive_access",))

    if "privilege_escalation" in stages:
        a = ensure(priv_id, "privilege", "root")
        link(primary_sid, priv_id)
        _bump(a, "compromised")
        a["evidence"] = _evidence_ids(recon, "privilege_escalation")
        _merge_tech(a, recon, ("privilege_escalation",))

    if "outbound_connection" in stages:
        for a in assets.values():
            if a["type"] == "egress":
                _bump(a, "touched")
                _merge_tech(a, recon, ("outbound_connection",))

    return {
        "hostname": hostname,
        "assets": list(assets.values()),
        "links": links,
        "asset_count": len(assets),
    }


def _first_path(cmd: str, marker: str) -> str:
    """Extract a readable path token starting at marker, trimmed at whitespace."""
    idx = cmd.find(marker)
    tail = cmd[idx:]
    for stop in (" ", '"', "'", ";", "|", "&", ")"):
        cut = tail.find(stop)
        if cut != -1:
            tail = tail[:cut]
    return tail[:64] if tail else marker


def _merge_tech(asset: dict, recon: dict, keys: tuple[str, ...]) -> None:
    for s in recon.get("stages", []):
        if s["key"] in keys and s["technique_id"] not in asset["techniques"]:
            asset["techniques"].append(s["technique_id"])


def impact(events: Iterable[dict], recon: dict) -> dict[str, Any]:
    """Blast radius: what the attack actually reached, proven from telemetry."""
    events = list(events)
    stages = _stage_keys(recon)

    root = "privilege_escalation" in stages
    code_exec = "webshell_rce" in stages or "ssti" in stages

    secrets = sorted({
        _first_path(_proc(e).get("command_line") or "", m)
        for e in events if e["event_type"] == "process_created"
        for m in ("/root/", "/etc/shadow", "/etc/sudoers")
        if m in (_proc(e).get("command_line") or "")
    })

    egress = sorted({
        f"{_net(e).get('destination_ip')}:{_net(e).get('destination_port')}"
        for e in events if e["event_type"] == "network_connection"
        and not _is_private(_net(e).get("destination_ip"))
    })

    # Severity: root or secrets read = critical; code exec = high; else medium/low.
    if root or secrets:
        severity = "critical"
    elif code_exec:
        severity = "high"
    elif stages:
        severity = "medium"
    else:
        severity = "low"

    return {
        "severity": severity,
        "code_execution": code_exec,
        "root_achieved": root,
        "secrets_read": secrets,
        "secret_count": len(secrets),
        "egress_attempts": egress,
        "stages": recon.get("stage_count", 0),
    }
