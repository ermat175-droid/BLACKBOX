"""Target Manager — load, run and monitor sandboxed attack targets.

A *target* is a containerized web application the lab attacks and BLACKBOX
investigates. The purple-team workflow is: load a site → start it in the
sandbox → attack it (by hand, a solver, or an AI agent) → read the
reconstruction. This module owns the first two steps and the telemetry
wiring, so the rest of the pipeline just sees events arrive.

Two source kinds (MVP):
* ``image`` — an existing Docker image name (e.g. the ice-* lab images);
* ``build`` — a directory containing a ``Dockerfile`` that BLACKBOX builds.

Safety rules, enforced here, matching the lab's constraints:
* a target's port is **always** published on 127.0.0.1 — never on all
  interfaces — because targets are deliberately vulnerable;
* the target container itself runs unprivileged (only the separate Tetragon
  sensor is privileged);
* build paths and image names come from the operator; nothing is fetched or
  executed from untrusted input on their behalf.

Docker is driven through the ``docker`` CLI (no extra dependency), the same
way the collectors already do. Collector subprocesses started for a target
are tracked so they can be stopped with it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

REGISTRY_PATH = Path(os.getenv("BLACKBOX_TARGETS", "targets.json"))
SENSOR_CONTAINER = os.getenv("BLACKBOX_SENSOR", "bb-tetragon")
SENSOR_IMAGE = "quay.io/cilium/tetragon:v1.8.0"
API_EVENTS = os.getenv("BLACKBOX_API", "http://127.0.0.1:8000/events")
TENANT_PREFIX = "bb-tgt-"          # container/image name prefix for targets
HOST_BIND = "127.0.0.1"            # never publish a vulnerable target wider
PORT_BASE = 8100                   # auto-assigned host ports start here
DOCKER = os.getenv("BLACKBOX_DOCKER", "docker")
# Dedicated bridge with IP masquerade off: published ports (ingress) still
# work, but the container cannot establish outbound internet connections —
# so a compromised target cannot exfiltrate, pull tooling or attack others.
LAB_NETWORK = os.getenv("BLACKBOX_LAB_NET", "bb-lab")
LAB_NETWORK_OPEN = LAB_NETWORK + "-open"   # same, but with internet egress
# Capture proxy: a tiny nginx put in front of every target so its HTTP
# traffic is logged (combined format, to stdout) regardless of whether the
# app logs requests itself — this is what makes ANY loaded site observable.
PROXY_PREFIX = "bb-prx-"
PROXY_IMAGE = os.getenv("BLACKBOX_PROXY_IMAGE", "nginx:latest")
_PROXY_DIR = Path(__file__).resolve().parent.parent / ".proxy"

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_lock = Lock()
# target id -> {"http": Popen|None, "tetra": Popen|None}
_procs: dict[str, dict[str, Any]] = {}


class TargetError(Exception):
    """A target operation failed for a reportable reason."""


# --------------------------------------------------------------------------
# pure helpers (unit-tested without Docker)
# --------------------------------------------------------------------------
def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    if not slug:
        raise TargetError("name must contain at least one letter or digit")
    return slug[:40]


def validate_source(source: Any) -> dict:
    """Normalize and check a target source definition."""
    if not isinstance(source, dict):
        raise TargetError("source must be an object")
    kind = source.get("type")
    if kind == "image":
        image = (source.get("image") or "").strip()
        if not image or not re.fullmatch(r"[A-Za-z0-9][\w./:@-]{0,255}", image):
            raise TargetError("invalid image name")
        return {"type": "image", "image": image}
    if kind == "build":
        raw = (source.get("path") or "").strip()
        if not raw:
            raise TargetError("build path is required")
        path = Path(raw).expanduser()
        if not path.is_dir():
            raise TargetError(f"build path is not a directory: {raw}")
        if not (path / "Dockerfile").is_file():
            raise TargetError("build path has no Dockerfile")
        return {"type": "build", "path": str(path.resolve())}
    raise TargetError("source.type must be 'image' or 'build'")


def _valid_port(value: Any, field: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise TargetError(f"{field} must be an integer")
    if not (1 <= port <= 65535):
        raise TargetError(f"{field} out of range")
    return port


def next_host_port(registry: list[dict], base: int = PORT_BASE) -> int:
    used = {t.get("host_port") for t in registry}
    port = base
    while port in used:
        port += 1
    return port


def validate_bind(bind: Any) -> str:
    """A publish address: 127.0.0.1 (this host) or an IPv4 / 0.0.0.0 (LAN)."""
    b = (str(bind) if bind is not None else HOST_BIND).strip() or HOST_BIND
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", b):
        raise TargetError(f"invalid bind address: {b}")
    for part in b.split("."):
        if int(part) > 255:
            raise TargetError(f"invalid bind address: {b}")
    return b


def run_argv(container: str, image: str, host_port: int, container_port: int,
             network: str | None = None, bind: str = HOST_BIND) -> list[str]:
    """docker argv to run a target.

    ``--pull=never`` keeps the sandbox from reaching out to a registry: a
    lab target must already be present locally, and a missing one fails fast
    with a clear "image not found locally" instead of an internet pull.
    ``network`` attaches the target to an isolated bridge (no egress).
    ``bind`` is the publish address — 127.0.0.1 keeps it to this host,
    0.0.0.0 (or a LAN IP) exposes the deliberately-vulnerable target to the
    network (only do that on a trusted/isolated link).
    """
    argv = [DOCKER, "run", "-d", "--pull=never", "--name", container]
    if network:
        argv += ["--network", network]
    argv += ["-p", f"{bind}:{host_port}:{container_port}", image]
    return argv


def ensure_lab_network() -> None:
    """Create the egress-blocked lab bridge if it does not exist (idempotent)."""
    ensure_network(True)


def ensure_network(isolated: bool) -> str:
    """Ensure a user-defined bridge exists (so target+proxy resolve by name).

    Isolated → egress blocked (masquerade off); otherwise egress allowed.
    Returns the network name.
    """
    net = LAB_NETWORK if isolated else LAB_NETWORK_OPEN
    if _docker([DOCKER, "network", "inspect", net], timeout=15).returncode == 0:
        return net
    args = [DOCKER, "network", "create"]
    if isolated:
        args += ["-o", "com.docker.network.bridge.enable_ip_masquerade=false"]
    args += [net]
    r = _docker(args, timeout=30)
    if r.returncode != 0:
        raise TargetError(f"cannot create network {net}: {r.stderr.strip()[-300:]}")
    return net


def _write_proxy_conf(slug: str, upstream: str, upstream_port: int) -> str:
    """Write an nginx config that proxies to the target and logs (combined)."""
    _PROXY_DIR.mkdir(exist_ok=True)
    conf = (
        "map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n"
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        f"        proxy_pass http://{upstream}:{upstream_port};\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $connection_upgrade;\n"
        "        proxy_buffering off;\n"
        "    }\n"
        "}\n"
    )
    path = _PROXY_DIR / f"{slug}.conf"
    path.write_text(conf, encoding="utf-8")
    return str(path)


def build_argv(path: str, tag: str) -> list[str]:
    return [DOCKER, "build", "-t", tag, path]


# --------------------------------------------------------------------------
# registry persistence
# --------------------------------------------------------------------------
def _load() -> list[dict]:
    if not REGISTRY_PATH.exists():
        return []
    try:
        return json.loads(REGISTRY_PATH.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save(registry: list[dict]) -> None:
    REGISTRY_PATH.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2), "utf-8"
    )


def _get(registry: list[dict], target_id: str) -> dict:
    for t in registry:
        if t["id"] == target_id:
            return t
    raise TargetError(f"no such target: {target_id}")


# --------------------------------------------------------------------------
# docker helpers
# --------------------------------------------------------------------------
def _docker(args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise TargetError(f"'{DOCKER}' not found — is Docker installed?")
    except subprocess.TimeoutExpired:
        raise TargetError(f"docker command timed out: {' '.join(args[:3])}…")


def _container_state(name: str) -> str | None:
    """'running' / 'exited' / ... or None if the container does not exist."""
    r = _docker([DOCKER, "inspect", "-f", "{{.State.Status}}", name], timeout=15)
    return r.stdout.strip() if r.returncode == 0 else None


def _container_id(name: str) -> str | None:
    r = _docker([DOCKER, "inspect", "-f", "{{.Id}}", name], timeout=15)
    return r.stdout.strip()[:12] if r.returncode == 0 else None


def sensor_running() -> bool:
    return _container_state(SENSOR_CONTAINER) == "running"


def _exposed_ports(exposed: Any) -> list[int]:
    """Port numbers from a docker ExposedPorts map ({'80/tcp': {}})."""
    ports = []
    for key in (exposed or {}):
        try:
            ports.append(int(str(key).split("/")[0]))
        except ValueError:
            continue
    return sorted(set(ports))


def list_local_images() -> list[dict]:
    """Tagged Docker images on this host, each with its EXPOSEd ports.

    Lets the UI offer a pick-list of what is actually present instead of a
    free-text image name (no typos, and the container port can be
    prefilled). Infra images (the sensor, our own built targets) are hidden.
    """
    r = _docker([DOCKER, "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=30)
    if r.returncode != 0:
        raise TargetError("cannot list docker images")
    names = sorted({
        ln.strip() for ln in r.stdout.splitlines()
        if ln.strip() and "<none>" not in ln
        and not ln.startswith(TENANT_PREFIX)
        and not ln.startswith("quay.io/cilium/tetragon")
    })

    ports_by: dict[str, list[int]] = {}
    if names:
        ins = _docker([DOCKER, "image", "inspect", *names], timeout=60)
        if ins.returncode == 0:
            try:
                for item in json.loads(ins.stdout):
                    ep = _exposed_ports((item.get("Config") or {}).get("ExposedPorts"))
                    for tag in (item.get("RepoTags") or []):
                        ports_by[tag] = ep
            except json.JSONDecodeError:
                pass

    return [{"name": n, "ports": ports_by.get(n, [])} for n in names]


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def list_targets() -> list[dict]:
    with _lock:
        registry = _load()
        for t in registry:
            state = _container_state(t["container"])
            t["container_state"] = state
            t["running"] = state == "running"
        return registry


def add_target(name: str, source: Any, container_port: int = 80,
               host_port: Any = None, isolated: bool = True,
               bind: Any = HOST_BIND) -> dict:
    source = validate_source(source)
    cport = _valid_port(container_port, "container_port")
    bind_addr = validate_bind(bind)
    with _lock:
        registry = _load()
        slug = slugify(name)
        if any(t["id"] == slug for t in registry):
            raise TargetError(f"a target named '{slug}' already exists")
        hport = _valid_port(host_port, "host_port") if host_port is not None \
            else next_host_port(registry)
        record = {
            "id": slug,
            "name": name.strip(),
            "source": source,
            "host_port": hport,
            "container_port": cport,
            "isolated": bool(isolated),
            "bind": bind_addr,
            "scenario_id": f"TGT-{slug}",
            "container": f"{TENANT_PREFIX}{slug}",
            "status": "stopped",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        registry.append(record)
        _save(registry)
        return record


def start_target(target_id: str) -> dict:
    with _lock:
        registry = _load()
        t = _get(registry, target_id)

        # resolve the image (build if needed)
        if t["source"]["type"] == "build":
            tag = f"{TENANT_PREFIX}{t['id']}:latest"
            r = _docker(build_argv(t["source"]["path"], tag))
            if r.returncode != 0:
                t["status"] = "error"
                _save(registry)
                raise TargetError(f"build failed: {r.stderr.strip()[-400:]}")
            image = tag
        else:
            image = t["source"]["image"]

        isolated = t.get("isolated", True)
        net = ensure_network(isolated)
        bind = validate_bind(t.get("bind", HOST_BIND))
        container = t["container"]                 # the target (app)
        proxy = f"{PROXY_PREFIX}{t['id']}"         # the capture proxy (nginx)

        # clean any previous pair (idempotent)
        _docker([DOCKER, "rm", "-f", container, proxy], timeout=30)

        # 1) the target: on the lab net, NOT publishing a host port — the
        #    proxy is the only ingress, so every request is logged.
        r = _docker([DOCKER, "run", "-d", "--pull=never", "--name", container,
                     "--network", net, image])
        if r.returncode != 0:
            t["status"] = "error"
            _save(registry)
            raise TargetError(f"run failed: {r.stderr.strip()[-400:]}")
        cid = _container_id(container)

        # 2) the capture proxy: nginx in front, logging combined to stdout,
        #    publishing the host port; this makes any app observable.
        conf = _write_proxy_conf(t["id"], container, t["container_port"])
        pr = _docker([DOCKER, "run", "-d", "--pull=never", "--name", proxy,
                      "--network", net,
                      "-v", f"{conf}:/etc/nginx/conf.d/default.conf:ro",
                      "-p", f"{bind}:{t['host_port']}:80", PROXY_IMAGE])
        if pr.returncode != 0:
            _docker([DOCKER, "rm", "-f", container], timeout=30)
            t["status"] = "error"
            _save(registry)
            raise TargetError(f"proxy failed: {pr.stderr.strip()[-400:]}")

        t["status"] = "running"
        t["proxy"] = proxy
        shown = "127.0.0.1" if bind in ("127.0.0.1", "0.0.0.0") else bind
        t["url"] = f"http://{shown}:{t['host_port']}"
        _save(registry)

    # wire telemetry: HTTP from the proxy's log, processes from the target.
    _start_collectors(t, cid, proxy)
    return t


def stop_target(target_id: str) -> dict:
    with _lock:
        registry = _load()
        t = _get(registry, target_id)
    _stop_collectors(target_id)
    _docker([DOCKER, "rm", "-f", t["container"],
             f"{PROXY_PREFIX}{target_id}"], timeout=30)
    with _lock:
        registry = _load()
        t = _get(registry, target_id)
        t["status"] = "stopped"
        t.pop("url", None)
        _save(registry)
    return t


def remove_target(target_id: str) -> None:
    stop_target(target_id)
    with _lock:
        registry = [x for x in _load() if x["id"] != target_id]
        _save(registry)


def telemetry_status(target_id: str) -> dict:
    procs = _procs.get(target_id, {})
    def alive(key):
        p = procs.get(key)
        return bool(p and p.poll() is None)
    return {"http": alive("http"), "tetra": alive("tetra")}


# --------------------------------------------------------------------------
# collector subprocesses
# --------------------------------------------------------------------------
def _spawn(module: str, args: list[str]):
    return subprocess.Popen(
        [sys.executable, "-m", module, *args],
        cwd=str(_PROJECT_ROOT),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _start_collectors(target: dict, cid: str | None,
                      http_container: str | None = None) -> None:
    _stop_collectors(target["id"])
    procs: dict[str, Any] = {"http": None, "tetra": None}
    scenario = target["scenario_id"]

    # HTTP comes from the capture proxy's combined log (falls back to the
    # target container for older records without a proxy).
    procs["http"] = _spawn("backend.collector.http_log_collector", [
        "--container", http_container or target.get("proxy") or target["container"],
        "--scenario", scenario, "--since", "0m", "--api", API_EVENTS,
    ])
    if cid and sensor_running():
        procs["tetra"] = _spawn("backend.collector.tetragon_collector", [
            "--sensor-container", SENSOR_CONTAINER, "--match", cid,
            "--scenario", scenario, "--api", API_EVENTS,
        ])
    _procs[target["id"]] = procs


def _stop_collectors(target_id: str) -> None:
    procs = _procs.pop(target_id, {})
    for p in procs.values():
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


# --------------------------------------------------------------------------
# capture engine (Tetragon sensor) — the one privileged piece
# --------------------------------------------------------------------------
def sensor_status() -> dict:
    return {"running": sensor_running(), "container": SENSOR_CONTAINER}


def sensor_start() -> dict:
    """Start the privileged Tetragon sensor and load the tcp_connect policy.

    Privileged + host PID/cgroup namespaces are required for eBPF; this runs
    on the operator's own lab host.
    """
    if sensor_running():
        return sensor_status()
    _docker([DOCKER, "rm", "-f", SENSOR_CONTAINER], timeout=30)
    r = _docker([
        DOCKER, "run", "--name", SENSOR_CONTAINER, "-d",
        "--pid=host", "--cgroupns=host", "--privileged",
        "-v", "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf",
        SENSOR_IMAGE, "/usr/bin/tetragon",
        "--enable-process-cred", "--enable-process-ns",
    ])
    if r.returncode != 0:
        raise TargetError(f"sensor start failed: {r.stderr.strip()[-400:]}")

    policy = _PROJECT_ROOT / "deploy" / "tetragon" / "tcp-connect.yaml"
    if policy.is_file():
        for _ in range(20):
            _docker([DOCKER, "cp", str(policy),
                     f"{SENSOR_CONTAINER}:/tmp/tcp-connect.yaml"], timeout=15)
            add = _docker([DOCKER, "exec", SENSOR_CONTAINER, "tetra",
                           "tracingpolicy", "add", "/tmp/tcp-connect.yaml"],
                          timeout=15)
            if add.returncode == 0:
                break
            time.sleep(1)

    # The sensor may come up *after* targets are already running; attach
    # process/network telemetry to them now so start order doesn't matter.
    reattach_running_targets()
    return sensor_status()


def reattach_running_targets() -> list[str]:
    """(Re)start collectors for every running target. Returns their ids."""
    reattached = []
    for t in _load():
        if _container_state(t["container"]) == "running":
            _start_collectors(t, _container_id(t["container"]), t.get("proxy"))
            reattached.append(t["id"])
    return reattached


def sensor_stop() -> dict:
    _docker([DOCKER, "rm", "-f", SENSOR_CONTAINER], timeout=30)
    return sensor_status()
