"""Live enforcement — block a proven attack on replay.

The climax of the loop: once BLACKBOX has reconstructed an attack, it can
load a kernel policy into the Tetragon sensor that **kills** the attack's
own binaries the next time they execute (verified: a Sigkill at
``security_bprm_creds_for_exec`` stops the process, exit 137).

Safety is the whole game here, because enforcement is host-wide. We block
**only attack-artifact binaries** — a planted ``rootbash`` or anything run
from a world-writable directory (/tmp, /var/tmp, /dev/shm). We **never**
block a system binary (``/bin/sh`` and friends): killing those host-wide
would take down every shell on the machine, including this session. A
hard allowlist enforces that no system path is ever armed.

The binaries to block are derived from the incident's own process
evidence, so the policy targets exactly what the attacker used.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Iterable

import yaml

from backend.targets import SENSOR_CONTAINER, TargetError, _docker, DOCKER

# World-writable dirs: a binary here is never legitimate system software.
_SAFE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Attack-artifact basenames we also allow blocking by exact path.
_SAFE_NAMES = {"rootbash"}
# System locations we must NEVER arm (killing these host-wide is catastrophic).
_SYSTEM_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
                "/usr/local/bin/", "/usr/local/sbin/", "/lib/", "/usr/lib/")


def _binary(cmd: str | None, name: str | None) -> str | None:
    """Best-effort absolute binary path from a command line / process name."""
    if cmd:
        tok = cmd.strip().split()[0] if cmd.strip() else ""
        # strip a leading "sh -c --" style wrapper token if it's a shell
        if tok.startswith("/") and not tok.endswith(("sh",)):
            return tok
        if tok.startswith("/"):
            return tok
    return None


def safe_to_block(path: str) -> bool:
    """True only for attack-artifact paths — never a system binary."""
    if not path or not path.startswith("/"):
        return False
    if any(path.startswith(d) for d in _SYSTEM_DIRS):
        return False
    base = path.rsplit("/", 1)[-1]
    if base in _SAFE_NAMES:
        return True
    if path.startswith(_SAFE_DIRS):
        return True
    return False


def enforce_targets(recon: dict, events: Iterable[dict]) -> list[str]:
    """Attack-artifact binary paths it is safe to block, from the evidence."""
    events = list(events)
    ev_by_id = {e["event_id"]: e for e in events}
    wanted = {"privilege_escalation", "webshell_rce"}
    ids: set[str] = set()
    for s in recon.get("stages", []):
        if s["key"] in wanted:
            ids.update(s["evidence"])

    paths: set[str] = set()
    for eid in ids:
        e = ev_by_id.get(eid)
        if not e or e.get("event_type") != "process_created":
            continue
        p = e.get("process") or {}
        cand = _binary(p.get("command_line"), p.get("name"))
        if cand and safe_to_block(cand):
            paths.add(cand)
    return sorted(paths)


def build_policy(name: str, binaries: list[str]) -> dict[str, Any]:
    """A Tetragon enforcement policy: Sigkill exec of the given binaries."""
    return {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {"kprobes": [{
            "call": "security_bprm_creds_for_exec",
            "syscall": False,
            "args": [{"index": 0, "type": "linux_binprm"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Equal", "values": binaries}],
                "matchActions": [{"action": "Sigkill"}],
            }],
        }]},
    }


def _policy_name(scenario_id: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in scenario_id.lower())
    return f"bb-enforce-{slug}"[:60]


def sensor_running() -> bool:
    r = _docker([DOCKER, "inspect", "-f", "{{.State.Status}}", SENSOR_CONTAINER], timeout=15)
    return r.returncode == 0 and r.stdout.strip() == "running"


def apply_enforcement(scenario_id: str, binaries: list[str]) -> dict:
    """Load a kill policy for the given (already safety-checked) binaries."""
    unsafe = [b for b in binaries if not safe_to_block(b)]
    if unsafe:
        raise TargetError(f"refusing to arm non-artifact binaries: {unsafe}")
    if not binaries:
        raise TargetError("no attack-artifact binaries to block in this incident")
    if not sensor_running():
        raise TargetError("capture engine (Tetragon sensor) is not running")

    name = _policy_name(scenario_id)
    policy = build_policy(name, binaries)

    # stage the policy as a host temp file, copy it in, then load it.
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    try:
        yaml.safe_dump(policy, tmp, sort_keys=False)
        tmp.close()
        _docker([DOCKER, "exec", SENSOR_CONTAINER, "tetra",
                 "tracingpolicy", "delete", name], timeout=15)  # idempotent
        cp = _docker([DOCKER, "cp", tmp.name,
                      f"{SENSOR_CONTAINER}:/tmp/{name}.yaml"], timeout=15)
        if cp.returncode != 0:
            raise TargetError(f"could not stage policy: {cp.stderr.strip()[-200:]}")
        add = _docker([DOCKER, "exec", SENSOR_CONTAINER, "tetra",
                       "tracingpolicy", "add", f"/tmp/{name}.yaml"], timeout=15)
        if add.returncode != 0:
            raise TargetError(f"could not arm policy: {add.stderr.strip()[-200:]}")
    finally:
        os.unlink(tmp.name)
    return {"armed": True, "policy": name, "blocked_binaries": binaries}


def remove_enforcement(scenario_id: str) -> dict:
    name = _policy_name(scenario_id)
    _docker([DOCKER, "exec", SENSOR_CONTAINER, "tetra",
             "tracingpolicy", "delete", name], timeout=15)
    return {"armed": False, "policy": name}


def enforcement_status(scenario_id: str) -> dict:
    name = _policy_name(scenario_id)
    if not sensor_running():
        return {"armed": False, "policy": name, "sensor": False}
    r = _docker([DOCKER, "exec", SENSOR_CONTAINER, "tetra",
                 "tracingpolicy", "list"], timeout=15)
    armed = r.returncode == 0 and name in r.stdout
    return {"armed": armed, "policy": name, "sensor": True}
