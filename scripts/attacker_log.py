#!/usr/bin/env python3
"""Attacker-side action recorder for blind validation.

The attacker (a solver, an AI agent, a human) records what it REALLY does as
it does it, then submits that log to BLACKBOX. BLACKBOX never sees this log
while it reconstructs — it builds its own record blind from telemetry. The
two independent records are then compared (``POST /incidents/{id}/validate``).
This is corroboration by two vantage points, not grading against a key.

    from scripts.attacker_log import AttackLog
    log = AttackLog("TGT-test", attacker="solve.py machine3")
    log.record("T1190", "ssti", marker="/export/generate-pdf", note="Jinja2 SSTI")
    log.record("T1548", "privesc", marker="rootbash")
    print(log.submit("http://127.0.0.1:8000"))   # -> validation result
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.request import Request, urlopen


class AttackLog:
    def __init__(self, scenario_id: str, attacker: str | None = None):
        self.scenario_id = scenario_id
        self.attacker = attacker
        self.actions: list[dict] = []

    def record(self, technique: str, kind: str | None = None,
               marker: str | None = None, note: str | None = None) -> "AttackLog":
        """Log one real action: its MITRE technique and a telemetry marker
        (an HTTP path, a command, a filename) that should show up downstream."""
        self.actions.append({
            "technique": technique, "kind": kind,
            "marker": marker, "note": note, "ts": time.time(),
        })
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "attacker": self.attacker,
            "actions": self.actions,
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    def submit(self, api_base: str) -> dict:
        url = f"{api_base.rstrip('/')}/incidents/{self.scenario_id}/validate"
        req = Request(
            url, data=json.dumps(self.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
