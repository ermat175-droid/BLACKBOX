"""Blind-investigation validation.

The point BLACKBOX has to make is that its reconstruction is *true*, not a
plausible story. We prove it by comparing two **independent** records of the
same incident:

* the **attacker's** own action log — what it really did (its real
  payloads/commands), recorded on the attacker side (``solve.py``, an AI
  agent, …) and submitted after the fact;
* BLACKBOX's **reconstruction**, built blind from kernel/log telemetry
  without ever seeing that log.

If two independently-produced records agree, the reconstruction is
corroborated — this is not grading against a hand-written answer key, it is
two different vantage points of the same event lining up.

``validate`` returns, per attacker action, whether BLACKBOX recovered it
(and whether the actual marker was found in the cited evidence), plus
technique-level precision/recall and an overall score. Pure function over
(actions, events, reconstruction); fully testable.
"""

from __future__ import annotations

from typing import Any, Iterable

from urllib.parse import unquote


def _event_text(event: dict) -> str:
    """Searchable text of an event — the artifacts an action marker may hit."""
    http = event.get("http") or {}
    proc = event.get("process") or {}
    parts = [
        unquote(http.get("path") or ""),
        proc.get("command_line") or "",
        proc.get("name") or "",
    ]
    return " ".join(parts).lower()


def validate(
    actions: Iterable[dict], events: Iterable[dict], recon: dict
) -> dict[str, Any]:
    """Compare an attacker action log against a BLACKBOX reconstruction."""
    actions = list(actions)
    events = list(events)
    stages = recon.get("stages", [])

    # technique id -> the stages that assert it
    stages_by_tech: dict[str, list[dict]] = {}
    for s in stages:
        stages_by_tech.setdefault(s["technique_id"], []).append(s)

    event_by_id = {e["event_id"]: e for e in events}

    results = []
    matched = 0
    confirmed = 0
    for act in actions:
        tech = act.get("technique")
        marker = (act.get("marker") or "").lower()
        hit_stages = stages_by_tech.get(tech, [])
        is_matched = bool(hit_stages)

        # Marker confirmation: the real artifact appears in the evidence the
        # matched stage cited — the strongest form of agreement.
        is_confirmed = False
        if is_matched and marker:
            for s in hit_stages:
                for eid in s["evidence"]:
                    ev = event_by_id.get(eid)
                    if ev and marker in _event_text(ev):
                        is_confirmed = True
                        break
                if is_confirmed:
                    break

        if is_matched:
            matched += 1
        if is_confirmed:
            confirmed += 1

        results.append({
            "technique": tech,
            "kind": act.get("kind"),
            "note": act.get("note"),
            "marker": act.get("marker"),
            "recovered": is_matched,
            "marker_confirmed": is_confirmed,
            "stage_keys": [s["key"] for s in hit_stages],
        })

    total_actions = len(actions)
    attacker_techs = {a.get("technique") for a in actions if a.get("technique")}
    recon_techs = set(stages_by_tech)

    # extra = techniques BLACKBOX asserted that the attacker did not log.
    extra_techs = sorted(recon_techs - attacker_techs)

    recall = matched / total_actions if total_actions else 0.0
    precision = (
        len(attacker_techs & recon_techs) / len(recon_techs)
        if recon_techs else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0.0
    )

    if recall >= 0.99 and not extra_techs:
        verdict = "verified"
    elif recall >= 0.6:
        verdict = "mostly_verified"
    elif recall > 0:
        verdict = "partial"
    else:
        verdict = "unverified"

    return {
        "verdict": verdict,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "f1": round(f1, 3),
        "actions_total": total_actions,
        "actions_recovered": matched,
        "markers_confirmed": confirmed,
        "extra_techniques": extra_techs,
        "results": results,
    }
