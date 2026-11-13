"""Investigation report — a self-verifying evidence package.

The capstone artifact for the "Law & Order" theme: one document that carries
the whole investigation — the reconstructed chain, the blast radius, the
asset map, the generated defences, and the validation — anchored to proof
that it was not altered.

Two anchors, both dependency-free and independently verifiable:

* ``chain_head`` — the head of the tamper-evident evidence hash chain
  (``backend.integrity``). It fixes every underlying event; recompute the
  chain and it must still end here.
* ``content_sha256`` — a SHA-256 over the canonical report body. Anyone can
  recompute it from the report alone and detect any change (see
  ``scripts/verify_report.py``). No secret is needed to verify.

``build_report`` assembles the structured report; ``to_html`` renders a
self-contained, printable page (print to PDF for a filed document).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from html import escape
from typing import Any


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def build_report(
    *, scenario_id: str, recon: dict, impact: dict, infrastructure: dict,
    rules: dict, integrity: dict, validation: dict | None = None,
    lang: str = "en",
) -> dict[str, Any]:
    """Assemble the investigation report and seal it with a content digest."""
    def L(field: Any) -> Any:
        if isinstance(field, dict) and lang in field:
            return field[lang]
        return field

    stages = [{
        "order": s["order"], "title": L(s["title"]), "tactic": L(s["tactic"]),
        "technique_id": s["technique_id"], "technique": s["technique"],
        "confidence": s["confidence"], "reason": L(s["technique_reason"]),
        "summary": L(s["summary"]), "evidence_count": len(s["evidence"]),
    } for s in recon.get("stages", [])]

    body = {
        "title": "BLACKBOX Investigation Report",
        "scenario_id": scenario_id,
        "overall_confidence": recon.get("overall_confidence"),
        "stages": stages,
        "impact": impact,
        "infrastructure": {
            "hostname": infrastructure.get("hostname"),
            "assets": [
                {"type": a["type"], "label": a["label"], "status": a["status"],
                 "techniques": a.get("techniques", [])}
                for a in infrastructure.get("assets", [])
            ],
        },
        "defenses": [
            {"stage": r["stage"], "technique": r["technique"],
             "format": r["format"], "title": r["title"],
             "enforces": r.get("enforces", False), "yaml": r["yaml"]}
            for r in rules.get("rules", [])
        ],
        "validation": validation,
        "integrity": {
            "verified": integrity.get("ok"),
            "event_count": integrity.get("count"),
            "chain_head": integrity.get("head"),
            "genesis": integrity.get("genesis"),
        },
    }

    seal = {
        "content_sha256": hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest(),
        "chain_head": integrity.get("head"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verifier": "scripts/verify_report.py",
    }
    return {"report": body, "seal": seal}


# --------------------------------------------------------------------------
# HTML rendering (self-contained, printable)
# --------------------------------------------------------------------------
_CSS = """
:root{--ink:#16150f;--mut:#6b6a63;--line:#d9d8d2;--acc:#b24a2b;
--hi:#1f8a57;--md:#b57d12;--lo:#86857c;--crit:#c0392b;}
*{box-sizing:border-box}
body{font:14px/1.55 Georgia,'Times New Roman',serif;color:var(--ink);
max-width:820px;margin:28px auto;padding:0 22px;background:#fff}
h1{font-size:23px;margin:0 0 2px;letter-spacing:.02em}
.sub{color:var(--mut);font-size:13px;margin-bottom:18px}
h2{font-size:15px;border-bottom:2px solid var(--ink);padding-bottom:3px;margin:26px 0 10px;
text-transform:uppercase;letter-spacing:.06em}
.seal{border:1px solid var(--line);border-left:4px solid var(--hi);border-radius:6px;
padding:10px 14px;background:#f7f9f7;font:12px/1.5 ui-monospace,Menlo,monospace;
word-break:break-all;margin:10px 0 4px}
.seal b{font-family:Georgia,serif}
.pill{display:inline-block;color:#fff;border-radius:999px;padding:2px 10px;font-size:11px;
font-weight:bold;text-transform:uppercase;letter-spacing:.04em}
.c-high,.c-critical{background:var(--crit)}.c-medium{background:var(--md)}.c-low{background:var(--lo)}
.conf-high{background:var(--hi)}.conf-medium{background:var(--md)}.conf-low{background:var(--lo)}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th,td{text-align:left;border-bottom:1px solid var(--line);padding:6px 8px;vertical-align:top}
th{color:var(--mut);font-weight:bold;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.stage-t{font-weight:bold}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.reason{color:var(--mut);font-style:italic}
pre{background:#f6f6f4;border:1px solid var(--line);border-radius:6px;padding:9px 11px;
font:11.5px/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.rule-h{font-weight:bold;margin-top:12px}.enf{color:var(--crit);font-weight:bold}
ul{margin:4px 0;padding-left:20px}
.foot{color:var(--mut);font-size:11px;border-top:1px solid var(--line);margin-top:26px;padding-top:8px}
@media print{body{margin:0}h2{page-break-after:avoid}pre,table{page-break-inside:avoid}}
"""


def to_html(report: dict) -> str:
    b, s = report["report"], report["seal"]
    imp = b.get("impact") or {}
    integ = b.get("integrity") or {}
    val = b.get("validation")

    def esc(x: Any) -> str:
        return escape(str(x if x is not None else ""))

    parts: list[str] = []
    parts.append(f"<h1>{esc(b['title'])}</h1>")
    parts.append(f"<div class='sub'>Case <b>{esc(b['scenario_id'])}</b> · "
                 f"generated {esc(s['generated_at'])}</div>")

    # verdict / impact
    sev = esc(imp.get("severity", "low"))
    parts.append("<h2>Summary</h2>")
    parts.append(f"<p>Reconstruction confidence: "
                 f"<span class='pill conf-{esc(b.get('overall_confidence') or 'low')}'>"
                 f"{esc(b.get('overall_confidence') or 'n/a')}</span> · "
                 f"Impact: <span class='pill c-{sev}'>{sev}</span></p>")
    facts = []
    if imp.get("code_execution"):
        facts.append("remote code execution")
    if imp.get("root_achieved"):
        facts.append("privilege escalation to <b>root</b>")
    if imp.get("secrets_read"):
        facts.append(f"{imp.get('secret_count', 0)} sensitive file(s) read "
                     f"({esc(', '.join(imp['secrets_read']))})")
    if imp.get("egress_attempts"):
        facts.append(f"{len(imp['egress_attempts'])} outbound attempt(s)")
    if facts:
        parts.append("<p>The attacker achieved: " + "; ".join(facts) + ".</p>")

    # validation
    if val:
        parts.append("<h2>Blind validation</h2>")
        parts.append(f"<p>Verdict <b>{esc(val.get('verdict'))}</b> · "
                     f"recall {esc(val.get('recall'))} · precision {esc(val.get('precision'))} · "
                     f"{esc(val.get('actions_recovered'))}/{esc(val.get('actions_total'))} "
                     f"attacker actions recovered, {esc(val.get('markers_confirmed'))} "
                     f"markers confirmed in evidence.</p>")

    # attack chain
    parts.append("<h2>Reconstructed attack chain</h2>")
    parts.append("<table><tr><th>#</th><th>Tactic / Technique</th><th>Finding</th>"
                 "<th>Conf.</th></tr>")
    for st in b["stages"]:
        parts.append(
            f"<tr><td>{st['order']}</td>"
            f"<td><span class='mono'>{esc(st['technique_id'])}</span> {esc(st['technique'])}"
            f"<br><span class='reason'>{esc(st['tactic'])}</span></td>"
            f"<td><span class='stage-t'>{esc(st['title'])}</span><br>{esc(st['summary'])}"
            f"<br><span class='reason'>Why: {esc(st['reason'])}</span></td>"
            f"<td><span class='pill conf-{esc(st['confidence'])}'>{esc(st['confidence'])}</span></td></tr>")
    parts.append("</table>")

    # infrastructure
    infra = b.get("infrastructure") or {}
    if infra.get("assets"):
        parts.append("<h2>Affected infrastructure</h2>")
        parts.append(f"<p>Host <span class='mono'>{esc(infra.get('hostname'))}</span></p><ul>")
        for a in infra["assets"]:
            tech = f" [{esc(', '.join(a['techniques']))}]" if a.get("techniques") else ""
            parts.append(f"<li><b>{esc(a['label'])}</b> ({esc(a['type'])}) — "
                         f"<span class='pill c-{'critical' if a['status']=='compromised' else ('medium' if a['status']=='touched' else 'low')}'>"
                         f"{esc(a['status'])}</span>{tech}</li>")
        parts.append("</ul>")

    # defenses
    if b.get("defenses"):
        parts.append("<h2>Recommended defences (derived from evidence)</h2>")
        for r in b["defenses"]:
            enf = " <span class='enf'>[ENFORCE — blocks the attack]</span>" if r.get("enforces") else ""
            parts.append(f"<div class='rule-h'>{esc(r['title'])} · "
                         f"<span class='mono'>{esc(r['technique'])}</span> · {esc(r['format'])}{enf}</div>")
            parts.append(f"<pre>{esc(r['yaml'])}</pre>")

    # integrity seal
    parts.append("<h2>Evidence integrity</h2>")
    parts.append(
        f"<div class='seal'><b>Chain of custody:</b> "
        f"{'VERIFIED' if integ.get('verified') else 'NOT VERIFIED'} over "
        f"{esc(integ.get('event_count'))} events<br>"
        f"<b>Chain head:</b> {esc(integ.get('chain_head'))}<br>"
        f"<b>Report content SHA-256:</b> {esc(s['content_sha256'])}</div>")
    parts.append("<p class='reason'>Recompute the chain over the stored events "
                 "and the report digest to independently verify this document "
                 f"was not altered (see <span class='mono'>{esc(s.get('verifier'))}</span>).</p>")

    parts.append("<div class='foot'>Generated by BLACKBOX — Cyber Investigation "
                 "&amp; Attack Reconstruction Platform.</div>")

    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{esc(b['title'])} — {esc(b['scenario_id'])}</title>"
            f"<style>{_CSS}</style></head><body>{''.join(parts)}</body></html>")
