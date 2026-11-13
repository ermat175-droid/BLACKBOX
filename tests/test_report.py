import hashlib
import json
import unittest

from backend.report import build_report, to_html, _canonical


def _stage(order, key, tech, tactic, title, conf):
    loc = lambda s: {"en": s, "ru": s, "kz": s}
    return {"order": order, "key": key, "technique_id": tech,
            "technique": "T", "tactic": loc(tactic), "title": loc(title),
            "technique_reason": loc("because"), "summary": loc("did a thing"),
            "confidence": conf, "evidence": ["e1", "e2"]}


RECON = {"overall_confidence": "high", "stages": [
    _stage(1, "ssti", "T1190", "Initial Access", "SSTI", "high"),
    _stage(2, "privilege_escalation", "T1548", "Privilege Escalation", "privesc", "medium"),
]}
IMPACT = {"severity": "critical", "code_execution": True, "root_achieved": True,
          "secrets_read": ["/root/flag.txt"], "secret_count": 1, "egress_attempts": []}
INFRA = {"hostname": "app.target", "assets": [
    {"type": "service", "label": "uvicorn", "status": "compromised", "techniques": ["T1059"]},
    {"type": "secret", "label": "/root/flag.txt", "status": "compromised", "techniques": ["T1005"]}]}
RULES = {"rules": [
    {"stage": "ssti", "technique": "T1190", "format": "sigma", "title": "SSTI",
     "enforces": False, "yaml": "title: SSTI\n"},
    {"stage": "privilege_escalation", "technique": "T1548", "format": "tetragon",
     "title": "Block SUID", "enforces": True, "yaml": "kind: TracingPolicy\n"}]}
INTEG = {"ok": True, "count": 141, "head": "a" * 64, "genesis": "0" * 64}


class TestReport(unittest.TestCase):

    def test_build_and_seal(self):
        rep = build_report(scenario_id="TGT-test", recon=RECON, impact=IMPACT,
                           infrastructure=INFRA, rules=RULES, integrity=INTEG)
        self.assertEqual(rep["report"]["scenario_id"], "TGT-test")
        self.assertEqual(rep["report"]["integrity"]["chain_head"], "a" * 64)
        self.assertEqual(len(rep["report"]["stages"]), 2)
        self.assertEqual(len(rep["report"]["defenses"]), 2)
        # seal digest matches the body independently
        digest = hashlib.sha256(_canonical(rep["report"]).encode()).hexdigest()
        self.assertEqual(rep["seal"]["content_sha256"], digest)

    def test_tamper_is_detectable(self):
        rep = build_report(scenario_id="TGT-test", recon=RECON, impact=IMPACT,
                           infrastructure=INFRA, rules=RULES, integrity=INTEG)
        rep["report"]["stages"][0]["title"] = "ALTERED"
        digest = hashlib.sha256(_canonical(rep["report"]).encode()).hexdigest()
        self.assertNotEqual(rep["seal"]["content_sha256"], digest)

    def test_localization_picks_lang(self):
        rec = {"overall_confidence": "high", "stages": [{
            "order": 1, "key": "ssti", "technique_id": "T1190", "technique": "T",
            "tactic": {"en": "Initial Access", "ru": "Первичный доступ", "kz": "x"},
            "title": {"en": "SSTI", "ru": "SSTI-ру", "kz": "x"},
            "technique_reason": {"en": "r", "ru": "причина", "kz": "x"},
            "summary": {"en": "s", "ru": "итог", "kz": "x"},
            "confidence": "high", "evidence": []}]}
        rep = build_report(scenario_id="c", recon=rec, impact=IMPACT,
                           infrastructure=INFRA, rules=RULES, integrity=INTEG, lang="ru")
        self.assertEqual(rep["report"]["stages"][0]["tactic"], "Первичный доступ")

    def test_html_contains_key_sections(self):
        rep = build_report(scenario_id="TGT-test", recon=RECON, impact=IMPACT,
                           infrastructure=INFRA, rules=RULES, integrity=INTEG)
        html = to_html(rep)
        self.assertIn("Investigation Report", html)
        self.assertIn("a" * 64, html)                    # chain head
        self.assertIn(rep["seal"]["content_sha256"], html)
        self.assertIn("ENFORCE", html)                   # the blocking rule flagged
        self.assertIn("/root/flag.txt", html)

    def test_validation_section_optional(self):
        rep = build_report(scenario_id="c", recon=RECON, impact=IMPACT,
                           infrastructure=INFRA, rules=RULES, integrity=INTEG,
                           validation={"verdict": "verified", "recall": 1.0,
                                       "precision": 0.8, "actions_total": 4,
                                       "actions_recovered": 4, "markers_confirmed": 4})
        self.assertIn("Blind validation", to_html(rep))


if __name__ == "__main__":
    unittest.main()
