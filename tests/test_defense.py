import unittest

import yaml

from backend.defense import generate_rules


def _stage(key, tech, tactic_en):
    return {"key": key, "technique_id": tech,
            "tactic": {"en": tactic_en, "ru": "", "kz": ""}}


RECON = {"stages": [
    _stage("ssti", "T1190", "Initial Access"),
    _stage("webshell_rce", "T1059", "Execution"),
    _stage("privilege_escalation", "T1548", "Privilege Escalation"),
    _stage("sensitive_access", "T1005", "Collection"),
]}


class TestGenerateRules(unittest.TestCase):

    def setUp(self):
        self.out = generate_rules(RECON)
        self.by_stage = {}
        for r in self.out["rules"]:
            self.by_stage.setdefault(r["stage"], []).append(r)

    def test_counts(self):
        self.assertGreater(self.out["rule_count"], 0)
        self.assertGreater(self.out["sigma_count"], 0)
        self.assertGreater(self.out["tetragon_count"], 0)

    def test_ssti_gets_sigma(self):
        rules = self.by_stage["ssti"]
        self.assertTrue(any(r["format"] == "sigma" for r in rules))

    def test_rce_gets_enforceable_tetragon(self):
        rce = self.by_stage["webshell_rce"]
        tetra = [r for r in rce if r["format"] == "tetragon"]
        self.assertTrue(tetra)
        self.assertTrue(tetra[0]["enforces"])
        self.assertIn("webshell_rce", self.out["enforceable"])

    def test_privesc_enforceable(self):
        self.assertIn("privilege_escalation", self.out["enforceable"])

    def test_sensitive_access_is_watch_only(self):
        tetra = [r for r in self.by_stage["sensitive_access"] if r["format"] == "tetragon"]
        self.assertTrue(tetra)
        self.assertFalse(tetra[0]["enforces"])  # alert, don't block, on reads

    def test_all_yaml_is_valid(self):
        for r in self.out["rules"]:
            parsed = yaml.safe_load(r["yaml"])
            self.assertIsInstance(parsed, dict)
            if r["format"] == "tetragon":
                self.assertEqual(parsed["kind"], "TracingPolicy")
            else:
                self.assertIn("detection", parsed)
                self.assertIn(f"attack.{r['technique'].lower()}", parsed["tags"])

    def test_enforce_policy_has_sigkill(self):
        rce_tetra = next(r for r in self.by_stage["webshell_rce"] if r["format"] == "tetragon")
        self.assertIn("Sigkill", rce_tetra["yaml"])

    def test_empty_recon(self):
        self.assertEqual(generate_rules({"stages": []})["rule_count"], 0)


if __name__ == "__main__":
    unittest.main()
