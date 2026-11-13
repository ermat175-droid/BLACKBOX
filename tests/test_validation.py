import unittest

from backend.validation import validate


def _stage(key, tech, evidence):
    return {"key": key, "technique_id": tech, "evidence": evidence}


def _http_ev(eid, path):
    return {"event_id": eid, "http": {"path": path}, "process": {}}


def _proc_ev(eid, name, cmd):
    return {"event_id": eid, "http": {}, "process": {"name": name, "command_line": cmd}}


EVENTS = [
    _http_ev("h1", "/export/generate-pdf?report_title={{x}}"),
    _proc_ev("p1", "rootbash", "/var/tmp/rootbash -p"),
    _proc_ev("p2", "cat", "/usr/bin/cat /root/flag.txt"),
]
RECON = {"stages": [
    _stage("ssti", "T1190", ["h1"]),
    _stage("webshell_rce", "T1059", ["p2"]),
    _stage("privilege_escalation", "T1548", ["p1"]),
    _stage("sensitive_access", "T1005", ["p2"]),
]}
ACTIONS = [
    {"technique": "T1190", "marker": "/export/generate-pdf"},
    {"technique": "T1059", "marker": "/root/flag.txt"},
    {"technique": "T1548", "marker": "rootbash"},
    {"technique": "T1005", "marker": "/root/flag.txt"},
]


class TestValidate(unittest.TestCase):

    def test_full_match_is_verified(self):
        r = validate(ACTIONS, EVENTS, RECON)
        self.assertEqual(r["verdict"], "verified")
        self.assertEqual(r["recall"], 1.0)
        self.assertEqual(r["actions_recovered"], 4)
        self.assertEqual(r["extra_techniques"], [])

    def test_markers_confirmed_in_evidence(self):
        r = validate(ACTIONS, EVENTS, RECON)
        # every action's marker appears in the cited evidence
        self.assertEqual(r["markers_confirmed"], 4)
        self.assertTrue(all(x["marker_confirmed"] for x in r["results"]))

    def test_missed_action_lowers_recall(self):
        actions = ACTIONS + [{"technique": "T1021", "marker": "ssh"}]  # not reconstructed
        r = validate(actions, EVENTS, RECON)
        self.assertLess(r["recall"], 1.0)
        self.assertEqual(r["actions_recovered"], 4)
        missed = [x for x in r["results"] if not x["recovered"]]
        self.assertEqual(missed[0]["technique"], "T1021")

    def test_extra_technique_blocks_verified(self):
        # reconstruction asserts a technique the attacker never logged
        recon = {"stages": RECON["stages"] + [_stage("outbound", "T1071", [])]}
        r = validate(ACTIONS, EVENTS, recon)
        self.assertIn("T1071", r["extra_techniques"])
        self.assertNotEqual(r["verdict"], "verified")

    def test_marker_mismatch_matched_but_not_confirmed(self):
        actions = [{"technique": "T1190", "marker": "nonexistent-string"}]
        r = validate(actions, EVENTS, RECON)
        self.assertTrue(r["results"][0]["recovered"])
        self.assertFalse(r["results"][0]["marker_confirmed"])

    def test_empty_actions(self):
        r = validate([], EVENTS, RECON)
        self.assertEqual(r["verdict"], "unverified")
        self.assertEqual(r["recall"], 0.0)


if __name__ == "__main__":
    unittest.main()
