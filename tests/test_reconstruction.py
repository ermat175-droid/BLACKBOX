import unittest

from backend.correlation import correlate
from backend.reconstruction import reconstruct


def _http(eid, path, ts, method="GET", status=200):
    return {
        "event_id": eid,
        "event_type": "http_request",
        "timestamp": ts,
        "hostname": "c1",
        "http": {"method": method, "path": path, "status": status},
        "network": {"source_ip": "172.17.0.1"},
        "process": {},
    }


def _proc(eid, name, pid, ppid, ts, cmd=None, parent_name=None):
    return {
        "event_id": eid,
        "event_type": "process_created",
        "timestamp": ts,
        "hostname": "c1",
        "process": {
            "name": name, "pid": pid, "parent_pid": ppid,
            "command_line": cmd, "parent_name": parent_name,
        },
        "network": {},
        "http": {},
    }


def _reconstruct(events):
    return reconstruct(events, correlate(events))


class TestDetectors(unittest.TestCase):

    def test_git_exposure_detected(self):
        events = [_http("e1", "/.git/HEAD", "2026-01-01T10:00:00")]
        stages = _reconstruct(events)["stages"]
        s = next(s for s in stages if s["key"] == "vcs_exposure")
        self.assertEqual(s["technique_id"], "T1595.003")
        self.assertEqual(s["confidence"], "high")
        self.assertEqual(s["evidence"], ["e1"])

    def test_git_404_not_flagged(self):
        events = [_http("e1", "/.git/HEAD", "2026-01-01T10:00:00", status=404)]
        keys = [s["key"] for s in _reconstruct(events)["stages"]]
        self.assertNotIn("vcs_exposure", keys)

    def test_blind_sqli_is_high_confidence(self):
        events = [
            _http(f"s{i}", f"/api/r.php?order=1 UNION SELECT {i}",
                  f"2026-01-01T10:00:0{i}")
            for i in range(6)
        ]
        s = next(s for s in _reconstruct(events)["stages"]
                 if s["key"] == "sql_injection")
        self.assertEqual(s["confidence"], "high")
        self.assertEqual(len(s["evidence"]), 6)

    def test_single_sqli_is_medium(self):
        events = [_http("s1", "/api/r.php?order=1 OR 1=1", "2026-01-01T10:00:00")]
        s = next(s for s in _reconstruct(events)["stages"]
                 if s["key"] == "sql_injection")
        self.assertEqual(s["confidence"], "medium")

    def test_webshell_rce_proven_by_graph(self):
        # apache -> request to a .phtml carrying a command -> sh runs it
        events = [
            _proc("web", "apache2", 10, 1, "2026-01-01T10:00:00"),
            _http("req", "/uploads/x.phtml?c=id", "2026-01-01T10:00:05"),
            _proc("sh", "sh", 50, 10, "2026-01-01T10:00:06",
                  cmd="/bin/sh -c -- id", parent_name="apache2"),
        ]
        stages = _reconstruct(events)["stages"]
        s = next(s for s in stages if s["key"] == "webshell_rce")
        self.assertEqual(s["technique_id"], "T1059")
        self.assertEqual(s["confidence"], "high")  # served a .phtml shell
        self.assertIn("req", s["evidence"])
        self.assertIn("sh", s["evidence"])

    def test_no_spawned_edge_no_rce_stage(self):
        events = [_http("req", "/index.html", "2026-01-01T10:00:00")]
        keys = [s["key"] for s in _reconstruct(events)["stages"]]
        self.assertNotIn("webshell_rce", keys)

    def test_privesc_path_hijack(self):
        events = [
            _proc("p1", "sh", 50, 10, "2026-01-01T10:00:06",
                  cmd="export PATH=/tmp:$PATH && system-backup"),
        ]
        s = next(s for s in _reconstruct(events)["stages"]
                 if s["key"] == "privilege_escalation")
        self.assertEqual(s["technique_id"], "T1548")

    def test_ssti_strong_is_high(self):
        events = [_http("s1", "/pdf?title={{ self.__globals__.__import__('os') }}",
                        "2026-01-01T10:00:00")]
        s = next(s for s in _reconstruct(events)["stages"] if s["key"] == "ssti")
        self.assertEqual(s["technique_id"], "T1190")
        self.assertEqual(s["confidence"], "high")

    def test_ssti_weak_is_medium(self):
        events = [_http("s1", "/p?x={{7*7}}", "2026-01-01T10:00:00")]
        s = next(s for s in _reconstruct(events)["stages"] if s["key"] == "ssti")
        self.assertEqual(s["confidence"], "medium")

    def test_rce_detected_from_process_only_no_http(self):
        # uvicorn app with NO access log: a web server spawning /bin/sh is RCE
        events = [
            _proc("web", "uvicorn", 10, 1, "2026-01-01T10:00:00"),
            _proc("sh", "sh", 50, 10, "2026-01-01T10:00:05",
                  cmd="/bin/sh -c cat /root/flag.txt", parent_name="uvicorn"),
        ]
        keys = [s["key"] for s in _reconstruct(events)["stages"]]
        self.assertIn("webshell_rce", keys)

    def test_privesc_rootbash_and_dash_p(self):
        for cmd, name in [("/var/tmp/rootbash -p -c id", "rootbash"),
                          ("/bin/bash -p", "bash")]:
            events = [_proc("p", name, 50, 10, "2026-01-01T10:00:06", cmd=cmd)]
            s = next((s for s in _reconstruct(events)["stages"]
                      if s["key"] == "privilege_escalation"), None)
            self.assertIsNotNone(s, f"privesc not detected for {cmd}")

    def test_sensitive_file_read(self):
        events = [_proc("c", "cat", 60, 50, "2026-01-01T10:00:07",
                        cmd="/usr/bin/cat /root/flag.txt")]
        s = next(s for s in _reconstruct(events)["stages"]
                 if s["key"] == "sensitive_access")
        self.assertEqual(s["technique_id"], "T1005")
        self.assertEqual(s["confidence"], "high")


class TestNarrative(unittest.TestCase):

    def test_empty_incident_has_no_stages(self):
        r = reconstruct([], {"nodes": [], "edges": [], "roots": []})
        self.assertEqual(r["stage_count"], 0)
        self.assertIsNone(r["overall_confidence"])

    def test_stages_ordered_by_evidence_time(self):
        events = [
            _proc("p1", "sh", 50, 10, "2026-01-01T10:05:00",
                  cmd="export PATH=/tmp:$PATH"),
            _http("g1", "/.git/HEAD", "2026-01-01T10:00:00"),
        ]
        stages = _reconstruct(events)["stages"]
        self.assertEqual(stages[0]["key"], "vcs_exposure")
        self.assertEqual([s["order"] for s in stages], list(range(1, len(stages) + 1)))

    def test_overall_confidence_is_strongest(self):
        events = [
            _http("g1", "/.git/HEAD", "2026-01-01T10:00:00"),          # high
            _proc("p1", "tar", 50, 10, "2026-01-01T10:05:00"),         # medium
        ]
        self.assertEqual(_reconstruct(events)["overall_confidence"], "high")


if __name__ == "__main__":
    unittest.main()
