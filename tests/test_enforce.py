import unittest

import yaml

from backend.enforce import (
    safe_to_block, enforce_targets, build_policy, _policy_name,
    _policy_block_count,
)


class TestBlockCount(unittest.TestCase):

    def test_counts_sigkills_from_stats(self):
        pol = {"stats": {"action_counters": {"post": "2", "signal": "2"}}}
        self.assertEqual(_policy_block_count(pol), 2)

    def test_zero_when_no_stats(self):
        self.assertEqual(_policy_block_count({}), 0)
        self.assertEqual(_policy_block_count({"stats": {}}), 0)
        self.assertEqual(
            _policy_block_count({"stats": {"action_counters": {"post": "5"}}}), 0)


class TestSafety(unittest.TestCase):
    """The guard that must never fail: no system binary is ever armed."""

    def test_system_shells_never_blockable(self):
        for p in ["/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash",
                  "/bin/dash", "/usr/bin/python3", "/bin/cat", "/usr/bin/cat",
                  "/sbin/init", "/usr/local/bin/anything", "/usr/bin/id"]:
            self.assertFalse(safe_to_block(p), f"{p} must NOT be blockable")

    def test_artifact_paths_blockable(self):
        for p in ["/var/tmp/rootbash", "/tmp/rootbash", "/tmp/evil",
                  "/dev/shm/x", "/var/tmp/backdoor"]:
            self.assertTrue(safe_to_block(p), f"{p} should be blockable")

    def test_bare_or_relative_rejected(self):
        for p in ["rootbash", "sh", "", "../x", None]:
            self.assertFalse(safe_to_block(p))

    def test_rootbash_by_name_in_nonstandard_dir(self):
        self.assertTrue(safe_to_block("/opt/rootbash"))      # suspicious name
        self.assertFalse(safe_to_block("/usr/bin/rootbash"))  # but not a system dir


def _proc(eid, name, cmd):
    return {"event_id": eid, "event_type": "process_created",
            "process": {"name": name, "command_line": cmd}}


class TestTargets(unittest.TestCase):

    def test_extracts_only_safe_artifacts(self):
        events = [
            _proc("p1", "rootbash", "/var/tmp/rootbash -p"),
            _proc("p2", "sh", "/bin/sh -c cat /root/flag.txt"),   # system shell: excluded
            _proc("p3", "cat", "/usr/bin/cat /root/flag.txt"),    # system: excluded
        ]
        recon = {"stages": [
            {"key": "privilege_escalation", "evidence": ["p1"]},
            {"key": "webshell_rce", "evidence": ["p2", "p3"]}]}
        targets = enforce_targets(recon, events)
        self.assertEqual(targets, ["/var/tmp/rootbash"])

    def test_no_targets_when_only_system_binaries(self):
        events = [_proc("p2", "sh", "/bin/sh -c id")]
        recon = {"stages": [{"key": "webshell_rce", "evidence": ["p2"]}]}
        self.assertEqual(enforce_targets(recon, events), [])


class TestPolicy(unittest.TestCase):

    def test_build_policy_is_sigkill_on_binaries(self):
        pol = build_policy("bb-enforce-x", ["/var/tmp/rootbash"])
        self.assertEqual(pol["kind"], "TracingPolicy")
        kp = pol["spec"]["kprobes"][0]
        self.assertEqual(kp["call"], "security_bprm_creds_for_exec")
        sel = kp["selectors"][0]
        self.assertIn("/var/tmp/rootbash", sel["matchArgs"][0]["values"])
        self.assertEqual(sel["matchActions"][0]["action"], "Sigkill")
        # serializes cleanly
        self.assertIn("Sigkill", yaml.safe_dump(pol))

    def test_policy_name_is_sanitized(self):
        self.assertEqual(_policy_name("TGT-test"), "bb-enforce-tgt-test")


if __name__ == "__main__":
    unittest.main()
