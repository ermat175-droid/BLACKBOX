import unittest

from backend.collector.tetragon_collector import map_event
from backend.normalization import normalize_event


def _exec_event(binary, pid, parent_binary, parent_pid, docker, args=None):
    return {
        "time": "2026-11-10T12:00:00.000Z",
        "process_exec": {
            "process": {
                "exec_id": f"exec-{pid}",
                "pid": pid,
                "uid": 33,
                "binary": binary,
                "arguments": args,
                "start_time": "2026-11-10T12:00:00.123Z",
                "docker": docker,
            },
            "parent": {
                "pid": parent_pid,
                "binary": parent_binary,
            },
        },
    }


class TestTetragonCollector(unittest.TestCase):

    def test_maps_exec_to_process_event(self):
        raw = map_event(
            _exec_event(
                "/usr/local/bin/system-backup", 324419,
                "/usr/bin/sh", 324412,
                "9c6810f2abd8a2e2d0d5a8b82c11a7b",
            ),
            scenario_id="BB-M1",
        )

        self.assertEqual(raw["event_type"], "process_created")
        self.assertEqual(raw["source"], "tetragon")
        self.assertEqual(raw["data"]["process_name"], "system-backup")
        self.assertEqual(raw["data"]["pid"], 324419)
        self.assertEqual(raw["data"]["parent_pid"], 324412)
        self.assertEqual(raw["data"]["scenario_id"], "BB-M1")
        self.assertEqual(raw["data"]["container_id"], "9c6810f2abd8")

    def test_mapped_event_normalizes_cleanly(self):
        """The collector output must survive the ingestion normalizer."""
        raw = map_event(
            _exec_event(
                "/usr/bin/sh", 324412,
                "/usr/sbin/apache2", 10,
                "9c6810f2abd8a2e2d0d5a8b82c11a7b",
                args='-c "id; /usr/local/bin/system-backup"',
            ),
            scenario_id="BB-M1",
        )

        norm = normalize_event(raw)
        self.assertEqual(norm["process"]["name"], "sh")
        self.assertEqual(norm["process"]["pid"], 324412)
        self.assertEqual(norm["process"]["parent_pid"], 10)
        self.assertEqual(norm["event_type"], "process_created")
        self.assertIn("system-backup", norm["process"]["command_line"])
        self.assertEqual(norm["hostname"], "9c6810f2abd8")

    def test_non_exec_event_is_skipped(self):
        self.assertIsNone(
            map_event({"process_exit": {"process": {}}}, scenario_id=None)
        )


if __name__ == "__main__":
    unittest.main()
