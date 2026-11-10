import json
import unittest
from pathlib import Path

from backend.normalization import normalize_event


class TestNormalization(unittest.TestCase):

    def test_process_event(self):
        raw = {
            "timestamp": "2026-11-10T12:00:00Z",
            "source": "blackbox_simulator",
            "severity": "medium",
            "scenario_id": "BB-001",
            "synthetic": True,
            "data": {
                "event_type": "process_created",
                "process_name": "bash",
                "pid": 1000,
                "parent_pid": 900,
                "command_line": "bash"
            }
        }

        result = normalize_event(raw)

        self.assertEqual(result["event_type"], "process_created")
        self.assertEqual(result["process"]["name"], "bash")
        self.assertEqual(result["process"]["pid"], 1000)
        self.assertEqual(result["process"]["parent_pid"], 900)
        self.assertTrue(result["synthetic"])
        self.assertEqual(result["scenario_id"], "BB-001")
        self.assertEqual(result["raw_data"], raw)

    def test_network_event(self):
        raw = {
            "timestamp": "2026-11-10T12:00:00Z",
            "data": {
                "event_type": "network_connection",
                "destination_ip": "192.0.2.10",
                "destination_port": "80",
                "protocol": "tcp"
            }
        }

        result = normalize_event(raw)

        self.assertEqual(
            result["network"]["destination_ip"],
            "192.0.2.10"
        )
        self.assertEqual(
            result["network"]["destination_port"],
            80
        )
        self.assertEqual(result["network"]["protocol"], "TCP")

    def test_windows_field_aliases(self):
        raw = {
            "timestamp": "2026-11-10T12:00:00Z",
            "data": {
                "event_type": "process_created",
                "Image": "powershell.exe",
                "ProcessId": "1500",
                "ParentProcessId": "1200"
            }
        }

        result = normalize_event(raw)

        self.assertEqual(result["process"]["name"], "powershell.exe")
        self.assertEqual(result["process"]["pid"], 1500)
        self.assertEqual(result["process"]["parent_pid"], 1200)

    def test_missing_timestamp(self):
        raw = {
            "data": {
                "event_type": "process_created"
            }
        }

        with self.assertRaises(ValueError):
            normalize_event(raw)

    def test_bb001_scenario(self):
        """Every event of the real BB-001 scenario must normalize fully."""
        scenario_file = (
            Path(__file__).resolve().parent.parent
            / "scenarios" / "test_incident.json"
        )
        scenario = json.loads(scenario_file.read_text(encoding="utf-8"))

        results = [
            normalize_event({
                "source": "blackbox_simulator",
                "timestamp": "2026-11-10T12:00:00Z",
                "event_type": event["event_type"],
                "severity": event["severity"],
                "data": {
                    **event["data"],
                    "scenario_id": scenario["scenario_id"],
                    "synthetic": True,
                },
            })
            for event in scenario["events"]
        ]

        chain = [
            (r["process"]["name"], r["process"]["pid"],
             r["process"]["parent_pid"])
            for r in results[:3]
        ]
        self.assertEqual(chain, [
            ("bash", 1000, 900),
            ("python3", 1100, 1000),
            ("curl", 1200, 1100),
        ])

        network = results[3]
        self.assertEqual(network["process"]["name"], "curl")
        self.assertEqual(network["network"]["destination_ip"], "192.0.2.10")
        self.assertEqual(network["network"]["destination_port"], 80)
        self.assertTrue(all(r["scenario_id"] == "BB-001" for r in results))

    def test_top_level_name_is_not_process_name(self):
        raw = {
            "timestamp": "2026-11-10T12:00:00Z",
            "event_type": "network_connection",
            "data": {"name": "BB-001 scenario"},
        }

        self.assertIsNone(normalize_event(raw)["process"]["name"])

    def test_missing_event_type(self):
        raw = {
            "timestamp": "2026-11-10T12:00:00Z",
            "data": {}
        }

        with self.assertRaises(ValueError):
            normalize_event(raw)


if __name__ == "__main__":
    unittest.main()
