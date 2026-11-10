import unittest

from backend.correlation import correlate
from backend.normalization import normalize_event


def http(path, ts, eid):
    return normalize_event({
        "event_id": eid,
        "source": "apache",
        "event_type": "http_request",
        "timestamp": ts,
        "severity": "info",
        "data": {
            "scenario_id": "BB-M1",
            "host": "c1",
            "source_ip": "172.17.0.1",
            "http_method": "GET",
            "http_path": path,
            "http_status": 200,
        },
    })


def proc(name, pid, ppid, ts, eid, parent_name=None):
    return normalize_event({
        "event_id": eid,
        "source": "tetragon",
        "event_type": "process_created",
        "timestamp": ts,
        "severity": "info",
        "data": {
            "scenario_id": "BB-M1",
            "host": "c1",
            "process_name": name,
            "pid": pid,
            "parent_pid": ppid,
            "command_line": name,
            "parent_process_name": parent_name,
        },
    })


def net(pid, dst_ip, dst_port, ts, eid):
    return normalize_event({
        "event_id": eid,
        "source": "tetragon",
        "event_type": "network_connection",
        "timestamp": ts,
        "severity": "warning",
        "data": {
            "scenario_id": "BB-M1",
            "host": "c1",
            "pid": pid,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "protocol": "TCP",
        },
    })


class TestCorrelation(unittest.TestCase):

    def _edges(self, graph, kind):
        return [e for e in graph["edges"] if e["kind"] == kind]

    def test_process_tree_by_pid(self):
        events = [
            proc("apache2", 10, 1, "2026-11-10T12:00:00Z", "p-apache"),
            proc("sh", 100, 10, "2026-11-10T12:00:01Z", "p-sh"),
            proc("curl", 101, 100, "2026-11-10T12:00:02Z", "p-curl"),
        ]
        graph = correlate(events)
        parent_edges = {
            (e["source"], e["target"]) for e in self._edges(graph, "parent_of")
        }
        self.assertIn(("p-apache", "p-sh"), parent_edges)
        self.assertIn(("p-sh", "p-curl"), parent_edges)

    def test_http_spawns_process(self):
        events = [
            http("/upload.phtml", "2026-11-10T12:00:00Z", "h1"),
            proc("apache2", 10, 1, "2026-11-10T11:59:00Z", "p-apache"),
            proc("sh", 100, 10, "2026-11-10T12:00:01Z", "p-sh",
                 parent_name="apache2"),
        ]
        graph = correlate(events)
        spawned = self._edges(graph, "spawned_by")
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0]["source"], "h1")
        self.assertEqual(spawned[0]["target"], "p-sh")

    def test_only_most_recent_request_matches_amid_many(self):
        """Blind-SQLi burst must not create false spawn edges."""
        events = [
            http("/sqli?order=1", "2026-11-10T12:00:00Z", "h1"),
            http("/sqli?order=2", "2026-11-10T12:00:01Z", "h2"),
            http("/shell.phtml?c=id", "2026-11-10T12:00:02Z", "h3"),
            proc("sh", 100, 10, "2026-11-10T12:00:02Z", "p-sh",
                 parent_name="apache2"),
        ]
        spawned = self._edges(correlate(events), "spawned_by")
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0]["source"], "h3")

    def test_non_webserver_child_is_not_attributed(self):
        events = [
            http("/", "2026-11-10T12:00:00Z", "h1"),
            proc("sh", 100, 10, "2026-11-10T12:00:01Z", "p-sh",
                 parent_name="sh"),
        ]
        self.assertEqual(self._edges(correlate(events), "spawned_by"), [])

    def test_http_does_not_match_outside_window(self):
        events = [
            http("/", "2026-11-10T12:00:00Z", "h1"),
            proc("sh", 100, 10, "2026-11-10T12:00:30Z", "p-late",
                 parent_name="apache2"),
        ]
        graph = correlate(events)
        self.assertEqual(self._edges(graph, "spawned_by"), [])

    def test_network_linked_to_process(self):
        events = [
            proc("curl", 101, 100, "2026-11-10T12:00:02Z", "p-curl"),
            net(101, "192.0.2.10", 80, "2026-11-10T12:00:03Z", "n1"),
        ]
        graph = correlate(events)
        conn = self._edges(graph, "connected_to")
        self.assertEqual(len(conn), 1)
        self.assertEqual(conn[0]["source"], "p-curl")
        self.assertEqual(conn[0]["target"], "n1")

    def test_full_chain_single_root(self):
        events = [
            http("/upload.phtml", "2026-11-10T12:00:00Z", "h1"),
            proc("apache2", 10, 1, "2026-11-10T11:59:00Z", "p-apache"),
            proc("sh", 100, 10, "2026-11-10T12:00:01Z", "p-sh"),
            proc("curl", 101, 100, "2026-11-10T12:00:02Z", "p-curl"),
            net(101, "192.0.2.10", 80, "2026-11-10T12:00:03Z", "n1"),
        ]
        graph = correlate(events)
        # every edge records a reason
        self.assertTrue(all(e["reason"] for e in graph["edges"]))
        # the http request and the apache root are not spawned by anything
        self.assertIn("h1", graph["roots"])


if __name__ == "__main__":
    unittest.main()


class TestSpawnContentMatch(unittest.TestCase):

    def test_prefers_request_that_carried_command(self):
        # Two requests in the same second; only one carries the command.
        cmd = "cat /root/flag.txt > /tmp/out"
        events = [
            http("/sqli?order=99", "2026-11-10T12:00:02Z", "h-sqli"),
            http(f"/shell.phtml?c={cmd.replace(' ', '%20')}",
                 "2026-11-10T12:00:02Z", "h-shell"),
            proc("sh", 100, 10, "2026-11-10T12:00:02Z", "p-sh",
                 parent_name="apache2"),
        ]
        events[2]["process"]["command_line"] = f"/bin/sh -c -- {cmd}"
        spawned = [e for e in correlate(events)["edges"]
                   if e["kind"] == "spawned_by"]
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0]["source"], "h-shell")
        self.assertIn("carried the command", spawned[0]["reason"])


if __name__ == "__main__":
    unittest.main()
