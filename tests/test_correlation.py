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


def proc(name, pid, ppid, ts, eid):
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
            proc("sh", 100, 10, "2026-11-10T12:00:01Z", "p-sh"),
        ]
        graph = correlate(events)
        spawned = self._edges(graph, "spawned_by")
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0]["source"], "h1")
        self.assertEqual(spawned[0]["target"], "p-sh")

    def test_http_does_not_match_webserver_or_outside_window(self):
        events = [
            http("/", "2026-11-10T12:00:00Z", "h1"),
            proc("apache2", 10, 1, "2026-11-10T12:00:01Z", "p-apache"),
            proc("sh", 100, 10, "2026-11-10T12:00:30Z", "p-late"),
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
