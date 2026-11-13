import unittest

from backend.correlation import correlate
from backend.infrastructure import discover, impact, _is_private
from backend.reconstruction import reconstruct


def _proc(eid, name, pid, ppid, ts, cmd=None, parent_name=None):
    return {
        "event_id": eid, "event_type": "process_created", "timestamp": ts,
        "hostname": "app.target", "process": {
            "name": name, "pid": pid, "parent_pid": ppid,
            "command_line": cmd, "parent_name": parent_name},
        "network": {}, "http": {},
    }


def _net(eid, pid, dip, dport, ts):
    return {
        "event_id": eid, "event_type": "network_connection", "timestamp": ts,
        "hostname": "app.target",
        "process": {"name": "node", "pid": pid},
        "network": {"destination_ip": dip, "destination_port": dport, "protocol": "TCP"},
        "http": {},
    }


def _http(eid, path, ts):
    return {
        "event_id": eid, "event_type": "http_request", "timestamp": ts,
        "hostname": "app.target",
        "http": {"method": "GET", "path": path, "status": 200},
        "network": {"source_ip": "172.18.0.1"}, "process": {},
    }


# A full SSTI -> RCE -> privesc -> flag read incident on a uvicorn app.
INCIDENT = [
    _http("h1", "/pdf?t={{ self.__globals__.__import__('os').popen('cat /root/flag.txt') }}",
          "2026-01-01T10:00:00"),
    _proc("web", "uvicorn", 10, 1, "2026-01-01T10:00:01"),
    _proc("sh1", "sh", 50, 10, "2026-01-01T10:00:02",
          cmd="/bin/sh -c cat /root/flag.txt", parent_name="uvicorn"),
    _proc("cat", "cat", 51, 50, "2026-01-01T10:00:03", cmd="/usr/bin/cat /root/flag.txt"),
    _proc("rb", "rootbash", 52, 10, "2026-01-01T10:00:04",
          cmd="/var/tmp/rootbash -p", parent_name="uvicorn"),
    _net("n1", 10, "127.0.0.1", 6379, "2026-01-01T10:00:05"),      # redis
    _net("n2", 10, "104.18.33.147", 443, "2026-01-01T10:00:06"),   # external
]


def _recon(events):
    return reconstruct(events, correlate(events))


class TestDiscover(unittest.TestCase):

    def setUp(self):
        self.infra = discover(INCIDENT, _recon(INCIDENT))
        self.by_type = {}
        for a in self.infra["assets"]:
            self.by_type.setdefault(a["type"], []).append(a)

    def test_host_present_and_compromised(self):
        host = self.by_type["host"][0]
        self.assertEqual(host["status"], "compromised")

    def test_web_service_discovered_and_compromised(self):
        svc = self.by_type["service"]
        self.assertTrue(any("uvicorn" in a["label"] for a in svc))
        self.assertTrue(all(a["status"] == "compromised" for a in svc))

    def test_datastore_discovered(self):
        stores = self.by_type["datastore"]
        self.assertTrue(any("Redis" in a["label"] for a in stores))

    def test_external_egress_asset(self):
        egress = self.by_type["egress"]
        self.assertTrue(any("104.18.33.147" in a["label"] for a in egress))

    def test_secret_asset_compromised(self):
        secrets = self.by_type["secret"]
        self.assertTrue(any("/root/flag.txt" in a["label"] for a in secrets))
        self.assertTrue(any(a["status"] == "compromised" for a in secrets))

    def test_root_privilege_asset(self):
        self.assertIn("privilege", self.by_type)
        self.assertEqual(self.by_type["privilege"][0]["status"], "compromised")

    def test_links_connect_host_to_service(self):
        ids = {a["id"] for a in self.infra["assets"]}
        for l in self.infra["links"]:
            self.assertIn(l["source"], ids)
            self.assertIn(l["target"], ids)


class TestImpact(unittest.TestCase):

    def test_full_incident_is_critical(self):
        imp = impact(INCIDENT, _recon(INCIDENT))
        self.assertEqual(imp["severity"], "critical")
        self.assertTrue(imp["root_achieved"])
        self.assertTrue(imp["code_execution"])
        self.assertTrue(any("flag" in s for s in imp["secrets_read"]))
        self.assertIn("104.18.33.147:443", imp["egress_attempts"])

    def test_benign_is_low(self):
        events = [_http("h", "/index.html", "2026-01-01T10:00:00")]
        imp = impact(events, _recon(events))
        self.assertEqual(imp["severity"], "low")
        self.assertFalse(imp["root_achieved"])


class TestHelpers(unittest.TestCase):

    def test_is_private(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.18.0.1"):
            self.assertTrue(_is_private(ip))
        for ip in ("104.18.33.147", "8.8.8.8", "172.32.0.1"):
            self.assertFalse(_is_private(ip))


if __name__ == "__main__":
    unittest.main()
