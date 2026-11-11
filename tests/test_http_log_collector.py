import unittest

from backend.collector.http_log_collector import map_line, parse_line
from backend.normalization import normalize_event

ACCESS = (
    '172.17.0.1 - - [10/Nov/2026:14:45:37 +0000] '
    '"GET /api/preview_reports.php?order=1 HTTP/1.1" 200 4464 '
    '"-" "curl/8.23.0"'
)
NOTICE = (
    "[Tue Nov 10 14:39:58.257520 2026] [mpm_prefork:notice] "
    "[pid 25:tid 25] AH00163: Apache configured"
)
# uvicorn / FastAPI default access line (no timestamp), carrying an SSTI payload
UVICORN = (
    'INFO:     172.18.0.1:49976 - "GET /export/generate-pdf?report_title='
    '%7B%7B+self.__init__.__globals__+%7D%7D HTTP/1.1" 200 OK'
)
UVICORN_STARTUP = "INFO:     Application startup complete."


class TestHttpLogCollector(unittest.TestCase):

    def test_parses_combined_line(self):
        fields = parse_line(ACCESS)
        self.assertEqual(fields["ip"], "172.17.0.1")
        self.assertEqual(fields["method"], "GET")
        self.assertEqual(fields["path"], "/api/preview_reports.php?order=1")
        self.assertEqual(fields["status"], "200")
        self.assertEqual(fields["ua"], "curl/8.23.0")

    def test_ignores_non_access_lines(self):
        self.assertIsNone(parse_line(NOTICE))
        self.assertIsNone(parse_line(""))

    def test_maps_and_normalizes(self):
        event = map_line(parse_line(ACCESS), "bb-portal", "BB-M1")
        self.assertEqual(event["event_type"], "http_request")

        norm = normalize_event(event)
        self.assertEqual(norm["http"]["method"], "GET")
        self.assertEqual(
            norm["http"]["path"], "/api/preview_reports.php?order=1"
        )
        self.assertEqual(norm["http"]["status"], 200)
        self.assertEqual(norm["network"]["source_ip"], "172.17.0.1")
        self.assertEqual(norm["hostname"], "bb-portal")

    def test_event_id_is_stable(self):
        a = map_line(parse_line(ACCESS), "bb-portal", "BB-M1")
        b = map_line(parse_line(ACCESS), "bb-portal", "BB-M1")
        self.assertEqual(a["event_id"], b["event_id"])

    def test_5xx_is_warning(self):
        line = ACCESS.replace('" 200 ', '" 500 ')
        event = map_line(parse_line(line), "bb-portal", "BB-M1")
        self.assertEqual(event["severity"], "warning")

    def test_parses_uvicorn_line(self):
        fields = parse_line(UVICORN)
        self.assertIsNotNone(fields)
        self.assertEqual(fields["fmt"], "uvicorn")
        self.assertEqual(fields["ip"], "172.18.0.1")
        self.assertEqual(fields["method"], "GET")
        self.assertIn("generate-pdf", fields["path"])
        self.assertEqual(fields["status"], "200")

    def test_uvicorn_startup_line_ignored(self):
        self.assertIsNone(parse_line(UVICORN_STARTUP))

    def test_uvicorn_maps_and_normalizes(self):
        event = map_line(parse_line(UVICORN), "bb-test", "TGT-test")
        self.assertEqual(event["source"], "uvicorn")
        norm = normalize_event(event)
        self.assertEqual(norm["http"]["method"], "GET")
        self.assertIn("generate-pdf", norm["http"]["path"])
        self.assertEqual(norm["network"]["source_ip"], "172.18.0.1")
        # no timestamp in the line -> a valid receipt timestamp is filled in
        self.assertTrue(norm["timestamp"])


if __name__ == "__main__":
    unittest.main()
