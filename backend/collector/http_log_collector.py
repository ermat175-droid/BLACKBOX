#!/usr/bin/env python3
"""HTTP access-log -> BLACKBOX collector.

Follows a lab container's stdout/stderr, recognizes an access-log line in
one of several server formats, and forwards each HTTP request to the
BLACKBOX ingestion API as an `http_request` event. Non-request lines are
ignored.

Supported formats (auto-detected per line):
* Apache / nginx "combined" (ip, time, request, status, referer, UA);
* uvicorn / FastAPI default ("INFO:  ip:port - \"GET /x HTTP/1.1\" 200 OK").

A line in a format with no timestamp is stamped with the collector's own
receipt time (the same clock the Tetragon collector uses), so the two
streams stay correlatable.

Read-only observer: it only reads `docker logs`, never touches the
container.

Usage:
    python -m backend.collector.http_log_collector \
        --container bb-portal \
        --scenario BB-M1 \
        --api http://127.0.0.1:8000/events
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Tetragon reports containers by the first 12 chars of their id; the HTTP
# collector must use the same key so events from both streams correlate.
ID_LEN = 12


def resolve_container_id(name: str) -> str:
    """Return the 12-char container id for a name, or the name itself."""
    try:
        full = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Id}}", name],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
        return full[:ID_LEN] if full else name
    except subprocess.CalledProcessError:
        return name


# Apache / nginx combined:
# 172.17.0.1 - - [10/Nov/2026:14:45:37 +0000] "GET /x HTTP/1.1" 200 4464 "-" "curl/8.23.0"
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# uvicorn / FastAPI default access log (no timestamp in the line):
# INFO:     172.18.0.1:49976 - "GET /x?y HTTP/1.1" 200 OK
UVICORN_RE = re.compile(
    r'^INFO:\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+ - '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3})'
)

APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_combined(line: str) -> dict | None:
    m = COMBINED_RE.match(line)
    if m is None:
        return None
    f = m.groupdict()
    f["fmt"] = "apache"
    return f


def _parse_uvicorn(line: str) -> dict | None:
    m = UVICORN_RE.match(line)
    if m is None:
        return None
    f = m.groupdict()
    f["fmt"] = "uvicorn"
    return f  # no time / referer / ua in this format


# Tried in order; first match wins.
PARSERS = (_parse_combined, _parse_uvicorn)


def parse_line(line: str) -> dict | None:
    line = line.strip()
    for parser in PARSERS:
        fields = parser(line)
        if fields is not None:
            return fields
    return None


def _iso_time(apache_time: str) -> str:
    return datetime.strptime(apache_time, APACHE_TIME_FMT).isoformat()


def map_line(fields: dict, container: str, scenario_id: str | None) -> dict:
    # Formats without a timestamp (e.g. uvicorn) are stamped with the
    # collector's receipt time, on the same clock as the Tetragon collector.
    log_time = fields.get("time")
    if log_time:
        timestamp = _iso_time(log_time)
        id_basis = log_time
    else:
        timestamp = datetime.now(timezone.utc).isoformat()
        id_basis = timestamp  # microsecond-precision: keeps repeats distinct

    # No unique id in a log line; derive a stable one from its content.
    fingerprint = "|".join([
        container, id_basis, fields["ip"],
        fields["method"], fields["path"], fields["status"],
    ])
    event_id = "http-" + hashlib.sha1(fingerprint.encode()).hexdigest()[:24]

    status = int(fields["status"])
    severity = "warning" if status >= 500 else "info"

    return {
        "event_id": event_id,
        "source": fields.get("fmt", "http"),
        "event_type": "http_request",
        "timestamp": timestamp,
        "severity": severity,
        "data": {
            "scenario_id": scenario_id,
            "host": container,
            "container_id": container,
            "source_ip": fields["ip"],
            "http_method": fields["method"],
            "http_path": fields["path"],
            "http_status": status,
            "user_agent": fields.get("ua"),
            "referer": fields.get("referer"),
        },
    }


def send_event(api_url: str, event: dict) -> tuple[bool, str]:
    request = Request(
        api_url,
        data=json.dumps(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            return True, f"id={body['id']}"
    except HTTPError as error:
        if error.code == 409:
            return True, "duplicate"
        return False, f"HTTP {error.code}: {error.read().decode('utf-8')}"
    except URLError as error:
        return False, f"connection error: {error.reason}"


def stream_log_lines(container: str, since: str):
    proc = subprocess.Popen(
        ["docker", "logs", "-f", "--since", since, container],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run(args: argparse.Namespace) -> None:
    sent = 0
    container_id = resolve_container_id(args.container)
    print(
        f"[*] HTTP collector online | container={args.container} "
        f"(id {container_id}) | api={args.api}",
        flush=True,
    )

    for line in stream_log_lines(args.container, args.since):
        fields = parse_line(line)
        if fields is None:
            continue

        event = map_line(fields, container_id, args.scenario)
        ok, detail = send_event(args.api, event)
        if ok:
            sent += 1
            print(
                f"[+] {event['data']['http_method']} "
                f"{event['data']['http_path']} "
                f"({event['data']['http_status']}) -> {detail}",
                flush=True,
            )
        else:
            print(f"[-] send failed: {detail}", file=sys.stderr, flush=True)

    print(f"[*] Stream ended. {sent} requests forwarded.", flush=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTP access-log -> BLACKBOX collector")
    parser.add_argument("--container", required=True,
                        help="Name of the lab container to follow")
    parser.add_argument("--scenario", default=None,
                        help="Scenario id to tag every request with")
    parser.add_argument("--since", default="0m",
                        help="docker logs --since value (default: 0m)")
    parser.add_argument(
        "--api",
        default=os.getenv("BLACKBOX_API", "http://127.0.0.1:8000/events"),
        help="BLACKBOX ingestion endpoint",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        run(parse_args())
    except KeyboardInterrupt:
        print("\n[*] Collector stopped.", flush=True)
