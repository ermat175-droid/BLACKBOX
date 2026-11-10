#!/usr/bin/env python3
"""Apache (combined log) -> BLACKBOX collector.

Follows a lab container's stdout, parses Apache "combined" access-log
lines and forwards each HTTP request to the BLACKBOX ingestion API as an
`http_request` event. Apache notice/error lines are ignored.

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
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# 172.17.0.1 - - [10/Nov/2026:14:45:37 +0000] "GET /x HTTP/1.1" 200 4464 "-" "curl/8.23.0"
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> dict | None:
    match = COMBINED_RE.match(line.strip())
    if match is None:
        return None
    return match.groupdict()


def _iso_time(apache_time: str) -> str:
    return datetime.strptime(apache_time, APACHE_TIME_FMT).isoformat()


def map_line(fields: dict, container: str, scenario_id: str | None) -> dict:
    timestamp = _iso_time(fields["time"])

    # Combined logs have no unique id; derive a stable one so replays of the
    # same log don't create duplicates.
    fingerprint = "|".join([
        container, fields["time"], fields["ip"],
        fields["method"], fields["path"], fields["status"],
    ])
    event_id = "http-" + hashlib.sha1(fingerprint.encode()).hexdigest()[:24]

    status = int(fields["status"])
    severity = "warning" if status >= 500 else "info"

    return {
        "event_id": event_id,
        "source": "apache",
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
            "user_agent": fields["ua"],
            "referer": fields["referer"],
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
    print(
        f"[*] HTTP collector online | container={args.container} "
        f"| api={args.api}",
        flush=True,
    )

    for line in stream_log_lines(args.container, args.since):
        fields = parse_line(line)
        if fields is None:
            continue

        event = map_line(fields, args.container, args.scenario)
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
    parser = argparse.ArgumentParser(description="Apache log -> BLACKBOX collector")
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
