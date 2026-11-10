#!/usr/bin/env python3
"""Tetragon -> BLACKBOX collector.

Streams process events from a running Tetragon sensor (via `tetra
getevents -o json`), keeps only the events that belong to the lab
containers we care about, maps each one to a BLACKBOX raw event and
POSTs it to the ingestion API.

This is a read-only observer: it never touches the target containers.
Tetragon watches them from the host kernel through eBPF, so the
monitored machines run unmodified.

Usage:
    python -m backend.collector.tetragon_collector \
        --sensor-container bb-tetragon \
        --match 9c6810f2abd8 \
        --scenario BB-M1 \
        --api http://127.0.0.1:8000/events
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Tetragon reports the container id as a prefix of the full id; matching
# is done on this many leading characters.
MATCH_LEN = 12


def _posix_name(binary: str | None) -> str | None:
    if not binary:
        return None
    return binary.rsplit("/", 1)[-1]


def _command_line(process: dict) -> str | None:
    binary = process.get("binary")
    if not binary:
        return None

    arguments = process.get("arguments")
    return f"{binary} {arguments}" if arguments else binary


def _container_id(process: dict) -> str | None:
    docker = process.get("docker")
    if not docker:
        return None
    return docker[:MATCH_LEN]


def map_event(tetra_event: dict, scenario_id: str | None) -> dict | None:
    """Translate one Tetragon event into a BLACKBOX raw event.

    Returns None for event kinds we do not ingest.
    """

    exec_ = tetra_event.get("process_exec")
    if exec_ is None:
        # process_exit and other kinds are ignored for now; the exec
        # stream alone is enough to reconstruct the process tree.
        return None

    process = exec_.get("process") or {}
    parent = exec_.get("parent") or {}

    container_id = _container_id(process)
    timestamp = process.get("start_time") or tetra_event.get("time")

    return {
        "event_id": process.get("exec_id"),
        "source": "tetragon",
        "event_type": "process_created",
        "timestamp": timestamp,
        "severity": "info",
        "data": {
            "scenario_id": scenario_id,
            "host": container_id,
            "process_name": _posix_name(process.get("binary")),
            "pid": process.get("pid"),
            "parent_pid": parent.get("pid"),
            "command_line": _command_line(process),
            "parent_process_name": _posix_name(parent.get("binary")),
            "uid": process.get("uid"),
            "container_id": container_id,
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
        # 409 (duplicate) is expected on replay and is not a failure.
        if error.code == 409:
            return True, "duplicate"
        return False, f"HTTP {error.code}: {error.read().decode('utf-8')}"
    except URLError as error:
        return False, f"connection error: {error.reason}"


def stream_events(sensor_container: str):
    """Yield parsed Tetragon JSON events from the sensor container."""

    proc = subprocess.Popen(
        ["docker", "exec", sensor_container,
         "tetra", "getevents", "-o", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run(args: argparse.Namespace) -> None:
    matches = {m[:MATCH_LEN] for m in args.match}
    sent = 0

    print(
        f"[*] Collector online | sensor={args.sensor_container} "
        f"| containers={sorted(matches)} | api={args.api}",
        flush=True,
    )

    for tetra_event in stream_events(args.sensor_container):
        exec_ = tetra_event.get("process_exec")
        if exec_ is None:
            continue

        container_id = _container_id(exec_.get("process") or {})
        if matches and container_id not in matches:
            continue

        event = map_event(tetra_event, args.scenario)
        if event is None:
            continue

        ok, detail = send_event(args.api, event)
        if ok:
            sent += 1
            name = event["data"]["process_name"]
            print(f"[+] {name} (pid {event['data']['pid']}) -> {detail}",
                  flush=True)
        else:
            print(f"[-] send failed: {detail}", file=sys.stderr, flush=True)

    print(f"[*] Stream ended. {sent} events forwarded.", flush=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tetragon -> BLACKBOX collector")
    parser.add_argument(
        "--sensor-container", default="bb-tetragon",
        help="Name of the running Tetragon container",
    )
    parser.add_argument(
        "--match", nargs="+", required=True,
        help="Container id prefix(es) to collect events for",
    )
    parser.add_argument(
        "--scenario", default=None,
        help="Scenario id to tag every collected event with",
    )
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
