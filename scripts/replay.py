#!/usr/bin/env python3
"""Replay a captured incident fixture into a running BLACKBOX API.

Each line of the fixture is one raw event exactly as a collector POSTed
it live. Replaying it reproduces the same incident graph offline, with no
Tetragon sensor or lab container running — which is what the demo uses.

Usage:
    python scripts/replay.py fixtures/incident_bb_m1.jsonl
    python scripts/replay.py fixtures/incident_bb_m1.jsonl --api http://127.0.0.1:8000/events
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def post(api: str, event: dict) -> tuple[bool, str]:
    req = Request(
        api,
        data=json.dumps(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return True, f"id={body['id']}"
    except HTTPError as error:
        if error.code == 409:  # already loaded — replay is idempotent
            return True, "duplicate"
        return False, f"HTTP {error.code}: {error.read().decode('utf-8')}"
    except URLError as error:
        return False, f"connection error: {error.reason}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay an incident fixture")
    parser.add_argument("fixture", help="Path to a .jsonl event fixture")
    parser.add_argument(
        "--api", default="http://127.0.0.1:8000/events",
        help="BLACKBOX ingestion endpoint",
    )
    args = parser.parse_args(argv)

    sent = dup = failed = 0
    with open(args.fixture, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            ok, detail = post(args.api, event)
            if not ok:
                failed += 1
                print(f"[-] {detail}", file=sys.stderr)
            elif detail == "duplicate":
                dup += 1
            else:
                sent += 1

    print(f"[*] Replay done: {sent} ingested, {dup} duplicate, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
