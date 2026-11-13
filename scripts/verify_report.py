#!/usr/bin/env python3
"""Independently verify a BLACKBOX investigation report.

Recomputes the report's content digest from the report body alone and checks
it against the embedded seal — no secret needed. Optionally checks the
report's chain head against a live BLACKBOX instance.

    python scripts/verify_report.py report.json
    python scripts/verify_report.py report.json --api http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from urllib.request import urlopen


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify a BLACKBOX report")
    ap.add_argument("report", help="path to report.json")
    ap.add_argument("--api", help="live BLACKBOX base url to check the chain head")
    args = ap.parse_args(argv)

    with open(args.report, encoding="utf-8") as f:
        doc = json.load(f)
    body, seal = doc["report"], doc["seal"]

    digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    ok = digest == seal["content_sha256"]
    print(f"content digest: {'MATCH' if ok else 'MISMATCH'}")
    if not ok:
        print(f"  expected {seal['content_sha256']}\n  computed {digest}")

    head_ok = True
    if args.api:
        live = json.loads(urlopen(f"{args.api.rstrip('/')}/integrity", timeout=5).read())
        head_ok = live.get("head") == seal.get("chain_head")
        print(f"chain head vs live store: {'MATCH' if head_ok else 'MISMATCH'}")

    verified = ok and head_ok
    print("REPORT VERIFIED" if verified else "REPORT FAILED VERIFICATION")
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
