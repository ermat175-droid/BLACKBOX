#!/usr/bin/env python3
"""Rebuild the evidence hash chain over all stored events, in id order.

Use after a schema change, or after a bug left the chain inconsistent
(e.g. the pre-lock concurrent-ingest race). This re-anchors the chain to
the *current* stored content, so run it only when you trust that content;
it is an operator tool, not part of the API surface.

    python scripts/rehash.py
"""

from __future__ import annotations

from sqlalchemy import select

from backend.database import SessionLocal
from backend.integrity import GENESIS, chain_hash, content_hash
from backend.models import Event


def main() -> None:
    db = SessionLocal()
    try:
        rows = list(db.scalars(select(Event).order_by(Event.id)))
        prev = GENESIS
        for r in rows:
            c = content_hash(r.normalized)
            ch = chain_hash(prev, c)
            r.content_hash = c
            r.prev_hash = prev
            r.chain_hash = ch
            prev = ch
        db.commit()
        print(f"rehashed {len(rows)} events; head={prev}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
