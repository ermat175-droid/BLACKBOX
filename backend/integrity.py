"""Evidence integrity — a tamper-evident hash chain over stored events.

For the "Law & Order" framing BLACKBOX needs a chain of custody that can be
*checked*, not just asserted. Every event, in ingestion order, is linked to
the one before it:

    content_hash = sha256(canonical event)
    chain_hash   = sha256(prev_chain_hash + content_hash)

Editing an event changes its ``content_hash``; removing or reordering one
breaks the ``prev_hash`` link of the next. Either way verification fails and
points at the first broken record. The head (last ``chain_hash``) is the
single value that fixes the whole history — publish or witness it and the
store becomes tamper-evident, not merely tamper-checked.

This is deliberately simple and dependency-free (hashlib + json). It does
not by itself stop a full rewrite of the local DB; the head hash is the
anchor you would record elsewhere to detect that.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

# prev_hash of the very first event.
GENESIS = "0" * 64


def content_hash(normalized: dict) -> str:
    """Stable fingerprint of one event's canonical content."""
    payload = json.dumps(
        normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def chain_hash(prev_hash: str, c_hash: str) -> str:
    return hashlib.sha256((prev_hash + c_hash).encode("utf-8")).hexdigest()


def link(prev_hash: str, normalized: dict) -> tuple[str, str]:
    """Hashes for a new event appended after ``prev_hash``.

    Returns ``(content_hash, chain_hash)``.
    """
    c = content_hash(normalized)
    return c, chain_hash(prev_hash, c)


def verify_chain(records: Iterable[Any]) -> dict:
    """Verify an ordered run of event records.

    Each record must expose ``event_id``, ``normalized``, ``content_hash``,
    ``prev_hash`` and ``chain_hash`` (attributes). Returns::

        {
          "ok": bool,
          "count": int,            # records checked
          "head": str,             # last good chain hash (GENESIS if none)
          "broken_at": int | None, # 0-based index of first bad record
          "event_id": str | None,  # its event_id
          "reason": str | None,    # what failed
        }
    """
    prev = GENESIS
    head = GENESIS
    count = 0

    for i, r in enumerate(records):
        count += 1
        recomputed_content = content_hash(r.normalized)
        if recomputed_content != r.content_hash:
            return _broken(count, head, i, r, "content altered")
        if r.prev_hash != prev:
            return _broken(count, head, i, r, "chain link broken")
        if chain_hash(prev, recomputed_content) != r.chain_hash:
            return _broken(count, head, i, r, "hash mismatch")
        prev = r.chain_hash
        head = r.chain_hash

    return {
        "ok": True, "count": count, "head": head,
        "broken_at": None, "event_id": None, "reason": None,
    }


def _broken(count: int, head: str, i: int, r: Any, reason: str) -> dict:
    return {
        "ok": False, "count": count, "head": head,
        "broken_at": i, "event_id": getattr(r, "event_id", None),
        "reason": reason,
    }
