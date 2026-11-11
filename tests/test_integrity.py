import unittest
from types import SimpleNamespace

from backend.integrity import (
    GENESIS, chain_hash, content_hash, link, verify_chain,
)


def _chain(normalized_list):
    """Build a well-formed chain of record objects from event contents."""
    records = []
    prev = GENESIS
    for i, norm in enumerate(normalized_list):
        c, ch = link(prev, norm)
        records.append(SimpleNamespace(
            event_id=f"e{i}", normalized=norm,
            content_hash=c, prev_hash=prev, chain_hash=ch,
        ))
        prev = ch
    return records


class TestHashing(unittest.TestCase):

    def test_content_hash_is_deterministic_and_key_order_independent(self):
        a = content_hash({"event_id": "x", "a": 1, "b": 2})
        b = content_hash({"b": 2, "event_id": "x", "a": 1})
        self.assertEqual(a, b)

    def test_content_hash_changes_with_content(self):
        self.assertNotEqual(
            content_hash({"event_id": "x", "v": 1}),
            content_hash({"event_id": "x", "v": 2}),
        )

    def test_link_matches_manual_computation(self):
        norm = {"event_id": "x", "v": 1}
        c, ch = link(GENESIS, norm)
        self.assertEqual(c, content_hash(norm))
        self.assertEqual(ch, chain_hash(GENESIS, c))


class TestVerify(unittest.TestCase):

    def setUp(self):
        self.norms = [{"event_id": f"e{i}", "v": i} for i in range(5)]

    def test_valid_chain_verifies(self):
        res = verify_chain(_chain(self.norms))
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 5)
        self.assertIsNone(res["broken_at"])
        self.assertNotEqual(res["head"], GENESIS)

    def test_empty_chain_ok_with_genesis_head(self):
        res = verify_chain([])
        self.assertTrue(res["ok"])
        self.assertEqual(res["head"], GENESIS)

    def test_tampered_content_detected(self):
        records = _chain(self.norms)
        records[2].normalized = {"event_id": "e2", "v": 999}  # edit evidence
        res = verify_chain(records)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 2)
        self.assertEqual(res["event_id"], "e2")
        self.assertEqual(res["reason"], "content altered")

    def test_removed_event_breaks_link(self):
        records = _chain(self.norms)
        del records[2]  # drop a record -> record 3's prev_hash no longer matches
        res = verify_chain(records)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 2)
        self.assertEqual(res["reason"], "chain link broken")

    def test_rewritten_hash_without_relink_detected(self):
        records = _chain(self.norms)
        records[3].chain_hash = "f" * 64  # corrupt the stored chain hash
        res = verify_chain(records)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 3)
        self.assertEqual(res["reason"], "hash mismatch")


if __name__ == "__main__":
    unittest.main()
