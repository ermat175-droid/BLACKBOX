import json
import tempfile
import unittest
from pathlib import Path

from backend import targets as tg


class TestPureHelpers(unittest.TestCase):

    def test_slugify(self):
        self.assertEqual(tg.slugify("My Shop App!"), "my-shop-app")
        self.assertEqual(tg.slugify("  ice_portal 1 "), "ice-portal-1")

    def test_slugify_rejects_empty(self):
        with self.assertRaises(tg.TargetError):
            tg.slugify("!!!")

    def test_validate_image_source(self):
        self.assertEqual(
            tg.validate_source({"type": "image", "image": "ice-public-portal:latest"}),
            {"type": "image", "image": "ice-public-portal:latest"},
        )

    def test_validate_rejects_shell_in_image(self):
        with self.assertRaises(tg.TargetError):
            tg.validate_source({"type": "image", "image": "img; rm -rf /"})

    def test_validate_rejects_unknown_type(self):
        with self.assertRaises(tg.TargetError):
            tg.validate_source({"type": "url", "url": "http://x"})

    def test_validate_build_requires_dockerfile(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(tg.TargetError):
                tg.validate_source({"type": "build", "path": d})
            (Path(d) / "Dockerfile").write_text("FROM scratch\n")
            out = tg.validate_source({"type": "build", "path": d})
            self.assertEqual(out["type"], "build")
            self.assertTrue(out["path"].endswith(d.rstrip("/").split("/")[-1]))

    def test_run_argv_binds_localhost(self):
        argv = tg.run_argv("bb-tgt-x", "img:latest", 8100, 80)
        self.assertIn("127.0.0.1:8100:80", argv)
        self.assertNotIn("0.0.0.0:8100:80", " ".join(argv))

    def test_run_argv_never_pulls(self):
        # a lab target must be local; the sandbox must not reach a registry
        self.assertIn("--pull=never", tg.run_argv("bb-tgt-x", "img:latest", 8100, 80))

    def test_next_host_port_skips_used(self):
        reg = [{"host_port": 8100}, {"host_port": 8101}, {"host_port": 8103}]
        self.assertEqual(tg.next_host_port(reg), 8102)
        self.assertEqual(tg.next_host_port([]), tg.PORT_BASE)


class TestRegistry(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self._tmp.close()
        Path(self._tmp.name).unlink()            # start with no file
        self._orig = tg.REGISTRY_PATH
        tg.REGISTRY_PATH = Path(self._tmp.name)

    def tearDown(self):
        tg.REGISTRY_PATH = self._orig
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_add_assigns_port_scenario_and_container(self):
        rec = tg.add_target("Ice Portal", {"type": "image", "image": "ice-public-portal:latest"})
        self.assertEqual(rec["id"], "ice-portal")
        self.assertEqual(rec["scenario_id"], "TGT-ice-portal")
        self.assertEqual(rec["container"], "bb-tgt-ice-portal")
        self.assertEqual(rec["host_port"], tg.PORT_BASE)
        self.assertEqual(rec["status"], "stopped")
        # persisted
        saved = json.loads(Path(self._tmp.name).read_text("utf-8"))
        self.assertEqual(len(saved), 1)

    def test_add_second_target_gets_next_port(self):
        tg.add_target("A", {"type": "image", "image": "a:latest"})
        b = tg.add_target("B", {"type": "image", "image": "b:latest"})
        self.assertEqual(b["host_port"], tg.PORT_BASE + 1)

    def test_duplicate_name_rejected(self):
        tg.add_target("Dup", {"type": "image", "image": "a:latest"})
        with self.assertRaises(tg.TargetError):
            tg.add_target("dup", {"type": "image", "image": "b:latest"})

    def test_bad_container_port_rejected(self):
        with self.assertRaises(tg.TargetError):
            tg.add_target("X", {"type": "image", "image": "a:latest"}, container_port=99999)


if __name__ == "__main__":
    unittest.main()
