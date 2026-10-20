import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("transport", Path(__file__).parents[1] / "delivery/transport.py")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def test_directory_link_is_link_target_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            (source / "real").mkdir(parents=True)
            (source / "real/value").write_text("synthetic")
            (source / "alias").symlink_to("real", target_is_directory=True)
            digest = transport.pack(source, root / "kit.zip")
            records = transport.unpack(root / "kit.zip", root / "extracted")
            self.assertEqual(len(digest), 64)
            self.assertEqual(records["alias"]["kind"], "symlink")
            self.assertNotIn("alias/value", records)
            self.assertEqual((root / "extracted/alias").readlink(), Path("real"))

    def test_escape_and_symlink_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "source").mkdir()
            (root / "source/link").symlink_to("../outside")
            with self.assertRaises(ValueError):
                transport.pack(root / "source", root / "kit.zip")
        with self.assertRaises(ValueError):
            transport.validate_links({"link": {"kind": "symlink"}, "link/value": {"kind": "file"}},
                                     {"link": b"real", "link/value": b"synthetic"})


if __name__ == "__main__":
    unittest.main()
