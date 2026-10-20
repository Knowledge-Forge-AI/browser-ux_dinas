"""R3 legacy delivery is held before any prerequisite, backup or writer."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "delivery"))
SPEC = importlib.util.spec_from_file_location("r3_rollout", ROOT / "delivery/rollout.py")
ROLLOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROLLOUT)


class RoleHoldTests(unittest.TestCase):
    def test_apply_held_before_any_effect(self):
        args = SimpleNamespace(browser=["vivaldi"], attended=True, backup=Path("/fixture/reference-backup"))
        with mock.patch.object(ROLLOUT, "check") as check, mock.patch.object(ROLLOUT, "backup") as backup, \
             mock.patch.object(ROLLOUT, "selected_browsers") as selection, \
             mock.patch.object(ROLLOUT.subprocess, "run") as writer:
            with self.assertRaisesRegex(ValueError, "R3_DEPLOYMENT_HELD"):
                ROLLOUT.execute(args)
            check.assert_not_called()
            backup.assert_not_called()
            selection.assert_not_called()
            writer.assert_not_called()

    def test_rollback_held_before_read_or_effect(self):
        args = SimpleNamespace(browser=["vivaldi"], attended=True, backup=Path("/fixture/reference-backup"))
        with mock.patch.object(ROLLOUT.subprocess, "run") as run, \
             mock.patch.object(Path, "read_text") as read:
            with self.assertRaisesRegex(ValueError, "R3_LEGACY_ROLLBACK_HELD"):
                ROLLOUT.rollback(args)
            run.assert_not_called()
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
