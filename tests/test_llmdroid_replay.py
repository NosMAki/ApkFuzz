"""Replay setup must tolerate transient Android logcat failures."""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/replay-llmdroid-trace.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("llmdroid_replay", SCRIPT)
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class LogcatResetTest(unittest.TestCase):
    def test_transient_failure_is_retried(self):
        responses = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]
        with patch.object(replay, "adb", side_effect=responses) as adb, \
                patch.object(replay.time, "sleep") as sleep:
            replay.clear_logcat("emulator-test")
        self.assertEqual(adb.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_persistent_failure_is_reported(self):
        with patch.object(replay, "adb", return_value=SimpleNamespace(returncode=1)) as adb, \
                patch.object(replay.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "after three attempts"):
                replay.clear_logcat("emulator-test")
        self.assertEqual(adb.call_count, 3)


if __name__ == "__main__":
    unittest.main()
