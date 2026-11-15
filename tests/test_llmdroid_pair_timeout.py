"""A replay timeout must leave a final inconclusive pair report."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/run-llmdroid-pair.py"
spec = importlib.util.spec_from_file_location("llmdroid_pair", SOURCE)
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class PairTimeoutTests(unittest.TestCase):
    def test_baseline_timeout_finalizes_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "app.apk"
            trace = root / "trace.json"
            apk.write_bytes(b"apk")
            trace.write_text("{}")
            output = root / "pair"
            argv = ["pair", "--checkout", str(root), "--baseline-apk", str(apk),
                    "--mutant-apk", str(apk), "--trace", str(trace),
                    "--serial", "emulator-test", "--output-dir", str(output)]
            with patch.object(sys, "argv", argv), patch.object(
                    pair, "adb_text", side_effect=["device", "1", "29", "fingerprint"]), patch.object(
                    pair.subprocess, "run", side_effect=subprocess.TimeoutExpired("replay", 270)):
                self.assertEqual(pair.main(), 1)
            report = json.loads((output / "pair-report.json").read_text())
            self.assertEqual(report["status"], "inconclusive")
            self.assertEqual(report["reason"], "baseline replay timed out")
            self.assertTrue(report["runs"]["baseline"]["timed_out"])


if __name__ == "__main__":
    unittest.main()
