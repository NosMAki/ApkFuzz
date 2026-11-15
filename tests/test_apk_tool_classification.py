#!/usr/bin/env python3
"""A normal tool exit code must not become a fabricated crash signal."""

import importlib.util
import signal
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/test-apk-tools.py"
spec = importlib.util.spec_from_file_location("apk_tool_probe", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ToolExitClassificationTests(unittest.TestCase):
    def test_normal_exit_139_is_not_sigsegv(self):
        result = probe.run_tool(["/bin/sh", "-c", "exit 139"], 2)
        self.assertEqual(result["rc"], 139)
        self.assertIsNone(result["signal"])

    def test_negative_return_code_is_a_real_signal(self):
        terminated = subprocess.CompletedProcess(["probe"], -signal.SIGSEGV, b"")
        with patch.object(probe.subprocess, "run", return_value=terminated):
            result = probe.run_tool(["probe"], 2)
        self.assertEqual(result["signal"], signal.SIGSEGV)


if __name__ == "__main__":
    unittest.main()
