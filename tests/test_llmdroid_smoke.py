#!/usr/bin/env python3
"""A returned guided run cannot claim a full action budget it did not reach."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/run-llmdroid-smoke.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("llmdroid_smoke", SOURCE)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeBudgetTests(unittest.TestCase):
    def test_guided_run_with_three_of_twelve_actions_is_partial(self):
        self.assertEqual(smoke.classify_event_budget("guided", 12, 3), "partial")

    def test_guided_run_at_limit_and_offline_run_complete(self):
        self.assertEqual(smoke.classify_event_budget("guided", 12, 12), "completed")
        self.assertEqual(smoke.classify_event_budget("offline", 0, 0), "completed")

    def test_partial_worker_returns_nonzero_to_callers(self):
        argv = ["smoke", "--checkout", "unused", "--apk", "unused",
                "--serial", "unused", "--output-dir", "unused", "--worker"]
        with patch.object(sys, "argv", argv), patch.object(
                smoke, "run", return_value={"status": "partial"}):
            self.assertEqual(smoke.main(), 3)

    def test_upstream_event_error_is_detected_without_copying_log_content(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "runtime.log"
            log.write_text("WARNING | exception during sending events: secret\n",
                           encoding="utf-8")
            self.assertEqual(smoke.upstream_event_errors(log), [
                {"line": 1, "kind": "event_generation_exception"}])
            self.assertNotIn("secret", str(smoke.upstream_event_errors(log)))
            self.assertEqual(smoke.upstream_event_errors(log.with_name("missing")), [])

    def test_upstream_error_overrides_full_event_budget(self):
        errors = [{"line": 4, "kind": "event_generation_exception"}]
        self.assertEqual(smoke.classify_returned_run("guided", 12, 12, errors),
                         ("inconclusive", "upstream_event_generation_error", "completed"))
        self.assertEqual(smoke.classify_returned_run("guided", 12, 3, errors),
                         ("inconclusive", "upstream_event_generation_error", "partial"))


if __name__ == "__main__":
    unittest.main()
