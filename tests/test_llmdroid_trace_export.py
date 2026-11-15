"""Verify the LLMDroid event bridge records complete, ordered actions."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/export-llmdroid-trace.py"
spec = importlib.util.spec_from_file_location("apkfuzz_llmdroid_trace", SCRIPT)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


class TraceExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-trace-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.apk = self.base / "test.apk"
        self.apk.write_bytes(b"test APK bytes")
        (self.base / "events").mkdir()

    def event(self, name, event_type="touch", start="s1", stop="s2"):
        path = self.base / "events" / name
        path.write_text(json.dumps({"tag": name, "event": {"event_type": event_type},
                                    "start_state": start, "stop_state": stop,
                                    "event_str": event_type}))
        return path

    def test_export_orders_and_preserves_exact_event_payload(self):
        later = self.event("event_2026-10-21_120002.json", "key", "s2", "s3")
        first = self.event("event_2026-10-21_120001.json")
        result = trace.export(self.base, self.apk)
        self.assertEqual(result["action_count"], 2)
        self.assertEqual([item["event_type"] for item in result["actions"]], ["touch", "key"])
        self.assertEqual(result["actions"][0]["source_sha256"], trace.digest(first))
        self.assertEqual(result["actions"][1]["source_sha256"], trace.digest(later))
        self.assertEqual(result["source_apk_sha256"], trace.digest(self.apk))

    def test_missing_state_is_rejected(self):
        self.event("event_1.json", stop="")
        with self.assertRaisesRegex(ValueError, "stop_state missing"):
            trace.export(self.base, self.apk)

    def test_no_events_is_not_a_complete_trace(self):
        with self.assertRaisesRegex(ValueError, "no LLMDroid action events"):
            trace.export(self.base, self.apk)


if __name__ == "__main__":
    unittest.main()
