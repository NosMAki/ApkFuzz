"""Queue admission requires retained exact bytes and a matching source trace."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/llmdroid-analysis-queue.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("llmdroid_queue", SCRIPT)
queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue)


class QueueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture_dir = self.root / "capture"
        self.capture_dir.mkdir()
        self.exact = self.capture_dir / "exact.apk"
        self.exact.write_bytes(b"exact")
        self.origin = self.root / "origin.apk"
        self.origin.write_bytes(b"original")
        self.baseline = self.root / "prepared-baseline.apk"
        self.baseline.write_bytes(b"baseline")
        self.mutant = self.root / "prepared-signed.apk"
        self.mutant.write_bytes(b"mutant")
        self.capture = self.capture_dir / "manifest.json"
        self.capture.write_text(json.dumps({"schema_version": 1, "candidates": [{
            "queue_entry": "id:1", "mutant_sha256": queue.digest(self.exact),
            "stored_apk": "exact.apk", "research_ready": True,
            "origin_path": str(self.origin), "origin_sha256": queue.digest(self.origin)}]}))
        self.preflight = self.root / "preflight.json"
        self.preflight.write_text(json.dumps({"schema_version": 1, "candidates": [{
            "mutant_sha256": queue.digest(self.exact),
            "origin_sha256": queue.digest(self.origin), "preflight": "blocked"}]}))
        self.prepared = self.root / "preparation.json"
        self.prepared.write_text(json.dumps({
            "schema_version": 1, "status": "ready_for_install_attempt",
            "exact_mutant_sha256": queue.digest(self.exact),
            "origin_sha256": queue.digest(self.origin),
            "prepared_baseline_path": str(self.baseline),
            "prepared_baseline_sha256": queue.digest(self.baseline),
            "prepared_apk_path": str(self.mutant),
            "prepared_apk_sha256": queue.digest(self.mutant)}))
        self.trace = self.root / "trace.json"
        self.trace.write_text(json.dumps({"schema_version": 1,
                                          "source_apk_sha256": queue.digest(self.baseline)}))
        self.device = self.root / "device-probe.json"
        self.write_device("launched_process_running")
        self.enqueued = self.root / "queue.json"
        queue.write_new(self.enqueued, queue.enqueue(self.capture))

    def write_device(self, classification, **changes):
        report = {"launch_gate_version": 3, "source_kind": "prepared_mutant",
                  "tested_apk_sha256": queue.digest(self.mutant),
                  "baseline_apk_sha256": queue.digest(self.baseline),
                  "classification": classification,
                  "expected_activity": "org.example/.Main",
                  "device_probe": {"resolved_activity": "org.example/.Main"}}
        report.update(changes)
        self.device.write_text(json.dumps(report))

    def plan(self, device=True):
        return queue.plan(self.enqueued, self.preflight, self.trace, [self.prepared],
                          [self.device] if device else [])

    def test_prepared_pair_becomes_ready(self):
        planned = self.plan()
        self.assertEqual(planned["summary"], {"ready": 1, "blocked": 0})
        self.assertEqual(planned["items"][0]["artifact_kind"], "prepared_pair")

    def test_offline_ready_pair_without_device_launch_is_blocked(self):
        planned = self.plan(device=False)
        self.assertEqual(planned["summary"], {"ready": 0, "blocked": 1})
        self.assertEqual(planned["items"][0]["reasons"], ["device_launch_gate_missing"])

    def test_failed_or_unversioned_device_launch_is_blocked(self):
        for changes in ({"classification": "launched_crashed"},
                        {"classification": "install_failed"},
                        {"launch_gate_version": None},
                        {"expected_activity": None},
                        {"baseline_apk_sha256": "0" * 64},
                        {"device_probe": {"resolved_activity": "org.example/.Crash"}}):
            self.write_device(**{"classification": "launched_process_running", **changes})
            planned = self.plan()
            self.assertEqual(planned["items"][0]["reasons"],
                             ["device_launch_gate_failed"], changes)

    def test_changed_exact_bytes_are_blocked(self):
        self.exact.write_bytes(b"changed")
        planned = queue.plan(self.enqueued, self.preflight, self.trace, [self.prepared])
        self.assertIn("exact_mutant_missing_or_hash_mismatch",
                      planned["items"][0]["reasons"])

    def test_trace_source_mismatch_is_blocked(self):
        self.trace.write_text(json.dumps({"schema_version": 1,
                                          "source_apk_sha256": "0" * 64}))
        planned = queue.plan(self.enqueued, self.preflight, self.trace, [self.prepared])
        self.assertIn("trace_source_mismatch", planned["items"][0]["reasons"])

    def test_duplicate_queue_entries_share_one_candidate(self):
        capture = json.loads(self.capture.read_text())
        duplicate = dict(capture["candidates"][0], queue_entry="id:2")
        capture["candidates"].append(duplicate)
        self.capture.write_text(json.dumps(capture))
        enqueued = queue.enqueue(self.capture)
        self.assertEqual(len(enqueued["items"]), 1)
        self.assertEqual(enqueued["items"][0]["queue_entries"], ["id:1", "id:2"])

    def test_prepared_pair_must_match_original_identity(self):
        prepared = json.loads(self.prepared.read_text())
        prepared["origin_sha256"] = "0" * 64
        self.prepared.write_text(json.dumps(prepared))
        planned = queue.plan(self.enqueued, self.preflight, self.trace, [self.prepared])
        self.assertEqual(planned["items"][0]["status"], "blocked")
        self.assertIn("runtime_preparation_required", planned["items"][0]["reasons"])

    def test_two_clean_runs_report_no_divergence(self):
        runs = [{"status": "no_divergence_observed"},
                {"status": "no_divergence_observed"}]
        self.assertEqual(queue.summarize_runs(runs, 2)["status"],
                         "no_divergence_observed")
        runs[1] = {"status": "inconclusive"}
        self.assertEqual(queue.summarize_runs(runs, 2)["status"], "inconclusive")

    def test_pair_timeout_is_recorded_as_inconclusive(self):
        planned = self.plan()
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps(planned))
        with patch.object(queue.subprocess, "run", side_effect=subprocess.TimeoutExpired("pair", 600)):
            report = queue.process(plan_path, self.root, "emulator-test",
                                   self.root / "analysis", 2)
        self.assertEqual(report["findings"][0]["status"], "inconclusive")
        self.assertEqual([run["reason"] for run in report["findings"][0]["runs"]],
                         ["pair_timeout", "pair_timeout"])

    def test_crash_fingerprint_groups_same_fault_but_separates_fault_classes(self):
        log = self.root / "crash.log"
        def finding():
            return {"first_divergence": {"mutant": {"status": "crash",
                                                    "logcat": str(log)}}}
        def write_crash(pid, error, line):
            log.write_text(
                f"10-21 E AndroidRuntime: FATAL EXCEPTION: main\n"
                f"10-21 E AndroidRuntime: Process: org.example.app, PID: {pid}\n"
                f"10-21 E AndroidRuntime: java.lang.{error}: varied message\n"
                f"10-21 E AndroidRuntime: \tat org.example.app.Main.save(Main.java:{line})\n")
        write_crash(100, "IllegalStateException", 18)
        first = queue.crash_fingerprint(finding())
        self.assertIsNotNone(first)
        write_crash(200, "IllegalStateException", 19)
        self.assertEqual(queue.crash_fingerprint(finding()), first)
        write_crash(200, "NullPointerException", 19)
        self.assertNotEqual(queue.crash_fingerprint(finding()), first)
        log.unlink()
        self.assertIsNone(queue.crash_fingerprint(finding()))


if __name__ == "__main__":
    unittest.main()
