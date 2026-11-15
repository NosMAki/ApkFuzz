"""Stage denominators never turn absent runtime evidence into zero findings."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/report-run-stages.py"
spec = importlib.util.spec_from_file_location("run_stages", SCRIPT)
stages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stages)


class RunStagesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.arm = Path(self.temp.name)
        (self.arm / "config.txt").write_text(
            "crash_reporter_pipe=1\nmissing_crashes_override=1\n")
        (self.arm / "afl/default").mkdir(parents=True)
        (self.arm / "afl/candidates").mkdir()
        (self.arm / "afl/default/fuzzer_stats").write_text(
            "execs_done : 100\ncorpus_count : 5\nsaved_crashes : 0\nsaved_hangs : 0\n")
        self.write("afl/candidates/manifest.json", {
            "schema_version": 1, "summary": {"new_queue_entries": 4, "selected": 1,
                                           "preserved": 1, "research_ready": 1},
            "selection": {"limit": 1, "method": "seeded_random_sample"}})
        self.write("candidate-preflight.json", {
            "schema_version": 1, "summary": {"candidates": 1, "reconstructed_only": 0,
                "zip": {"valid": 0, "checked": 1, "statuses": {"bad_entry": 1}},
                "manifest": {"valid": 0, "checked": 0, "statuses": {"not_checked": 1}},
                "signature": {"valid": 0, "checked": 0, "statuses": {"unavailable": 1}},
                "eligible_for_install_attempt": 0}})

    def write(self, name, value):
        path = self.arm / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def test_unmeasured_android_is_null_and_unselected_queue_is_not_invalid(self):
        report = stages.summarize(self.arm)
        self.assertEqual(report["afl_harness"]["execs_done"], 100)
        self.assertEqual(report["afl_harness"]["crash_reporter_pipe"], "1")
        self.assertEqual(report["capture"]["unselected"], 3)
        self.assertEqual(report["capture"]["provenance_verified"], 1)
        self.assertEqual(report["offline_preflight"]["zip"]["valid"], 0)
        self.assertIsNone(report["android_device"])
        self.assertIsNone(report["matched_pairs"])
        self.assertIsNone(report["manually_confirmed_application_defects"])

    def test_runtime_artifacts_keep_exact_and_prepared_denominators_separate(self):
        exact = self.write("exact-probe.json", {"schema_version": 1,
            "source_kind": "exact_mutant", "device_probe": None})
        prepared = self.write("prepared-probe.json", {"schema_version": 1,
            "source_kind": "prepared_mutant", "device_probe": {
                "install": {"status": "ok", "stdout": "Success"},
                "launch": {"status": "ok"}, "classification": "launched_process_running"}})
        base_run = self.write("base-replay.json", {"schema_version": 1, "status": "completed"})
        mutant_run = self.write("mutant-replay.json", {"schema_version": 1, "status": "completed"})
        pair = self.write("pair.json", {"schema_version": 1, "status": "no_divergence_observed",
            "runs": {"baseline": {"exit_code": 0, "report": str(base_run)},
                     "mutant": {"exit_code": 0, "report": str(mutant_run)}}})
        analysis = self.write("analysis.json", {"schema_version": 1,
            "findings": [{"status": "reproduced_candidate"}]})
        report = stages.summarize(self.arm, [exact, prepared], [pair], [analysis])
        self.assertEqual(report["android_device"]["exact_mutant"]["install_attempts"], 0)
        self.assertEqual(report["android_device"]["prepared_mutant"]["install_successes"], 1)
        self.assertEqual(report["matched_pairs"]["completed_matched_pairs"], 1)
        self.assertEqual(report["analysis"]["reproduced_candidates"], 1)

    def test_capture_preflight_mismatch_is_rejected(self):
        path = self.arm / "candidate-preflight.json"
        data = json.loads(path.read_text())
        data["summary"]["candidates"] = 2
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "denominator mismatch"):
            stages.summarize(self.arm)

    def test_selected_cannot_exceed_new_queue_entries(self):
        path = self.arm / "afl/candidates/manifest.json"
        data = json.loads(path.read_text())
        data["summary"]["new_queue_entries"] = 0
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "new queue denominator"):
            stages.summarize(self.arm)


if __name__ == "__main__":
    unittest.main()
