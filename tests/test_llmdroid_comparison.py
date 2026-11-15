"""Conservative classification of paired replay outcomes."""

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare-llmdroid-runs.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("llmdroid_compare", SCRIPT)
compare_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare_module)


class ComparisonTest(unittest.TestCase):
    def run_report(self, role, status="completed", steps=None):
        return {"schema_version": 1, "role": role, "status": status,
                "trace_sha256": "a" * 64, "apk_sha256": "b" * 64,
                "steps": steps if steps is not None else [
                    {"index": 0, "status": "ok", "activity": "app.Main",
                     "ui_structure": "same"}]}

    def test_identical_completed_runs_are_negative_control(self):
        result = compare_module.compare(self.run_report("baseline"),
                                        self.run_report("mutant"))
        self.assertEqual(result["status"], "no_divergence_observed")

    def test_equal_partial_runs_are_inconclusive(self):
        result = compare_module.compare(self.run_report("baseline", "inconclusive"),
                                        self.run_report("mutant", "inconclusive"))
        self.assertEqual((result["status"], result["classification"]),
                         ("inconclusive", "incomplete_execution"))

    def test_concrete_crash_is_candidate_not_confirmed(self):
        mutant = self.run_report("mutant", "inconclusive", [
            {"index": 0, "status": "crash", "activity": "app.Main",
             "ui_structure": "same"}])
        mutant["apk_sha256"] = "c" * 64
        result = compare_module.compare(self.run_report("baseline"), mutant)
        self.assertEqual(result["classification"], "crash_candidate")
        self.assertFalse(result["confirmed_defect"])

    def test_identical_apk_ui_difference_is_control_failure(self):
        mutant = self.run_report("mutant", "inconclusive", [
            {"index": 0, "status": "ok", "activity": "app.Main",
             "ui_structure": "dynamic"}])
        result = compare_module.compare(self.run_report("baseline"), mutant)
        self.assertEqual((result["status"], result["classification"]),
                         ("inconclusive", "identical_apk_divergence"))

    def test_incomplete_ui_difference_is_inconclusive(self):
        mutant = self.run_report("mutant", "inconclusive", [
            {"index": 0, "status": "ok", "activity": "app.Main",
             "ui_structure": "dynamic"}])
        mutant["apk_sha256"] = "c" * 64
        result = compare_module.compare(self.run_report("baseline"), mutant)
        self.assertEqual((result["status"], result["classification"]),
                         ("inconclusive", "incomplete_execution"))

    def test_identical_apk_infrastructure_failure_keeps_its_reason(self):
        mutant = self.run_report("mutant", "inconclusive", [
            {"index": 0, "status": "infrastructure_error"}])
        result = compare_module.compare(self.run_report("baseline"), mutant)
        self.assertEqual((result["status"], result["classification"]),
                         ("inconclusive", "inconclusive"))

    def test_watchdog_does_not_create_defect(self):
        mutant = self.run_report("mutant", "watchdog_timeout", [])
        result = compare_module.compare(self.run_report("baseline"), mutant)
        self.assertEqual((result["status"], result["classification"]),
                         ("inconclusive", "infrastructure_failure"))


if __name__ == "__main__":
    unittest.main()
