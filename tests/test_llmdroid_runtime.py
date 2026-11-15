"""Controlled examples for conservative UI matching and first divergence."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import llmdroid_runtime as runtime


class ViewMatchingTest(unittest.TestCase):
    def test_lifecycle_prefix_does_not_prelaunch_app(self):
        self.assertFalse(runtime.needs_initial_app_launch("kill_app"))
        self.assertFalse(runtime.needs_initial_app_launch("intent"))
        self.assertTrue(runtime.needs_initial_app_launch("touch"))

    def test_unique_resource_and_class_survives_changed_view_hash(self):
        recorded = {"view_str": "old", "resource_id": "app:id/save",
                    "class": "android.widget.Button", "text": "Save"}
        current = [{"view_str": "new", "resource_id": "app:id/save",
                    "class": "android.widget.Button", "text": "Save", "bounds": [[1, 2], [9, 10]]}]
        match = runtime.match_view(recorded, current)
        self.assertEqual(match.method, "resource_id_and_class")
        self.assertIs(match.view, current[0])

    def test_ambiguous_target_is_rejected(self):
        recorded = {"resource_id": "app:id/item", "class": "android.widget.Button"}
        current = [dict(recorded), dict(recorded)]
        with self.assertRaisesRegex(runtime.SynchronizationError, "ambiguous"):
            runtime.match_view(recorded, current)

    def test_unstable_coordinates_are_not_used_for_matching(self):
        with self.assertRaisesRegex(runtime.SynchronizationError, "stable identifier"):
            runtime.match_view({"bounds": [[0, 0], [10, 10]]}, [])

    def test_retarget_ignores_recorded_coordinates(self):
        view = {"view_str": "current", "resource_id": "app:id/save",
                "class": "android.widget.Button", "bounds": [[20, 30], [70, 80]]}
        payload, methods = runtime.retarget_event(
            {"event_type": "touch", "view": {"view_str": "old",
             "resource_id": "app:id/save", "class": "android.widget.Button"},
             "x": 999, "y": 999}, [view], "app.example")
        self.assertEqual((payload["x"], payload["y"]), (None, None))
        self.assertEqual(payload["view"]["bounds"], view["bounds"])
        self.assertEqual(methods["view"], "resource_id_and_class")

    def test_foreign_intent_is_rejected(self):
        with self.assertRaisesRegex(runtime.SynchronizationError, "foreign intent"):
            runtime.retarget_event(
                {"event_type": "intent", "intent": "am force-stop other.app"},
                [], "app.example")

    def test_recorded_kill_app_becomes_package_scoped_force_stop(self):
        payload, method = runtime.retarget_event(
            {"event_type": "kill_app", "stop_intent": "am force-stop app.example"},
            [], "app.example")
        self.assertEqual(payload, {"event_type": "intent",
                                   "intent": "am force-stop app.example"})
        self.assertEqual(method, {"normalized_from": "kill_app"})
        with self.assertRaisesRegex(runtime.SynchronizationError, "foreign kill-app"):
            runtime.retarget_event(
                {"event_type": "kill_app", "stop_intent": "am force-stop other.app"},
                [], "app.example")

    def test_coordinate_only_event_is_rejected(self):
        with self.assertRaises(runtime.SynchronizationError):
            runtime.retarget_event(
                {"event_type": "touch", "x": 20, "y": 30}, [], "app.example")


class OutcomeComparisonTest(unittest.TestCase):
    def step(self, index, **changes):
        result = {"index": index, "status": "ok", "activity": "App.Main",
                  "ui_structure": "same"}
        result.update(changes)
        return result

    def test_identical_control_has_no_divergence(self):
        steps = [self.step(0), self.step(1)]
        self.assertIsNone(runtime.first_divergence(steps, steps))

    def test_known_crash_is_first_divergence(self):
        baseline = [self.step(0), self.step(1), self.step(2)]
        mutant = [self.step(0), self.step(1, status="crash"), self.step(2)]
        result = runtime.first_divergence(baseline, mutant)
        self.assertEqual((result["index"], result["classification"]),
                         (1, "crash_candidate"))

    def test_infrastructure_failure_is_inconclusive(self):
        result = runtime.first_divergence([self.step(0)],
                                          [self.step(0, status="infrastructure_error")])
        self.assertEqual(result["classification"], "inconclusive")

    def test_missing_actions_are_inconclusive(self):
        result = runtime.first_divergence([self.step(0)], [])
        self.assertEqual(result["classification"], "inconclusive_missing_actions")


if __name__ == "__main__":
    unittest.main()
