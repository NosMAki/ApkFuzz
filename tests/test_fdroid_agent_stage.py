"""The agent stage must report missing runtime pairs without pretending to run a model."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / "scripts/run-fdroid-agent-stage.py"
spec = importlib.util.spec_from_file_location("fdroid_agent_stage", SOURCE)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class AgentStageGateTests(unittest.TestCase):
    def test_no_eligible_pair_is_recorded_without_agent_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.apk"
            trace = root / "trace.json"
            baseline.write_bytes(b"baseline")
            trace.write_text("{}")
            args = SimpleNamespace(output_dir=root / "stage", arm_dir=root,
                                   trace=trace, baseline_apk=baseline, serial=None)
            plan = {"summary": {"ready": 0, "blocked": 2}, "items": []}
            self.assertEqual(stage.run_stage(args, plan), 4)
            report = json.loads((args.output_dir / "agent-stage-report.json").read_text())
            self.assertEqual(report["status"], "blocked_no_runtime_eligible_pair")
            self.assertEqual(report["guided_runs"], [])
            self.assertFalse((args.output_dir / "paired-replay").exists())


if __name__ == "__main__":
    unittest.main()
