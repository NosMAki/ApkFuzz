"""Focused checks for sampling completed live mutator output bytes."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sample-live-mutations.py"
SPEC = importlib.util.spec_from_file_location("sample_live_mutations", SCRIPT)
SAMPLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAMPLE)


class LiveMutationSampleTest(unittest.TestCase):
    def test_captures_exact_bytes_with_patch_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch = root / "apkfuzz-scratch-test"
            patches = root / "patches"
            scratch.mkdir()
            patches.mkdir()
            apk = scratch / "F-Droid_1_1.apk"
            apk.write_bytes(b"exact mutant bytes")
            (patches / (apk.name + ".patch")).write_bytes(b"patch evidence")
            log = root / "mutator.log"
            log.write_text(f"seed=1 iter=1 gen=1 status=ok out={apk}\n")
            stop = root / "stop"
            stop.touch()
            output = root / "capture"
            args = SimpleNamespace(log=log, patch_dir=patches, output=output,
                                   stop_file=stop, scratch_base=root, seed=42,
                                   gen1_rate=1, gen1_first=1, descendant_rate=1, max_seconds=2,
                                   max_capture_bytes=1000000)
            summary = SAMPLE.run(args)
            row = json.loads((output / "captures.jsonl").read_text())
            self.assertEqual(summary["counts"]["captured"], 1)
            self.assertEqual(Path(row["stored_apk"]).read_bytes(), b"exact mutant bytes")
            self.assertEqual(row["mutant_sha256"], SAMPLE.sha256_file(apk))
            self.assertEqual(row["patch_sha256"],
                             SAMPLE.sha256_file(patches / (apk.name + ".patch")))
            self.assertEqual(row["selection_method"], "first_gen_prefix")

    def test_first_generation_prefix_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch = root / "apkfuzz-scratch-test"
            patches = root / "patches"
            scratch.mkdir()
            patches.mkdir()
            lines = []
            for iteration in range(1, 4):
                apk = scratch / f"F-Droid_1_{iteration}.apk"
                apk.write_bytes(f"mutant {iteration}".encode())
                (patches / (apk.name + ".patch")).write_bytes(b"patch")
                lines.append(f"seed=1 iter={iteration} gen=1 status=ok out={apk}\n")
            log = root / "mutator.log"
            log.write_text("".join(lines))
            stop = root / "stop"
            stop.touch()
            output = root / "capture"
            args = SimpleNamespace(log=log, patch_dir=patches, output=output,
                                   stop_file=stop, scratch_base=root, seed=42,
                                   gen1_rate=1 << 64, gen1_first=2,
                                   descendant_rate=1 << 64, max_seconds=2,
                                   max_capture_bytes=1000000)
            summary = SAMPLE.run(args)
            rows = [json.loads(line) for line in
                    (output / "captures.jsonl").read_text().splitlines()]
            self.assertEqual(summary["counts"]["targeted_gen1_selected"], 2)
            self.assertEqual([row["iteration"] for row in rows], [1, 2])
            self.assertTrue(all(row["status"] == "captured" and
                                row["selection_method"] == "first_gen_prefix"
                                for row in rows))

    def test_rejects_path_outside_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patches = root / "patches"
            output = root / "capture"
            patches.mkdir()
            output.mkdir()
            apk = root / "other.apk"
            apk.write_bytes(b"bytes")
            (patches / "other.apk.patch").write_bytes(b"patch")
            with self.assertRaises(ValueError):
                SAMPLE.capture({"out": str(apk), "iter": 1, "gen": 1},
                               output, root, patches)


if __name__ == "__main__":
    unittest.main()
