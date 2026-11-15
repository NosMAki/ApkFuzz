"""Candidate capture keeps exact live bytes and enough evidence to audit them."""

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture-runtime-candidates.py"

spec = importlib.util.spec_from_file_location("candidate_capture", SCRIPT)
capture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture_module)


class QueueSelectionTest(unittest.TestCase):
    def test_seeded_sample_is_stable_and_spans_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "queue-index.tsv"
            with index.open("w", newline="") as target:
                writer = csv.DictWriter(target, fieldnames=["queue_entry"], delimiter="\t")
                writer.writeheader()
                for number in range(30):
                    writer.writerow({"queue_entry": f"id:{number:06},src:000000"})
            first = capture_module.queue_rows(index, set(), 5, 10407)
            second = capture_module.queue_rows(index, set(), 5, 10407)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 5)
            self.assertNotEqual(first, capture_module.queue_rows(index, set(), 5))


class CaptureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-capture-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.original = self.base / "original.apk"
        self.original.write_bytes(b"0123456789abcdef")
        self.live = self.base / "scratch" / "original_123_1.apk"
        self.live.parent.mkdir()
        self.live.write_bytes(b"012x456789abcdef")
        self.meta = Path(str(self.live) + ".meta")
        self.meta.write_text(f"origin {self.original}\ngen 1\n")
        self.patch = self.base / "patches" / (self.live.name + ".patch")
        self.patch.parent.mkdir()
        self.patch.write_text(
            f"# apkfuzz-patch v2\norigin {self.original}\nmode random-range\n"
            "seed 123\niter 1\ngen 1\nstatus ok\nedits 1\n3 33 78\n"
        )
        self.catalog = self.base / "corpus.csv"
        with self.catalog.open("w", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=["filename", "sha256"])
            writer.writeheader()
            writer.writerow({"filename": self.original.name,
                             "sha256": hashlib.sha256(self.original.read_bytes()).hexdigest()})
        self.mutator = self.base / "mutator.so"
        self.mutator.write_bytes(b"test mutator build")
        self.stats = self.base / "fuzzer_stats"
        self.stats.write_text("afl_version : ++4.09c\nexecs_done : 10\n")
        self.index = self.base / "queue-index.tsv"
        self.write_index()

    def write_index(self, patch=None, live=None):
        patch = self.patch if patch is None else patch
        live = self.live if live is None else live
        with self.index.open("w", newline="") as target:
            writer = csv.DictWriter(target, delimiter="\t",
                                    fieldnames=["queue_entry", "apk_path", "patch_path", "patch_exists"])
            writer.writeheader()
            writer.writerow({"queue_entry": "id:000000,orig:seed.txt", "apk_path": str(self.original),
                             "patch_path": "", "patch_exists": 0})
            writer.writerow({"queue_entry": "id:000001,src:000000,+cov", "apk_path": str(live),
                             "patch_path": str(patch) if patch else "", "patch_exists": int(bool(patch))})

    def capture(self):
        output = self.base / "captured"
        run = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--queue-index", str(self.index),
             "--corpus-csv", str(self.catalog), "--output-dir", str(output),
             "--mutator", str(self.mutator), "--fuzzer-stats", str(self.stats)],
            capture_output=True, text=True,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        manifest = json.loads((output / "manifest.json").read_text())
        return output, manifest, manifest["candidates"][0]

    def test_exact_live_apk_and_patch_evidence_are_preserved(self):
        output, manifest, item = self.capture()
        self.assertEqual(manifest["summary"]["selected"], 1)
        self.assertEqual(manifest["summary"]["new_queue_entries"], 1)
        self.assertEqual(manifest["summary"]["unselected"], 0)
        self.assertEqual(manifest["summary"]["provenance_verified"], 1)
        self.assertEqual(manifest["selection"]["method"], "queue_order")
        self.assertEqual(manifest["summary"]["research_ready"], 1)
        self.assertEqual(manifest["run"]["afl_version"], "++4.09c")
        self.assertEqual(manifest["run"]["mutator_sha256"],
                         hashlib.sha256(self.mutator.read_bytes()).hexdigest())
        self.assertEqual((output / manifest["run"]["stored_fuzzer_stats"]).read_bytes(),
                         self.stats.read_bytes())
        self.assertTrue(item["research_ready"])
        self.assertEqual(item["patch_reconstruction_match"], "match")
        self.assertEqual((output / item["stored_apk"]).read_bytes(), self.live.read_bytes())
        self.assertEqual(item["mutant_sha256"], hashlib.sha256(self.live.read_bytes()).hexdigest())
        self.assertEqual(len(item["patch_chain"]), 1)
        self.assertEqual((output / item["patch_chain"][0]["path"]).read_bytes(), self.patch.read_bytes())
        self.assertEqual((output / "queue-index.tsv").read_bytes(), self.index.read_bytes())

    def test_live_patch_mismatch_is_retained_but_not_research_ready(self):
        self.live.write_bytes(b"012xZ56789abcdef")
        output, _, item = self.capture()
        self.assertTrue(item["preserved"])
        self.assertFalse(item["research_ready"])
        self.assertEqual(item["patch_reconstruction_match"], "mismatch")
        self.assertIn("patch_live_mismatch", item["reasons"])
        self.assertEqual((output / item["stored_apk"]).read_bytes(), self.live.read_bytes())

    def test_missing_live_apk_is_not_reconstructed_as_exact(self):
        self.live.unlink()
        _, manifest, item = self.capture()
        self.assertFalse(item["preserved"])
        self.assertIsNone(item["stored_apk"])
        self.assertIn("live_apk_missing", item["reasons"])
        self.assertEqual(manifest["summary"]["preserved"], 0)

    def test_missing_patch_keeps_live_bytes_with_incomplete_provenance(self):
        self.write_index(patch="")
        output, _, item = self.capture()
        self.assertTrue(item["preserved"])
        self.assertFalse(item["research_ready"])
        self.assertIn("patch_missing", item["reasons"])
        self.assertEqual(item["origin_sha256"], hashlib.sha256(self.original.read_bytes()).hexdigest())
        self.assertEqual((output / item["stored_apk"]).read_bytes(), self.live.read_bytes())

    def test_parent_chain_is_copied_and_reconstructs(self):
        parent = self.patch.parent / "original_123_0.apk.patch"
        parent.write_text(
            f"# apkfuzz-patch v2\norigin {self.original}\nmode random-range\n"
            "seed 123\niter 0\ngen 1\nstatus ok\nedits 1\n2 32 79\n"
        )
        self.patch.write_text(
            f"# apkfuzz-patch v2\norigin {self.original}\nparent {parent.name}\n"
            "mode random-range\nseed 123\niter 1\ngen 2\nstatus ok\nedits 1\n3 33 78\n"
        )
        self.live.write_bytes(b"01yx456789abcdef")
        self.meta.write_text(f"origin {self.original}\ngen 2\n")
        output, _, item = self.capture()
        self.assertTrue(item["research_ready"])
        self.assertEqual(item["patch_reconstruction_match"], "match")
        self.assertEqual(len(item["patch_chain"]), 2)
        for evidence in item["patch_chain"]:
            self.assertTrue((output / evidence["path"]).is_file())

    def test_preflight_uses_captured_apk_and_detects_later_tampering(self):
        output, _, item = self.capture()

        def preflight_report(name):
            path = self.base / name
            run = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts/inspect-runtime-candidates.py"),
                 "--capture-manifest", str(output / "manifest.json"),
                 "--corpus-csv", str(self.catalog), "--aapt", "/nonexistent/aapt",
                 "--apksigner", "/nonexistent/apksigner", "--output", str(path)],
                capture_output=True, text=True,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            return json.loads(path.read_text())["candidates"][0]

        first = preflight_report("preflight-first.json")
        self.assertEqual(first["live_apk_match"], "match")
        self.assertEqual(first["capture_integrity"], "match")
        stored = output / item["stored_apk"]
        stored.write_bytes(b"tampered")
        second = preflight_report("preflight-second.json")
        self.assertEqual(second["capture_integrity"], "mismatch")
        self.assertIn("capture_hash_mismatch", second["reasons"])

    def test_preflight_detects_changed_patch_metadata(self):
        output, _, item = self.capture()
        patch_path = output / item["patch_chain"][0]["path"]
        patch_path.write_text(patch_path.read_text().replace("mode random-range", "mode crc-fields"))
        report_path = self.base / "preflight-patch.json"
        run = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/inspect-runtime-candidates.py"),
             "--capture-manifest", str(output / "manifest.json"),
             "--corpus-csv", str(self.catalog), "--output", str(report_path)],
            capture_output=True, text=True,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        result = json.loads(report_path.read_text())["candidates"][0]
        self.assertEqual(result["live_apk_match"], "match")
        self.assertIn("captured_patch_hash_mismatch", result["reasons"])

    def test_existing_output_directory_is_not_overwritten(self):
        output = self.base / "captured"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("keep")
        run = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--queue-index", str(self.index),
             "--corpus-csv", str(self.catalog), "--output-dir", str(output)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
