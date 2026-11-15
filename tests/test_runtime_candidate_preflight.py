"""Focused tests for patch provenance and runtime preflight classification."""

import csv
import hashlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parent.parent / "scripts/inspect-runtime-candidates.py"
spec = importlib.util.spec_from_file_location("runtime_candidates", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class CandidatePreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-preflight-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
            archive.writestr("classes.dex", b"classespayload" * 30)
            archive.comment = b"A"
        self.original = self.root / "test.apk"
        self.original.write_bytes(out.getvalue())
        self.original_hash = preflight.sha256_file(self.original)
        self.catalog = self.root / "corpus.csv"
        with self.catalog.open("w", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=["filename", "sha256"])
            writer.writeheader()
            writer.writerow({"filename": "test.apk", "sha256": self.original_hash})
        # ZIP comments are outside entry CRCs, making this a parseable mutant.
        source = self.original.read_bytes()
        self.offset = len(source) - 1
        self.mutant = source[:-1] + b"B"
        self.patch = self.root / "test_123_1.apk.patch"
        self.patch.write_text(
            f"# apkfuzz-patch v2\norigin {self.original}\nmode random-range\n"
            f"seed 123\niter 1\ngen 1\nstatus ok\nedits 1\n"
            f"{self.offset} {source[-1]:02x} 42\n"
        )
        self.item = {"patch": str(self.patch), "queue_refs": [], "live_apk_paths": []}

    def test_verified_reconstruction_and_zip_preflight(self):
        result = preflight.inspect_candidate(
            self.item, preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertEqual(result["origin_sha256"], self.original_hash)
        self.assertEqual(result["mutant_sha256"], hashlib.sha256(self.mutant).hexdigest())
        self.assertEqual(result["zip"]["status"], "valid")
        self.assertEqual(result["signature"]["status"], "unavailable")
        self.assertEqual(result["preflight"], "blocked")
        self.assertEqual(preflight.stage_summary([result], "zip")["valid"], 1)
        self.assertEqual(preflight.stage_summary([result], "manifest")["checked"], 0)
        self.assertEqual(preflight.stage_summary([result], "signature")["checked"], 0)

    def test_zip_decompression_error_is_classified(self):
        with patch.object(zipfile.ZipFile, "testzip", side_effect=zlib.error("damaged compressed data")):
            result = preflight.zip_check(self.original)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("error", result["detail"])

    def test_aapt_malformed_xml_warning_is_invalid_even_on_exit_zero(self):
        result = subprocess.CompletedProcess(
            ["aapt", "dump", "badging", "candidate.apk"], 0,
            stdout="package: name='example'\n",
            stderr="Bad XML block: node attributes exceed block\n")
        with patch.object(preflight.subprocess, "run", return_value=result):
            checked = preflight.probe(result.args, 2)
        self.assertEqual(checked["status"], "invalid")
        self.assertEqual(checked["exit_code"], 0)

    def test_any_aapt_resource_parser_warning_is_invalid_on_exit_zero(self):
        warning = ("ResourceType W 11-15 10:52:46 679366 679366] Bad string block: "
                   "string #247 entry is at 2301952, past end at 17516\n")
        self.assertTrue(preflight.aapt_resource_warning(warning))
        self.assertTrue(preflight.aapt_resource_warning("W/ResourceType( 1): bad\n"))
        self.assertFalse(preflight.aapt_resource_warning(
            "package: name='org.example.ResourceType'\n"))
        self.assertFalse(preflight.aapt_resource_warning(""))
        result = subprocess.CompletedProcess(
            ["aapt", "dump", "badging", "candidate.apk"], 0,
            stdout="package: name='example'\n", stderr=warning)
        with patch.object(preflight.subprocess, "run", return_value=result):
            self.assertEqual(preflight.probe(result.args, 2)["status"], "invalid")

    def test_changed_original_outside_edited_offset_is_rejected(self):
        contents = bytearray(self.original.read_bytes())
        contents[40] ^= 1
        self.original.write_bytes(contents)
        result = preflight.inspect_candidate(
            self.item, preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertIn("origin_hash_mismatch", result["reasons"])
        self.assertIsNone(result["mutant_sha256"])

    def test_missing_parent_is_rejected(self):
        self.patch.write_text(self.patch.read_text().replace(
            "mode random-range", "parent absent.apk.patch\nmode random-range").replace(
            "gen 1", "gen 2"))
        result = preflight.inspect_candidate(
            self.item, preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertIn("reconstruction_failed", result["reasons"])

    def test_live_apk_mismatch_is_reported(self):
        live = self.root / "live.apk"
        live.write_bytes(self.original.read_bytes())
        self.item["live_apk_paths"] = [str(live)]
        result = preflight.inspect_candidate(
            self.item, preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertEqual(result["live_apk_match"], "mismatch")
        self.assertIn("live_apk_mismatch", result["reasons"])

    def test_patch_at_edit_capacity_requires_live_apk_comparison(self):
        original = self.original.read_bytes()
        edit_lines = [f"{off} {original[off]:02x} {original[off] ^ 1:02x}"
                      for off in range(preflight.V2_EDIT_CAPACITY)]
        self.patch.write_text(
            f"# apkfuzz-patch v2\norigin {self.original}\nmode random-range\n"
            f"seed 123\niter 1\ngen 1\nstatus ok\nedits {len(edit_lines)}\n"
            + "\n".join(edit_lines) + "\n"
        )
        result = preflight.inspect_candidate(
            self.item, preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertIn("edit_capacity_reached_unverified", result["reasons"])
        self.assertEqual(result["edit_count"], preflight.V2_EDIT_CAPACITY)
        self.assertEqual(result["preflight"], "blocked")

    def test_queue_index_skips_original_seed_and_links_mutant(self):
        index = self.root / "queue-index.tsv"
        with index.open("w", newline="") as target:
            writer = csv.DictWriter(target, delimiter="\t",
                                    fieldnames=["queue_entry", "apk_path", "patch_path", "patch_exists"])
            writer.writeheader()
            writer.writerow({"queue_entry": "id:000000,orig:test.txt", "apk_path": str(self.original),
                             "patch_path": "", "patch_exists": 0})
            writer.writerow({"queue_entry": "id:000001,src:000000", "apk_path": str(self.root / "missing.apk"),
                             "patch_path": str(self.patch), "patch_exists": 1})
        selected = preflight.candidates_from_inputs([], [index])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["patch"], str(self.patch))
        self.assertEqual(len(selected[0]["queue_refs"]), 1)

    def test_queue_mutant_without_patch_is_blocked(self):
        index = self.root / "queue-index.tsv"
        with index.open("w", newline="") as target:
            writer = csv.DictWriter(target, delimiter="\t",
                                    fieldnames=["queue_entry", "apk_path", "patch_path", "patch_exists"])
            writer.writeheader()
            writer.writerow({"queue_entry": "id:000001,src:000000", "apk_path": "",
                             "patch_path": "", "patch_exists": 0})
        selected = preflight.candidates_from_inputs([], [index])
        self.assertEqual(len(selected), 1)
        result = preflight.inspect_candidate(selected[0], preflight.corpus_hashes(self.catalog), None, None, 2)
        self.assertEqual(result["reasons"], ["patch_missing"])
        self.assertEqual(result["preflight"], "blocked")


if __name__ == "__main__":
    unittest.main()
