"""The runtime preparation keeps mutant content while repairing only its CRC."""

import importlib.util
import io
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-manifest-runtime-candidate.py"
spec = importlib.util.spec_from_file_location("apkfuzz_manifest_prepare", SCRIPT)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class ManifestPreparationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-manifest-prepare-")
        self.addCleanup(self.temp.cleanup)
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=0) as archive:
            archive.writestr("AndroidManifest.xml", b"prefix-AAAA-suffix")
            archive.writestr("classes.dex", b"another entry")
        self.original = out.getvalue()
        self.layout = prepare.manifest_layout(self.original)
        self.mutant = bytearray(self.original)
        compressed = self.original[self.layout["data_start"]:self.layout["data_end"]]
        offset = self.layout["data_start"] + compressed.index(b"AAAA")
        self.mutant[offset] ^= 0x02

    def test_repair_changes_only_crc_fields_and_preserves_manifest_mutation(self):
        exact = bytes(self.mutant)
        mutant_manifest = prepare.manifest_bytes(exact, self.layout)
        self.assertNotEqual(mutant_manifest, b"prefix-AAAA-suffix")
        repaired, _, changes = prepare.repair_crc(exact, self.layout)
        allowed = set(range(self.layout["local_crc_offset"],
                            self.layout["local_crc_offset"] + 4))
        allowed.update(range(self.layout["central_crc_offset"],
                             self.layout["central_crc_offset"] + 4))
        self.assertTrue(changes)
        self.assertTrue(set(changes) <= allowed)
        with zipfile.ZipFile(io.BytesIO(repaired)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.read("AndroidManifest.xml"), mutant_manifest)
            self.assertEqual(archive.read("classes.dex"), b"another entry")

    def test_unmodified_archive_needs_no_crc_repair(self):
        with self.assertRaisesRegex(ValueError, "made no change"):
            prepare.repair_crc(self.original, self.layout)

    def test_non_manifest_corruption_remains_detectable(self):
        repaired, _, _ = prepare.repair_crc(bytes(self.mutant), self.layout)
        corrupt = bytearray(repaired)
        with zipfile.ZipFile(io.BytesIO(repaired)) as archive:
            other = archive.getinfo("classes.dex")
            index = other.header_offset + 30 + len(other.filename)
        corrupt[index + 5] ^= 0x01
        path = Path(self.temp.name) / "corrupt.apk"
        path.write_bytes(corrupt)
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            prepare.zip_valid(path)

    def test_paired_payload_check_rejects_other_app_changes(self):
        baseline = Path(self.temp.name) / "baseline.apk"
        mutant = Path(self.temp.name) / "mutant.apk"
        with zipfile.ZipFile(baseline, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"original")
            archive.writestr("classes.dex", b"same code")
            archive.writestr("META-INF/library.version", b"1")
            archive.writestr("META-INF/TEST-KEY.SF", b"signature A")
        with zipfile.ZipFile(mutant, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"mutated")
            archive.writestr("classes.dex", b"same code")
            archive.writestr("META-INF/library.version", b"1")
            archive.writestr("META-INF/TEST-KEY.SF", b"signature B")
        self.assertEqual(prepare.shared_payload_unchanged(baseline, mutant), 2)
        with zipfile.ZipFile(mutant, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"mutated")
            archive.writestr("classes.dex", b"same code")
            archive.writestr("META-INF/library.version", b"2")
        with self.assertRaisesRegex(ValueError, "non-manifest payload"):
            prepare.shared_payload_unchanged(baseline, mutant)

    def test_aapt_malformed_xml_warning_blocks_preparation(self):
        argv = ["aapt", "dump", "badging", "candidate.apk"]
        result = subprocess.CompletedProcess(
            argv, 0, stdout="package: name='example'\n",
            stderr="Bad XML block: node attributes exceed block\n")
        with patch.object(prepare.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "Bad XML block"):
                prepare.run_ok(argv)


if __name__ == "__main__":
    unittest.main()
