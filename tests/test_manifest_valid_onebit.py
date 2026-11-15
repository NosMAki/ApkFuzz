"""The opt-in valid mode must keep manifest ZIP data intact across generations."""

import hashlib
import importlib.util
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V2 = ROOT / "src/custom_mutators/v2"
APK = ROOT / "Evaluation-SSBSE-2026/apk/F-Droid.apk"
SPEC = importlib.util.spec_from_file_location("patch_tool", ROOT / "scripts/apply-patch.py")
PATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCH)
SPEC = importlib.util.spec_from_file_location("android_binary_xml",
                                              ROOT / "scripts/android_binary_xml.py")
AXML = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AXML)


class ValidManifestOnebitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not APK.is_file():
            raise unittest.SkipTest("F-Droid test APK unavailable")
        compiler = shutil.which(os.environ.get("CC", "clang"))
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-valid-onebit-")
        cls.base = Path(cls.temp.name)
        cls.binary = cls.base / "mutator"
        cls.axml_binary = cls.base / "mutator-axml"
        for binary, mode in ((cls.binary, "manifest-valid-onebit"),
                             (cls.axml_binary, "manifest-axml-onebit")):
            command = [compiler, "-Wall", "-O2", "-D", "APKFUZZ_STANDALONE",
                       "-D", "APKFUZZ_LOCK_COMPILED_MODE=1",
                       f'-DAPKFUZZ_COMPILED_MODE="{mode}"',
                       str(V2 / "zip2.c"), str(V2 / "strategies.c"),
                       str(V2 / "cm_ApkVulFuzz2.c"), "-o", str(binary), "-lz"]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
        (cls.base / "mutants").mkdir()
        (cls.base / "patches").mkdir()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def mutate(self, source, seed, binary=None):
        env = os.environ.copy()
        env["APKFUZZ_OUT_DIR"] = str(self.base / "mutants")
        env["APKFUZZ_SAVE_DIR"] = str(self.base / "patches")
        env["APKFUZZ_LOG"] = "1"
        env["APKFUZZ_LOG_FILE"] = str(self.base / "mutator.log")
        run = subprocess.run([str(binary or self.binary), str(source), str(seed)],
                             env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        output = Path(run.stdout.strip())
        self.assertTrue(output.is_file())
        return output

    def assert_valid_with_lineage(self, output, generation):
        with zipfile.ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            self.assertTrue(archive.read("AndroidManifest.xml").startswith(
                b"\x03\x00\x08\x00"))
        patch = self.base / "patches" / (output.name + ".patch")
        rebuilt, _, actual_generation = PATCH.reconstruct(str(patch), None, True)
        self.assertEqual(actual_generation, generation)
        self.assertEqual(hashlib.sha256(rebuilt).digest(),
                         hashlib.sha256(output.read_bytes()).digest())

    def test_valid_first_and_second_generation(self):
        parents = [self.mutate(APK, seed) for seed in range(10422, 10426)]
        for parent in parents:
            self.assert_valid_with_lineage(parent, 1)
        child = self.mutate(parents[0], 10430)
        self.assert_valid_with_lineage(child, 2)

    def test_invalid_descendant_restarts_from_origin(self):
        raw = bytearray(APK.read_bytes())
        with zipfile.ZipFile(APK) as archive:
            info = archive.getinfo("AndroidManifest.xml")
        name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
        data_start = info.header_offset + 30 + name_len + extra_len
        raw[data_start] ^= 1
        invalid = self.base / "invalid-parent.apk"
        invalid.write_bytes(raw)
        Path(str(invalid) + ".meta").write_text(f"origin {APK}\ngen 1\n")
        output = self.mutate(invalid, 10431)
        self.assert_valid_with_lineage(output, 1)
        log = (self.base / "mutator.log").read_text()
        self.assertIn("status=fallback_to_origin", log)
        self.assertIn("source_reason=descendant_manifest_invalid", log)

    @staticmethod
    def structure_error(apk):
        with zipfile.ZipFile(apk) as archive:
            return AXML.structure_error(archive.read("AndroidManifest.xml"))

    def test_axml_mode_keeps_binary_xml_structure_across_generations(self):
        parents = [self.mutate(APK, seed, self.axml_binary) for seed in range(10440, 10456)]
        for parent in parents:
            self.assert_valid_with_lineage(parent, 1)
            self.assertIsNone(self.structure_error(parent))
        child = self.mutate(parents[0], 10460, self.axml_binary)
        self.assert_valid_with_lineage(child, 2)
        self.assertIsNone(self.structure_error(child))

    def test_axml_mode_restarts_from_origin_after_a_structurally_broken_parent(self):
        # The older mode admits ZIP-valid mutants whose binary XML is damaged.
        broken = next((mutant for mutant in (self.mutate(APK, seed)
                                             for seed in range(10470, 10530))
                       if self.structure_error(mutant)), None)
        self.assertIsNotNone(broken, "no structurally broken valid-onebit mutant in 60 seeds")
        self.assert_valid_with_lineage(broken, 1)
        self.assert_valid_with_lineage(self.mutate(broken, 10531), 2)
        restarted = self.mutate(broken, 10531, self.axml_binary)
        self.assert_valid_with_lineage(restarted, 1)
        self.assertIsNone(self.structure_error(restarted))
        last = (self.base / "mutator.log").read_text().splitlines()[-1]
        self.assertIn("effective_mode=manifest-axml-onebit", last)
        self.assertIn("status=fallback_to_origin", last)
        self.assertIn("source_reason=descendant_manifest_invalid", last)


if __name__ == "__main__":
    unittest.main()
