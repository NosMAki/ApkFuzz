"""The Python and C binary-XML structure checks must agree and reject damage."""

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
SPEC = importlib.util.spec_from_file_location("android_binary_xml",
                                              ROOT / "scripts/android_binary_xml.py")
AXML = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AXML)
NO = 0xFFFFFFFF


def pool(strings, utf8=False):
    data, offsets = b"", []
    for text in strings:
        offsets.append(len(data))
        if utf8:
            raw = text.encode()
            data += bytes([len(text), len(raw)]) + raw + b"\0"
        else:
            data += struct.pack("<H", len(text)) + text.encode("utf-16le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(strings)
    return (struct.pack("<HHIIIIII", 1, 28, start + len(data), len(strings), 0,
                        0x100 if utf8 else 0, start, 0) +
            b"".join(struct.pack("<I", offset) for offset in offsets) + data)


def node(kind, ext):
    return struct.pack("<HHIII", kind, 16, 16 + len(ext), 1, NO) + ext


def document(utf8=False, end=True):
    strings = ["manifest", "package", "org.example.app"]
    attribute = struct.pack("<IIIHBBI", NO, 1, 2, 8, 0, 3, 2)
    body = pool(strings, utf8) + node(
        0x0102, struct.pack("<IIHHHHHH", NO, 0, 20, 20, 1, 0, 0, 0) + attribute)
    if end:
        body += node(0x0103, struct.pack("<II", NO, 0))
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


def patched(data, offset, fmt, value):
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


class Driver:
    """Compiled apkfuzz_axml_valid(); unavailable without a C compiler."""

    def __init__(self):
        compiler = shutil.which(os.environ.get("CC", "clang"))
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-axml-")
        self.base = Path(self.temp.name)
        self.binary = self.base / "axml_check_driver"
        subprocess.run([compiler, "-Wall", "-O2", f"-I{V2}",
                        str(ROOT / "tests/axml_check_driver.c"), str(V2 / "strategies.c"),
                        str(V2 / "zip2.c"), "-o", str(self.binary), "-lz"],
                       check=True, capture_output=True, timeout=30)

    def verdicts(self, data, variants=()):
        source = self.base / "manifest.bin"
        source.write_bytes(data)
        run = subprocess.run([str(self.binary), str(source)], capture_output=True, text=True,
                             input="".join(f"{o} {m}\n" for o, m in variants), timeout=60)
        if run.returncode:
            raise AssertionError(f"driver failed: {run.stderr}")
        return [line == "1" for line in run.stdout.split()]


class StructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = Driver()
        cls.addClassCleanup(cls.driver.temp.cleanup)

    def check(self, data, reason):
        self.assertEqual(AXML.structure_error(data), reason)
        self.assertEqual(self.driver.verdicts(data), [reason is None])

    def test_minimal_documents_are_valid(self):
        self.check(document(), None)
        self.check(document(utf8=True), None)

    def test_damage_classes_are_rejected(self):
        good = document()
        first_offset = 8 + 28
        strings_start = 8 + 28 + 12
        element = 8 + struct.unpack_from("<I", good, 12)[0]
        cases = [
            (good[:-4], "document_header"),
            (patched(good, 2, "<H", 12), "document_header"),
            (patched(good, first_offset + 4, "<I", 0x232000), "string_offset"),
            (patched(good, strings_start, "<H", 9), "string_termination"),
            (patched(good, 12, "<I", struct.unpack_from("<I", good, 12)[0] + 2), "chunk_bounds"),
            (patched(good, element, "<H", 0x0105), "chunk_type"),
            (patched(good, element + 2, "<H", 0), "chunk_bounds"),
            (patched(good, element + 16 + 4, "<I", 7), "string_reference"),
            (patched(good, element + 16 + 12, "<H", 900), "attribute_bounds"),
            (patched(good, element + 36 + 16, "<I", 3), "attribute_value"),
            (document(end=False), "document_incomplete"),
        ]
        for data, reason in cases:
            with self.subTest(reason=reason):
                self.check(data, reason)

    def test_python_and_c_agree_on_single_byte_changes_to_a_real_manifest(self):
        if not APK.is_file():
            self.skipTest("F-Droid test APK unavailable")
        with zipfile.ZipFile(APK) as archive:
            manifest = archive.read("AndroidManifest.xml")
        self.assertIsNone(AXML.structure_error(manifest))
        # Every header and string-offset byte twice, then a fixed stride over the rest.
        variants = [(offset, mask) for offset in range(0, 1244) for mask in (0x01, 0x80)]
        variants += [(offset, 1 << (offset % 8)) for offset in range(1244, len(manifest), 23)]
        actual = self.driver.verdicts(manifest, variants)
        self.assertTrue(actual[0])
        work = bytearray(manifest)
        rejected = 0
        for (offset, mask), verdict in zip(variants, actual[1:], strict=True):
            work[offset] ^= mask
            expected = AXML.structure_error(bytes(work)) is None
            work[offset] ^= mask
            self.assertEqual(verdict, expected, f"offset {offset} mask {mask}")
            rejected += not expected
        # The sample must exercise both verdicts, not agree trivially.
        self.assertGreater(rejected, 100)
        self.assertGreater(len(variants) - rejected, 100)


if __name__ == "__main__":
    unittest.main()
