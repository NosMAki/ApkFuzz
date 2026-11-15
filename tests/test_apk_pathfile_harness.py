"""The AFL path-file harness must consume the whole manifest and its CRC."""

import importlib.util
import struct
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
afl = types.ModuleType("afl")
afl.init = lambda: None
sys.modules["afl"] = afl
spec = importlib.util.spec_from_file_location("apk_pathfile_harness",
                                             ROOT / "afl/apk_pathfile_harness.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class PathfileHarnessTest(unittest.TestCase):
    def test_late_manifest_crc_damage_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            apk = root / "valid.apk"
            manifest = b"\x03\x00\x08\x00" + b"manifest payload"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("AndroidManifest.xml", manifest)
            pathfile = root / "input.txt"
            pathfile.write_text(str(apk) + "\n")
            self.assertTrue(harness.test_pathfile(pathfile))

            raw = bytearray(apk.read_bytes())
            with zipfile.ZipFile(apk) as archive:
                info = archive.getinfo("AndroidManifest.xml")
            name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
            start = info.header_offset + 30 + name_len + extra_len
            raw[start + 5] ^= 1  # The first four bytes still look correct.
            damaged = root / "damaged.apk"
            damaged.write_bytes(raw)
            pathfile.write_text(str(damaged) + "\n")
            self.assertFalse(harness.test_pathfile(pathfile))


if __name__ == "__main__":
    unittest.main()
