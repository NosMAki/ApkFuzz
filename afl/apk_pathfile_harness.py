#!/usr/bin/env python3
"""AFL target for ZIP/path-file handling, not F-Droid execution.

Coverage and saved crashes from this process concern Python and ``zipfile``.
They do not measure Android app code, UI coverage, or F-Droid defects. A valid
return only clears this narrow archive check; Android install/launch and
signature admission are separate downstream gates.
"""

import sys
import zipfile
import zlib
from pathlib import Path

from afl import init as afl_init  # Reject an empty local `afl` namespace package.

MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def read_apk_path(pathfile):
    try:
        raw = Path(pathfile).read_bytes()
    except OSError:
        return None

    text = raw.replace(b"\x00", b"").decode("utf-8", errors="ignore").strip()
    if not text:
        return None

    apk_path = Path(text).expanduser()
    if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
        return None

    return apk_path


def touch_optional_entry(apk, name):
    if name not in apk.namelist():
        return

    with apk.open(name, "r") as entry:
        entry.read(4)


def test_pathfile(pathfile):
    apk_path = read_apk_path(pathfile)
    if apk_path is None:
        return False

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            names = apk.namelist()
            if "AndroidManifest.xml" not in names:
                return False

            # Read to EOF: zipfile checks the entry CRC only after the complete
            # manifest is consumed. A four-byte probe admitted broken deflate
            # streams and CRC mismatches into the AFL queue.
            with apk.open("AndroidManifest.xml", "r") as entry:
                manifest = entry.read(MAX_MANIFEST_BYTES + 1)
            if len(manifest) > MAX_MANIFEST_BYTES:
                return False
            if not manifest.startswith(b"\x03\x00\x08\x00"):
                return False
            touch_optional_entry(apk, "classes.dex")
            touch_optional_entry(apk, "resources.arsc")
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error):
        return False
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: apk_pathfile_harness.py <path_file>")
        sys.exit(1)

    afl_init()
    test_pathfile(sys.argv[1])


if __name__ == "__main__":
    main()
