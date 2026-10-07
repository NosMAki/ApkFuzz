#!/usr/bin/env python3
"""Crash and hang path-files remain reconstructable after tmpfs cleanup."""
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="apkfuzz-triage-") as tmp:
        base = Path(tmp)
        origin = base / "origin.apk"
        origin.write_bytes(b"0123456789")
        missing = base / "reaped" / "origin_123_1.apk"
        patch_dir = base / "patches"
        patch_dir.mkdir()
        (patch_dir / (missing.name + ".patch")).write_text(
            "# apkfuzz-patch v2\n"
            f"origin {origin}\nmode random-range\nseed 123\niter 1\n"
            "gen 1\nstatus ok\nedits 1\n3 33 78\n"
        )
        out = base / "afl" / "default"
        for kind in ("crashes", "hangs"):
            folder = out / kind
            folder.mkdir(parents=True)
            (folder / "id:000001").write_text(str(missing) + "\n")
        queue = out / "queue"
        queue.mkdir()
        (queue / "id:000002,src:000000,+cov").write_text(str(missing) + "\n")
        collected = base / "collected"
        queue_index = base / "queue-index.tsv"
        result = subprocess.run(
            [sys.executable, str(root / "scripts/triage-afl-output.py"), str(out),
             "--collect", str(collected), "--patch-dir", str(patch_dir),
             "--queue-index", str(queue_index)],
            capture_output=True, text=True,
        )
        assert result.returncode == 3, result.stdout + result.stderr
        for kind in ("crashes", "hangs"):
            assert (collected / kind / "inputs" / "id:000001").exists()
            assert (collected / kind / "apks" / missing.name).read_bytes() == b"012x456789"
        assert "\t1\n" in queue_index.read_text()
    print("PASS  queue, crash and hang artifacts survive tmpfs cleanup")


if __name__ == "__main__":
    main()
