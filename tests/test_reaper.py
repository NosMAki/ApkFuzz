#!/usr/bin/env python3
"""The scratch reaper keeps AFL queue inputs and removes stale mutants."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="apkfuzz-reaper-") as tmp:
        base = Path(tmp)
        scratch = base / "scratch"
        queue = base / "out" / "default" / "queue"
        scratch.mkdir()
        queue.mkdir(parents=True)
        live = scratch / "live.apk"
        dead = scratch / "dead.apk"
        for path in (live, dead):
            path.write_bytes(b"apk")
            (scratch / (path.name + ".meta")).write_text("metadata")
            old = time.time() - 30
            os.utime(path, (old, old))
        (queue / "id:000001").write_text(str(live) + "\n")
        result = subprocess.run(
            [sys.executable, str(root / "scripts/reap-scratch.py"),
             "--scratch", str(scratch), "--output", str(base / "out"),
             "--grace", "1", "--once"], capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert live.exists() and (scratch / "live.apk.meta").exists()
        assert not dead.exists() and not (scratch / "dead.apk.meta").exists()
    print("PASS  scratch reaper preserves live queue mutants and removes stale files")


if __name__ == "__main__":
    main()
