#!/usr/bin/env python3
"""Run a locked local F-Droid arm and its live sampler in one process session."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def source_hashes():
    names = ("run-fdroid-local-sampled-arm.py", "sample-live-mutations.py",
             "analyze-live-mutation-sample.py")
    return {name: hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
            for name in names}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration", type=int)
    parser.add_argument("seed", type=int)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mode", choices=("manifest-onebit", "manifest-valid-onebit",
                                           "manifest-axml-onebit"),
                        default="manifest-onebit")
    parser.add_argument("--gen1-rate", type=int, default=1000)
    parser.add_argument("--gen1-first", type=int, default=24)
    parser.add_argument("--descendant-rate", type=int, default=2000)
    parser.add_argument("--max-capture-bytes", type=int, default=4_000_000_000)
    args = parser.parse_args()
    if args.duration < 1 or args.seed < 0 or args.gen1_first < 0 or min(args.gen1_rate,
            args.descendant_rate, args.max_capture_bytes) < 1:
        parser.error("duration, rates, and budget must be positive; seed nonnegative")
    output = args.output.absolute()
    sample = Path(str(output) + "-live-sample")
    analysis = Path(str(output) + "-live-analysis")
    if output.exists() or sample.exists() or analysis.exists():
        parser.error("arm, live-sample, or analysis output already exists")
    locked = ["bash", str(ROOT / "scripts/run-fdroid-locked-arm.sh"),
              args.mode, str(args.duration), str(args.seed), str(output)]
    preflight = subprocess.run(locked + ["--check"], cwd=ROOT)
    if preflight.returncode:
        return preflight.returncode
    watcher = [sys.executable, "-B", str(ROOT / "scripts/sample-live-mutations.py"),
               "--log", str(output / "afl/apkfuzz_mutator.log"),
               "--patch-dir", str(output / "patches"),
               "--output", str(sample), "--stop-file", str(sample / "stop"),
               "--seed", str(args.seed), "--gen1-rate", str(args.gen1_rate),
               "--gen1-first", str(args.gen1_first),
               "--descendant-rate", str(args.descendant_rate),
               "--max-capture-bytes", str(args.max_capture_bytes),
               "--max-seconds", str(args.duration + 400)]
    sample_process = subprocess.Popen(watcher, cwd=ROOT, start_new_session=True)
    started = utc_now()
    start_hashes = source_hashes()
    arm_process = subprocess.Popen(locked, cwd=ROOT, start_new_session=True)
    watcher_died_early = False
    try:
        while arm_process.poll() is None:
            if sample_process.poll() is not None:
                watcher_died_early = True
                os.killpg(arm_process.pid, signal.SIGINT)
                break
            time.sleep(1)
        arm_rc = arm_process.wait()
    except KeyboardInterrupt:
        os.killpg(arm_process.pid, signal.SIGINT)
        arm_rc = arm_process.wait()
    sample.mkdir(parents=True, exist_ok=True)
    (sample / "stop").touch()
    try:
        sample_rc = sample_process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(sample_process.pid, signal.SIGTERM)
        sample_rc = sample_process.wait(timeout=10)
    analysis_command = [sys.executable, "-B",
                        str(ROOT / "scripts/analyze-live-mutation-sample.py"),
                        "--sample-dir", str(sample), "--output-dir", str(analysis)]
    analysis_rc = None
    if arm_rc == 0 and sample_rc == 0 and not watcher_died_early:
        analysis_rc = subprocess.run(analysis_command, cwd=ROOT).returncode
    final_hashes = source_hashes()
    report = {"started_utc": started, "finished_utc": utc_now(),
              "arm_command": locked, "watcher_command": watcher,
              "analysis_command": analysis_command,
              "arm_exit_code": arm_rc, "watcher_exit_code": sample_rc,
              "analysis_exit_code": analysis_rc,
              "source_sha256_start": start_hashes,
              "source_sha256_end": final_hashes,
              "source_drift": start_hashes != final_hashes,
              "watcher_died_early": watcher_died_early}
    (sample / "supervisor.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)
    return arm_rc or sample_rc or int(watcher_died_early) or analysis_rc or int(start_hashes != final_hashes)


if __name__ == "__main__":
    sys.exit(main())
