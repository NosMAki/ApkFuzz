#!/usr/bin/env python3
"""Bounded DroidBot APK-parser check over saved random-mutator patches.

This invokes DroidBot's App parser in a separate process for each reconstructed
APK. It does not install or launch apps on an emulator.
"""

import argparse
import csv
import itertools
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = r'''
import json
import sys
from droidbot.app import App
try:
    app = App(sys.argv[1])
    result = {"status": "parsed", "detail": app.get_package_name()}
except Exception as exc:
    result = {"status": "rejected:" + type(exc).__name__, "detail": str(exc)[:300]}
print("APKFUZZ_PROBE=" + json.dumps(result, ensure_ascii=False), flush=True)
'''


def parser_probe(python, checkout, apk, seconds):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(checkout) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        result = subprocess.run(
            [str(python), "-c", PROBE, str(apk)], env=env, text=True,
            capture_output=True, timeout=seconds,
        )
    except subprocess.TimeoutExpired:
        return "timeout", "parser exceeded per-input limit", 124
    if result.returncode < 0:
        return "signal", f"signal {-result.returncode}", result.returncode
    for line in reversed(result.stdout.splitlines()):
        if line.startswith("APKFUZZ_PROBE="):
            try:
                value = json.loads(line[len("APKFUZZ_PROBE="):])
                return value["status"], value.get("detail", ""), result.returncode
            except (ValueError, KeyError):
                break
    return "probe_error", result.stderr.strip()[-300:], result.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--campaign", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--duration", type=int, default=10800, help="wall-clock seconds")
    ap.add_argument("--seed", type=int, default=23005)
    ap.add_argument("--max-cases", type=int, default=0, help="short rehearsal only")
    ap.add_argument("--input-timeout", type=int, default=20)
    ap.add_argument("--droidbot", type=Path, default=Path("/home/sahar/Projects/droidbot"))
    ap.add_argument("--python", type=Path, default=ROOT / ".venv-droidbot/bin/python3")
    args = ap.parse_args()
    if args.duration < 1 or args.input_timeout < 1 or args.max_cases < 0:
        ap.error("duration and input timeout must be positive; max cases cannot be negative")
    args.campaign = args.campaign.resolve()
    args.out = args.out.resolve()
    args.droidbot = args.droidbot.resolve()
    # Keep the venv executable path: resolving its symlink to /usr/bin/python3
    # would discard the environment that contains DroidBot's dependencies.
    args.python = args.python.absolute()
    if not args.python.is_file() or not (args.droidbot / "droidbot/app.py").is_file():
        ap.error("DroidBot checkout or Python environment is missing")
    if args.out.exists():
        ap.error(f"output already exists: {args.out}")

    rng = random.Random(args.seed)
    paths = {}
    for app in ("F-Droid", "flashlight"):
        items = list((args.campaign / "patches" / app).glob("*.patch"))
        if not items:
            ap.error(f"no patches for {app}")
        rng.shuffle(items)
        paths[app] = items

    # A clean APK must parse before malformed inputs are classified.
    controls = {}
    for app in paths:
        clean = ROOT / "Evaluation-SSBSE-2026/apk" / f"{app}.apk"
        status, detail, _ = parser_probe(args.python, args.droidbot, clean, args.input_timeout)
        if status != "parsed":
            ap.error(f"clean {app} failed DroidBot parsing: {status}: {detail}")
        controls[app] = detail

    args.out.mkdir(parents=True)
    (args.out / "findings").mkdir()
    config = {
        "campaign": str(args.campaign), "droidbot": str(args.droidbot),
        "python": str(args.python), "duration_seconds": args.duration,
        "input_timeout_seconds": args.input_timeout, "selection_seed": args.seed,
        "patches_available": {app: len(items) for app, items in paths.items()},
        "clean_controls": controls, "started_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (args.out / "config.json").write_text(json.dumps(config, indent=2) + "\n")

    stopped = False

    def stop_requested(_signum, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    started = time.monotonic()
    counts = Counter()
    app_counts = Counter()
    infrastructure_failures = 0
    total = 0
    report = args.out / "results.tsv"
    with report.open("w", newline="") as f, tempfile.TemporaryDirectory(
        prefix="apkfuzz-droidbot-parser-", dir="/dev/shm"
    ) as scratch:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(("local_time", "app", "patch", "status", "detail", "elapsed_ms", "exit_code"))
        f.flush()
        candidate = Path(scratch) / "candidate.apk"
        for pair in itertools.zip_longest(paths["F-Droid"], paths["flashlight"]):
            for app, patch in zip(("F-Droid", "flashlight"), pair):
                if stopped or time.monotonic() - started >= args.duration:
                    break
                if args.max_cases and total >= args.max_cases:
                    break
                if patch is None:
                    continue
                candidate.unlink(missing_ok=True)
                case_start = time.monotonic()
                try:
                    rebuild = subprocess.run(
                        [sys.executable, str(ROOT / "scripts/apply-patch.py"), str(patch),
                         "-o", str(candidate)], text=True, capture_output=True, timeout=30,
                    )
                    if rebuild.returncode:
                        status, detail, exit_code = "reconstruct_failed", rebuild.stderr.strip()[-300:], rebuild.returncode
                    else:
                        status, detail, exit_code = parser_probe(
                            args.python, args.droidbot, candidate, args.input_timeout
                        )
                except subprocess.TimeoutExpired:
                    status, detail, exit_code = "reconstruct_timeout", "patch reconstruction exceeded 30s", 124

                if status in ("signal", "timeout") and candidate.is_file() and counts[status] < 10:
                    shutil.copy2(candidate, args.out / "findings" / f"{app}-{patch.stem}.apk")
                elapsed_ms = round((time.monotonic() - case_start) * 1000)
                writer.writerow((time.strftime("%Y-%m-%dT%H:%M:%S%z"), app, str(patch),
                                 status, detail.replace("\t", " ").replace("\n", " "),
                                 elapsed_ms, exit_code))
                f.flush()
                total += 1
                counts[status] += 1
                app_counts[app] += 1
                if status in ("probe_error", "reconstruct_failed", "reconstruct_timeout"):
                    infrastructure_failures += 1
                else:
                    infrastructure_failures = 0
                if total % 100 == 0:
                    print(f"checked={total} elapsed_s={int(time.monotonic()-started)} "
                          f"statuses={dict(counts)}", flush=True)
                if infrastructure_failures >= 3:
                    stopped = True
                    print("stopping after three consecutive infrastructure failures", file=sys.stderr)
                    break
            if stopped or time.monotonic() - started >= args.duration or (args.max_cases and total >= args.max_cases):
                break

    summary = {
        "finished_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "cases": total, "by_app": dict(app_counts), "by_status": dict(counts),
        "stopped_early": stopped or (not args.max_cases and time.monotonic() - started < args.duration),
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 1 if infrastructure_failures >= 3 else 0


if __name__ == "__main__":
    sys.exit(main())
