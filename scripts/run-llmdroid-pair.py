#!/usr/bin/env python3
"""Run baseline and mutant sequentially on one controlled Android emulator."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def adb_text(serial, *args):
    run = subprocess.run(["adb", "-s", serial, *args], capture_output=True,
                         text=True, timeout=30, check=True)
    return run.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--baseline-apk", type=Path, required=True)
    parser.add_argument("--mutant-apk", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-per-run", type=int, default=240)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("output directory already exists")
    if args.timeout_per_run <= 0 or args.interval <= 0:
        parser.error("timeouts and intervals must be positive")
    for path in (args.baseline_apk, args.mutant_apk, args.trace):
        if not path.is_file():
            parser.error(f"missing input: {path}")
    if adb_text(args.serial, "get-state") != "device":
        parser.error("Android emulator is not ready")
    if adb_text(args.serial, "shell", "getprop", "sys.boot_completed") != "1":
        parser.error("Android emulator has not finished booting")

    output = args.output_dir.resolve()
    output.mkdir(parents=True)
    report_path = output / "pair-report.json"
    report = {
        "schema_version": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "execution": "sequential on one emulator; clean APK reinstall for each role",
        "serial": args.serial,
        "android_sdk": adb_text(args.serial, "shell", "getprop", "ro.build.version.sdk"),
        "android_fingerprint": adb_text(args.serial, "shell", "getprop", "ro.build.fingerprint"),
        "trace_sha256": digest(args.trace),
        "baseline_apk_sha256": digest(args.baseline_apk),
        "mutant_apk_sha256": digest(args.mutant_apk),
        "runs": {},
    }

    def save():
        report["updated_utc"] = datetime.now(timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save()
    replay = Path(__file__).with_name("replay-llmdroid-trace.py")
    for role, apk in (("baseline", args.baseline_apk), ("mutant", args.mutant_apk)):
        role_dir = output / role
        command = [sys.executable, str(replay), "--checkout", str(args.checkout),
                   "--apk", str(apk), "--trace", str(args.trace), "--serial", args.serial,
                   "--role", role, "--output-dir", str(role_dir), "--interval",
                   str(args.interval), "--timeout", str(args.timeout_per_run)]
        with (output / f"{role}-runner.log").open("w", encoding="utf-8") as log:
            try:
                run = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                     timeout=args.timeout_per_run + 30)
            except subprocess.TimeoutExpired:
                report["runs"][role] = {"exit_code": None,
                                        "report": str(role_dir / "replay-report.json"),
                                        "timed_out": True}
                report["status"] = "inconclusive"
                report["reason"] = f"{role} replay timed out"
                save()
                print(f"{report['status']}: {report_path}")
                return 1
        report["runs"][role] = {"exit_code": run.returncode,
                                "report": str(role_dir / "replay-report.json")}
        save()
        if not (role_dir / "replay-report.json").is_file():
            report["status"] = "inconclusive"
            report["reason"] = f"{role} replay produced no report"
            save()
            print(f"{report['status']}: {report_path}")
            return 1

    comparison_dir = output / "comparison"
    comparison = subprocess.run([
        sys.executable, str(Path(__file__).with_name("compare-llmdroid-runs.py")),
        "--baseline", report["runs"]["baseline"]["report"],
        "--mutant", report["runs"]["mutant"]["report"],
        "--output-dir", str(comparison_dir)], capture_output=True, text=True)
    if comparison.returncode:
        report["status"] = "inconclusive"
        report["reason"] = comparison.stderr[-500:]
    else:
        finding = json.loads((comparison_dir / "finding.json").read_text())
        report["status"] = finding["status"]
        report["classification"] = finding["classification"]
        report["finding"] = str(comparison_dir / "finding.json")
    save()
    print(f"{report['status']}: {report_path}")
    return 0 if comparison.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
