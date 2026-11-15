#!/usr/bin/env python3
"""Run pinned LLMDroid-Droidbot on one authorized test APK with time-based mode.

The local checkout must first be guarded by patch-llmdroid-local.py. ELM's
key is read from an ignored, owner-only local file and is never written to the
generated LLMDroid config or this script's report.
"""

import argparse
import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from llmdroid_elm import DEFAULT_KEY_FILE, ELM_MODEL, ELM_URL, read_local_key, validate_base_url

COMMIT = "5b5485cf195583370d49e353601985850210277e"


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_event_budget(mode, event_count, event_files):
    """Separate a returned DroidBot run from a fully exercised action budget."""
    if mode != "guided":
        return "completed"
    return "completed" if event_files >= event_count else "partial"


def upstream_event_errors(runtime_log):
    """Find a known upstream event-loop failure without treating app logs as defects."""
    markers = []
    try:
        with Path(runtime_log).open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if "exception during sending events:" in line.lower():
                    markers.append({"line": number, "kind": "event_generation_exception"})
                if len(markers) >= 10:
                    break
    except FileNotFoundError:
        pass
    return markers


def classify_returned_run(mode, event_count, event_files, errors):
    budget = classify_event_budget(mode, event_count, event_files)
    if errors:
        return "inconclusive", "upstream_event_generation_error", budget
    if budget == "partial":
        return "partial", "action_limit_not_reached", budget
    return "completed", None, budget


def check_checkout(checkout):
    checkout = Path(checkout).resolve()
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if commit != COMMIT:
        raise ValueError(f"unsupported LLMDroid commit: {commit}")
    droidbot = checkout / "LLMDroid-Droidbot"
    source = droidbot / "droidbot/policy/llm_agent.py"
    content = source.read_text(encoding="utf-8")
    if ('APKVULFUZZ_LLM_API_KEY' not in content or
            '"ApiKey": "<redacted>"' not in content):
        raise ValueError("LLMDroid credential guard has not been applied")
    return droidbot


def run(args):
    base_url = validate_base_url(args.base_url)
    droidbot_dir = check_checkout(args.checkout)
    apk = Path(args.apk).resolve()
    if not apk.is_file():
        raise ValueError(f"test APK missing: {apk}")
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise ValueError(f"output directory already exists: {output}")
    if args.mode == "guided":
        os.environ["APKVULFUZZ_LLM_API_KEY"] = read_local_key(args.key_file)
    else:
        os.environ.pop("APKVULFUZZ_LLM_API_KEY", None)
    runtime = output / "runtime"
    runtime.mkdir(parents=True)
    config = {
        "AppName": args.app_name,
        "Description": args.description,
        "ApiKey": "",
        "Model": args.model,
        "BaseUrl": base_url,
    }
    (runtime / "config.json").write_text(json.dumps(config, indent=2) + "\n",
                                           encoding="utf-8")
    shutil.copyfile(droidbot_dir / "logging.conf", runtime / "logging.conf")
    report_path = output / "smoke-report.json"
    report = {
        "schema_version": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "llmdroid_commit": COMMIT,
        "python": sys.version.split()[0],
        "mode": args.mode,
        "provider": "University of Edinburgh ELM",
        "base_url": base_url,
        "model": args.model,
        "coverage_mode": "time (no code instrumentation)",
        "apk_path": str(apk),
        "apk_sha256": sha256(apk),
        "device_serial": args.serial,
        "event_limit": args.event_count if args.mode == "guided" else 0,
        "output_dir": str(output / "droidbot-output"),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    os.chdir(runtime)
    sys.path.insert(0, str(droidbot_dir))
    started = time.monotonic()
    try:
        from droidbot import DroidBot, env_manager

        bot = DroidBot(
            app_path=str(apk), device_serial=args.serial, is_emulator=True,
            output_dir=str(output / "droidbot-output"),
            env_policy=env_manager.POLICY_NONE,
            policy_name="dfs_greedy" if args.mode == "guided" else "none",
            random_input=False, event_count=args.event_count if args.mode == "guided" else 0,
            event_interval=args.interval, timeout=args.timeout,
            keep_app=False, keep_env=False, grant_perm=True,
            code_coverage="time",
        )
        bot.start()
        if args.mode == "guided":
            events = output / "droidbot-output/events"
            if not events.is_dir() or not list(events.glob("event_*.json")):
                raise RuntimeError("guided run produced no recorded actions")
        report["status"] = "completed"
    except BaseException as exc:
        report["status"] = "failed"
        report["error_type"] = type(exc).__name__
        secret = os.environ.get("APKVULFUZZ_LLM_API_KEY")
        detail = str(exc)
        report["error"] = (detail.replace(secret, "<redacted>") if secret else detail)[:500]
        raise
    finally:
        report["runtime_seconds"] = round(time.monotonic() - started, 3)
        events = output / "droidbot-output/events"
        report["event_files"] = len(list(events.glob("event_*.json"))) if events.is_dir() else 0
        errors = upstream_event_errors(runtime / "runtime.log")
        if errors:
            report["upstream_errors"] = errors
        if report["status"] == "completed":
            report["status"], reason, report["event_budget_status"] = \
                classify_returned_run(args.mode, args.event_count,
                                      report["event_files"], errors)
            if reason:
                report["reason"] = reason
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        os.environ.pop("APKVULFUZZ_LLM_API_KEY", None)
    print(f"{report['status']}: {report_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("offline", "guided"), default="offline")
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE)
    parser.add_argument("--base-url", default=ELM_URL)
    parser.add_argument("--model", default=ELM_MODEL)
    parser.add_argument("--app-name", default="BenchApp")
    parser.add_argument("--description", default="A local test app that lists installed applications.")
    parser.add_argument("--event-count", type=int, default=5)
    parser.add_argument("--interval", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.event_count < 1 or args.interval < 1 or args.timeout < 1:
        parser.error("event count, interval, and timeout must be positive")
    if not args.worker:
        worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                   *sys.argv[1:], "--worker"], start_new_session=True)
        try:
            code = worker.wait(timeout=args.timeout + 60)
        except subprocess.TimeoutExpired:
            os.killpg(worker.pid, signal.SIGTERM)
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(worker.pid, signal.SIGKILL)
                worker.wait()
            report_path = args.output_dir / "smoke-report.json"
            if report_path.is_file():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["status"] = "watchdog_timeout"
                report["finished_utc"] = datetime.now(timezone.utc).isoformat()
                report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print("LLMDroid smoke watchdog timed out", file=sys.stderr)
            return 124
        return code
    try:
        report = run(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0 if report["status"] == "completed" else 3


if __name__ == "__main__":
    sys.exit(main())
