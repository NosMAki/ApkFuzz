#!/usr/bin/env python3
"""Replay one exported LLMDroid trace using its pinned DroidBot device stack."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from llmdroid_runtime import SynchronizationError, needs_initial_app_launch, retarget_event


COMMIT = "5b5485cf195583370d49e353601985850210277e"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_inputs(args):
    checkout = args.checkout.resolve()
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise ValueError(f"unsupported LLMDroid commit: {head}")
    if not (checkout / "LLMDroid-Droidbot/droidbot/device.py").is_file():
        raise ValueError("LLMDroid device stack missing")
    if not args.apk.is_file():
        raise ValueError("APK missing")
    trace = json.loads(args.trace.read_text(encoding="utf-8"))
    if (trace.get("schema_version") != 1 or trace.get("framework") != "LLMDroid-Droidbot" or
            trace.get("llmdroid_commit") != COMMIT or
            not isinstance(trace.get("actions"), list) or not trace["actions"] or
            trace.get("action_count") != len(trace["actions"])):
        raise ValueError("invalid or empty LLMDroid trace")
    for index, action in enumerate(trace["actions"]):
        if (not isinstance(action, dict) or action.get("index") != index or
                not isinstance(action.get("event"), dict)):
            raise ValueError(f"invalid trace action {index}")
    if args.role == "baseline" and trace.get("source_apk_sha256") != digest(args.apk):
        raise ValueError("baseline APK differs from recorded source APK")
    if args.output_dir.exists():
        raise ValueError(f"output directory already exists: {args.output_dir}")
    return trace, checkout / "LLMDroid-Droidbot"


def adb(serial, *words, timeout=20, check=False):
    return subprocess.run(["adb", "-s", serial, *words], capture_output=True,
                          text=True, timeout=timeout, check=check)


def clear_logcat(serial):
    """Retry short-lived ADB logcat failures without mixing step evidence."""
    for attempt in range(3):
        result = adb(serial, "logcat", "-c", timeout=20)
        if result.returncode == 0:
            return
        if attempt < 2:
            time.sleep(1)
    raise RuntimeError("Android logcat reset failed after three attempts")


def state_summary(state, output_dir, index, phase):
    if state is None:
        raise RuntimeError("LLMDroid could not collect device state")
    screenshot = None
    source = getattr(state, "screenshot_path", None)
    if source and Path(source).is_file():
        destination = output_dir / f"step-{index:03d}-{phase}.png"
        shutil.copyfile(source, destination)
        screenshot = str(destination)
    return {
        "activity": getattr(state, "foreground_activity", None),
        "ui_state": getattr(state, "state_str", None),
        "ui_structure": getattr(state, "structure_str", None),
        "screenshot": screenshot,
        "view_count": len(getattr(state, "views", [])),
    }


def read_state(device, attempts=3):
    """Tolerate brief accessibility-helper gaps without guessing a UI state."""
    for number in range(attempts):
        state = device.get_current_state()
        if state is not None:
            return state
        if number + 1 < attempts:
            time.sleep(2)
    raise RuntimeError("LLMDroid could not collect device state after retries")


def runtime_status(serial, package, output_dir, index):
    log = adb(serial, "logcat", "-d", "-t", "600", timeout=20)
    content = log.stdout[-100000:]
    path = output_dir / f"step-{index:03d}-logcat.txt"
    path.write_text(content, encoding="utf-8", errors="replace")
    if log.returncode != 0:
        return "infrastructure_error", str(path)
    if f"ANR in {package}" in content:
        return "anr", str(path)
    crash_pattern = (r"FATAL EXCEPTION:[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*Process: " +
                     re.escape(package) + r"(?:,|\s)")
    if re.search(crash_pattern, content):
        return "crash", str(path)
    return "ok", str(path)


def run(args):
    trace, stack = check_inputs(args)
    output = args.output_dir.resolve()
    output.mkdir(parents=True)
    report_path = output / "replay-report.json"
    report = {
        "schema_version": 1,
        "role": args.role,
        "status": "running",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "llmdroid_commit": COMMIT,
        "trace_sha256": digest(args.trace),
        "apk_sha256": digest(args.apk),
        "apk_path": str(args.apk.resolve()),
        "device_serial": args.serial,
        "steps": [],
    }

    def save():
        report["updated_utc"] = datetime.now(timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save()
    sys.path.insert(0, str(stack))
    from droidbot.app import App
    from droidbot.device import Device
    from droidbot.input_event import InputEvent

    app = App(str(args.apk.resolve()), output_dir=str(output))
    package = app.get_package_name()
    if not package:
        raise ValueError("APK package name missing")
    report["package"] = package
    device = None
    connected = False
    try:
        # Both roles begin from an absent install and the same clean app data.
        adb(args.serial, "uninstall", package, timeout=30)
        previous = adb(args.serial, "shell", "pm", "path", package, timeout=20)
        if previous.returncode not in (0, 1):
            raise RuntimeError("Android package check failed")
        if previous.stdout.strip():
            raise RuntimeError("prior APK install remains after uninstall")
        device = Device(device_serial=args.serial, is_emulator=True,
                        output_dir=str(output), grant_perm=True)
        device.set_up()
        device.connect()
        connected = True
        # Upstream Device.install_app starts adb install asynchronously and may
        # return as soon as the package appears, before installation finishes.
        # Finish the install here so the following data reset cannot race it.
        installed = adb(args.serial, "install", "-g", str(args.apk.resolve()),
                        timeout=120, check=True)
        if "Success" not in installed.stdout:
            raise RuntimeError("Android did not confirm APK installation")
        device.install_app(app)
        cleared = adb(args.serial, "shell", "pm", "clear", package,
                      timeout=30, check=True)
        if "Success" not in cleared.stdout:
            raise RuntimeError("Android did not confirm app data reset")
        clear_logcat(args.serial)
        first_event = trace["actions"][0]["event"]
        if needs_initial_app_launch(first_event.get("event_type")):
            device.start_app(app)
            time.sleep(args.interval)

        for action in trace["actions"]:
            index = action["index"]
            step = {"index": index, "event_type": action["event"].get("event_type"),
                    "status": "unverified", "source_event_sha256": action.get("source_sha256")}
            report["steps"].append(step)
            try:
                before = read_state(device)
                step["before"] = state_summary(before, output, index, "before")
                payload, matches = retarget_event(action["event"], before.views, package)
                step["matching"] = matches
                event = InputEvent.from_dict(payload)
                if event is None:
                    raise SynchronizationError("LLMDroid cannot deserialize event")
                clear_logcat(args.serial)
                device.send_event(event)
                time.sleep(args.interval)
                step["status"], step["logcat"] = runtime_status(
                    args.serial, package, output, index)
                after = read_state(device)
                step.update(state_summary(after, output, index, "after"))
            except SynchronizationError as exc:
                step["status"] = "sync_failure"
                step["reason"] = str(exc)
            except Exception as exc:
                if step["status"] not in {"crash", "anr"}:
                    step["status"] = "infrastructure_error"
                step["reason"] = f"{type(exc).__name__}: {exc}"[:500]
            save()
            if step["status"] != "ok":
                break
        report["status"] = ("completed" if len(report["steps"]) == len(trace["actions"])
                            and all(step["status"] == "ok" for step in report["steps"])
                            else "inconclusive")
    except BaseException as exc:
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
        raise
    finally:
        if device is not None:
            try:
                if connected:
                    device.disconnect()
                device.tear_down()
                device.uninstall_app(app)
            except Exception as exc:
                report["cleanup_error"] = f"{type(exc).__name__}: {exc}"[:500]
        save()
    print(f"{report['status']}: {report_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--role", choices=("baseline", "mutant"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.interval <= 0 or args.timeout <= 0:
        parser.error("interval and timeout must be positive")
    if not args.worker:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                  *sys.argv[1:], "--worker"], start_new_session=True)
        try:
            return child.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            report_path = args.output_dir / "replay-report.json"
            if report_path.is_file():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["status"] = "watchdog_timeout"
                report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print("LLMDroid replay watchdog timed out", file=sys.stderr)
            return 124
    try:
        run(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
