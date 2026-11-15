#!/usr/bin/env python3
"""Record a bounded, non-LLM launch action with LLMDroid's own EventLog."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


COMMIT = "5b5485cf195583370d49e353601985850210277e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--settle", type=float, default=3)
    parser.add_argument("--tap-text", help="also record one uniquely matched Button tap")
    args = parser.parse_args()
    if args.output_dir.exists() or not args.apk.is_file() or args.settle <= 0:
        parser.error("output must be new, APK must exist, and settle must be positive")
    head = subprocess.run(["git", "-C", str(args.checkout), "rev-parse", "HEAD"],
                          check=True, text=True, capture_output=True).stdout.strip()
    if head != COMMIT:
        parser.error("unsupported LLMDroid checkout")
    sys.path.insert(0, str(args.checkout.resolve() / "LLMDroid-Droidbot"))
    from droidbot.app import App
    from droidbot.device import Device
    from droidbot.input_event import EventLog, IntentEvent, TouchEvent
    from llmdroid_runtime import match_view

    output = args.output_dir.resolve()
    output.mkdir(parents=True)
    app = App(str(args.apk.resolve()), output_dir=str(output))
    package = app.get_package_name()
    if not package:
        parser.error("APK has no package")
    subprocess.run(["adb", "-s", args.serial, "uninstall", package],
                   capture_output=True, timeout=30)
    old = subprocess.run(["adb", "-s", args.serial, "shell", "pm", "path", package],
                         capture_output=True, text=True, timeout=20)
    if old.returncode not in (0, 1):
        raise RuntimeError("Android package check failed")
    if old.stdout.strip():
        raise RuntimeError("prior APK install remains after uninstall")
    device = Device(device_serial=args.serial, is_emulator=True,
                    output_dir=str(output), grant_perm=True)
    connected = False
    try:
        device.set_up()
        device.connect()
        connected = True
        device.install_app(app)
        cleared = subprocess.run(["adb", "-s", args.serial, "shell", "pm", "clear", package],
                                 check=True, capture_output=True, text=True, timeout=30)
        if "Success" not in cleared.stdout:
            raise RuntimeError("Android did not confirm app data reset")
        event = IntentEvent(app.get_start_intent())
        log = EventLog(device, app, event, tag="000-launch")
        log.start()
        time.sleep(args.settle)
        log.stop()
        event_path = output / "events/event_000-launch.json"
        if not event_path.is_file():
            raise RuntimeError("LLMDroid did not save launch event")
        record = json.loads(event_path.read_text(encoding="utf-8"))
        if not record.get("start_state") or not record.get("stop_state"):
            raise RuntimeError("LLMDroid event lacks start or stop state")
        if args.tap_text:
            current = device.get_current_state()
            if current is None:
                raise RuntimeError("could not observe screen before tap")
            target = match_view({"class": "android.widget.Button", "text": args.tap_text},
                                current.views).view
            tap = EventLog(device, app, TouchEvent(view=target), tag="001-tap")
            tap.start()
            time.sleep(args.settle)
            tap.stop()
            if not (output / "events/event_001-tap.json").is_file():
                raise RuntimeError("LLMDroid did not save tap event")
        print(f"recorded: {event_path}")
    finally:
        try:
            if connected:
                device.disconnect()
            device.tear_down()
            device.uninstall_app(app)
        except Exception as exc:
            print(f"cleanup failed: {type(exc).__name__}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
