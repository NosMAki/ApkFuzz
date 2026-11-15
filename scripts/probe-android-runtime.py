#!/usr/bin/env python3
"""Bounded Android install/launch probe for one preserved APKVulFuzz mutant.

The default is a device-free plan. --execute requires an explicit ADB serial.
Only a candidate whose capture and offline preflight agree may reach the device.
An APK installed by this probe is uninstalled before it exits.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path


LAUNCH_GATE_VERSION = 3  # process, crash/ANR evidence, and baseline activity
PREFLIGHT = Path(__file__).with_name("inspect-runtime-candidates.py")
spec = importlib.util.spec_from_file_location("apkfuzz_preflight", PREFLIGHT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def run_command(argv, timeout, output_limit=600):
    try:
        # Mutated manifests put arbitrary bytes into tool and crash-log output.
        run = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                             timeout=timeout)
        stdout = run.stdout.strip()
        stderr = run.stderr.strip()
        return {"status": "ok" if run.returncode == 0 else "failed",
                "exit_code": run.returncode, "stdout": stdout[:output_limit],
                "stderr": stderr[:output_limit],
                "stdout_truncated": len(stdout) > output_limit,
                "stderr_truncated": len(stderr) > output_limit}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": f"exceeded {timeout}s"}
    except OSError as exc:
        return {"status": "error", "detail": str(exc)[:300]}


def stored_path(base, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"invalid stored APK path: {relative}")
    return base / path


def select_candidate(capture_path, preflight_path, queue_entry):
    capture_path = Path(capture_path).absolute()
    with capture_path.open(encoding="utf-8") as source:
        capture = json.load(source)
    with open(preflight_path, encoding="utf-8") as source:
        checks = json.load(source)
    matches = [item for item in capture.get("candidates", [])
               if item.get("queue_entry") == queue_entry]
    if len(matches) != 1:
        raise ValueError(f"expected one captured queue entry {queue_entry!r}; found {len(matches)}")
    checked = [item for item in checks.get("candidates", [])
               if any(Path(ref.get("manifest", "")).absolute() == capture_path
                      and ref.get("entry") == queue_entry
                      for ref in item.get("capture_refs", []))]
    if len(checked) != 1:
        raise ValueError(f"expected one preflight result for {queue_entry!r}; found {len(checked)}")
    return capture_path.parent, matches[0], checked[0]


def eligibility(base, captured, checked):
    reasons = []
    relative = captured.get("stored_apk")
    apk = stored_path(base, relative) if relative else None
    if not captured.get("research_ready"):
        reasons.append("capture_not_research_ready")
    if checked.get("preflight") != "eligible_for_install_attempt":
        reasons.append("preflight_blocked")
    if checked.get("capture_integrity") != "match":
        reasons.append("capture_integrity_unverified")
    if checked.get("live_apk_match") != "match":
        reasons.append("patch_live_identity_unverified")
    expected = captured.get("mutant_sha256")
    if not apk or not apk.is_file():
        reasons.append("stored_apk_missing")
    elif not expected or preflight.sha256_file(apk) != expected:
        reasons.append("stored_apk_hash_mismatch")
    if expected != checked.get("mutant_sha256"):
        reasons.append("preflight_hash_mismatch")
    return apk, reasons


def prepared_eligibility(report_path):
    with open(report_path, encoding="utf-8") as source:
        prepared = json.load(source)
    reasons = []
    if prepared.get("status") != "ready_for_install_attempt":
        reasons.append("preparation_not_ready")
    if prepared.get("manifest_content_retained") is not True or (
            prepared.get("mutated_manifest_sha256") !=
            prepared.get("prepared_manifest_sha256")):
        reasons.append("mutation_retention_unverified")
    if (not prepared.get("original_manifest_sha256") or
            prepared.get("original_manifest_sha256") ==
            prepared.get("mutated_manifest_sha256")):
        reasons.append("mutation_not_observed")
    for name in ("origin", "exact_mutant", "crc_repair", "patch", "prepared_apk",
                 "prepared_baseline"):
        path = prepared.get(f"{name}_path")
        digest = prepared.get(f"{name}_sha256")
        if not path or not digest or not Path(path).is_file():
            reasons.append(f"{name}_missing")
        elif preflight.sha256_file(path) != digest:
            reasons.append(f"{name}_hash_mismatch")
    apk = Path(prepared["prepared_apk_path"]) if prepared.get("prepared_apk_path") else None
    if apk and apk.is_file() and "prepared_apk_hash_mismatch" not in reasons:
        try:
            with zipfile.ZipFile(apk) as archive:
                manifest = archive.read("AndroidManifest.xml")
            if hashlib.sha256(manifest).hexdigest() != prepared.get("mutated_manifest_sha256"):
                reasons.append("prepared_manifest_hash_mismatch")
        except (OSError, zipfile.BadZipFile, RuntimeError, KeyError):
            reasons.append("prepared_manifest_unreadable")
    baseline = prepared.get("prepared_baseline_path")
    if baseline and Path(baseline).is_file() and "prepared_baseline_hash_mismatch" not in reasons:
        try:
            with zipfile.ZipFile(baseline) as archive:
                manifest = archive.read("AndroidManifest.xml")
            if hashlib.sha256(manifest).hexdigest() != prepared.get("original_manifest_sha256"):
                reasons.append("baseline_manifest_hash_mismatch")
        except (OSError, zipfile.BadZipFile, RuntimeError, KeyError):
            reasons.append("baseline_manifest_unreadable")
    return apk, prepared, reasons


def package_metadata(aapt, apk, timeout):
    command = run_command([aapt, "dump", "badging", str(apk)], timeout, 100000)
    if command["status"] == "ok" and preflight.aapt_resource_warning(command["stderr"]):
        command["status"] = "failed"
        command["reason"] = "malformed_xml_warning"
    if command["status"] != "ok":
        command["stdout"] = command["stdout"][:600]
        command["stderr"] = command["stderr"][:600]
        return command, None, None
    package = re.search(r"^package: name='([^']+)'", command["stdout"], re.MULTILINE)
    launch = re.search(r"^launchable-activity: name='([^']+)'", command["stdout"], re.MULTILINE)
    command["stdout"] = command["stdout"][:600]
    command["stderr"] = command["stderr"][:600]
    return command, package.group(1) if package else None, launch.group(1) if launch else None


def package_absent(check):
    # Android's `pm path` exits 1 without output when the package is missing.
    return (check.get("status") == "ok" and "package:" not in check.get("stdout", "")
            or check.get("status") == "failed" and check.get("exit_code") == 1
            and not check.get("stdout") and not check.get("stderr"))


def launch_succeeded(check):
    return check["status"] == "ok" and "Status: ok" in check["stdout"]


def resolved_activity(*checks):
    for check in checks:
        if check and launch_succeeded(check):
            found = re.search(r"^Activity: (\S+)", check.get("stdout", ""), re.MULTILINE)
            return found.group(1) if found else None
    return None


def package_fatal_events(log, package):
    """Extract package-owned AndroidRuntime fatal blocks, not nearby log lines."""
    headers = list(re.finditer(r"FATAL EXCEPTION:", log))
    events = []
    process_pattern = re.compile(
        rf"Process: ({re.escape(package)}(?::[\w.]+)?), PID: \d+")
    invalidity_patterns = {
        "security_exception": r"\bSecurityException\b",
        "class_not_found": r"\bClassNotFoundException\b",
        "unable_to_instantiate": r"\bUnable to instantiate\b",
        "required_permission": r"\bPermission\b[^\n]*\bis required\b",
    }
    for index, header in enumerate(headers):
        block = log[header.start():headers[index + 1].start()
                    if index + 1 < len(headers) else len(log)]
        # The Process line belongs immediately to the fatal header. A later
        # unrelated log entry mentioning this package must not claim it.
        process = process_pattern.search(block[:600])
        if not process:
            continue
        reasons = [name for name, pattern in invalidity_patterns.items()
                   if re.search(pattern, block, re.IGNORECASE)]
        exception = re.search(r"(?:Caused by:\s*)?([\w.$]+(?:Exception|Error))(?::|\s|$)",
                              block)
        frames = re.findall(r"\bat\s+([\w.$]+\([^\n)]*\))", block)
        first_frame = next((frame for frame in frames if package in frame),
                           frames[0] if frames else None)
        # Line numbers vary between builds; the exception and first relevant
        # frame are a stable starting point for manual deduplication.
        normalized_frame = re.sub(r":\d+\)", ")", first_frame or "")
        identity = f"{exception.group(1) if exception else ''}|{normalized_frame}"
        events.append({"process": process.group(1),
                       "exception_class": exception.group(1) if exception else None,
                       "first_frame": first_frame,
                       "fingerprint": hashlib.sha256(identity.encode()).hexdigest()
                       if exception and first_frame else None,
                       "suspected_manifest_rejection": bool(reasons),
                       "manifest_rejection_reasons": reasons,
                       "stack_present": bool(frames),
                       "log_block": block[:12000],
                       "log_block_truncated": len(block) > 12000})
    return events


def package_anr_events(log, package):
    """Extract ANR records naming this package or a package-owned process."""
    headers = list(re.finditer(r"\bANR in ([\w.]+(?::[\w.]+)?)", log))
    events = []
    for index, header in enumerate(headers):
        process = header.group(1)
        if process != package and not process.startswith(package + ":"):
            continue
        block = log[header.start():headers[index + 1].start()
                    if index + 1 < len(headers) else len(log)]
        reason = re.search(r"Reason:\s*([^\n]+)", block)
        events.append({"process": process,
                       "reason": reason.group(1).strip()[:300] if reason else None,
                       "input_dispatch_timeout": bool(reason and re.search(
                           r"Input dispatching timed out", reason.group(1), re.IGNORECASE)),
                       "log_block": block[:4000],
                       "log_block_truncated": len(block) > 4000})
    return events


def baseline_expectation(report_path, prepared, serial):
    """Resolved activity of a healthy baseline launch on the same device."""
    with open(report_path, encoding="utf-8") as source:
        base = json.load(source)
    runtime = base.get("device_probe") or {}
    if (base.get("launch_gate_version") != LAUNCH_GATE_VERSION or
            base.get("source_kind") != "prepared_baseline" or
            base.get("classification") != "launched_process_running" or
            base.get("tested_apk_sha256") != prepared.get("prepared_baseline_sha256") or
            runtime.get("serial") != serial or not runtime.get("resolved_activity") or
            (runtime.get("crash") or {}).get("package_fatal_exceptions") != 0):
        raise ValueError("baseline probe report is not a healthy launch of this "
                         "prepared baseline on this device")
    return runtime["resolved_activity"]


def device_probe(adb, serial, apk, package, activity, timeout, settle,
                 expected_activity=None):
    """Install, launch, and remove one APK.

    `launched_process_running` requires a running process, no fatal exception
    or launch ANR logged for the package since the probe began, and, when a baseline's
    resolved activity is supplied, the same resolved activity. A crash-report
    process alone satisfied the older process-only check.
    """
    result = {"serial": serial, "checks": {}, "install": None, "launch": None,
              "launch_fallback": None, "process": None, "crash": None, "anr": None,
              "resolved_activity": None, "expected_activity": expected_activity,
              "cleanup": None, "classification": None}
    command = lambda *parts: [adb, "-s", serial, *parts]
    devices = run_command([adb, "devices", "-l"], timeout)
    result["checks"]["devices"] = devices
    if devices["status"] != "ok" or not any(
        line.split()[:2] == [serial, "device"] for line in devices["stdout"].splitlines()
    ):
        result["classification"] = "device_unavailable"
        return result
    boot = run_command(command("shell", "getprop", "sys.boot_completed"), timeout)
    result["checks"]["boot_completed"] = boot
    if boot["status"] != "ok" or boot["stdout"] != "1":
        result["classification"] = "device_not_ready"
        return result
    installed_before = run_command(command("shell", "pm", "path", package), timeout)
    result["checks"]["package_before"] = installed_before
    if "package:" in installed_before["stdout"]:
        result["classification"] = "package_already_installed"
        return result
    if not package_absent(installed_before):
        result["classification"] = "package_check_failed"
        return result
    # Non-root `logcat -c` leaves other UIDs' entries, so bound the crash check
    # by device time. One second later than now still precedes any launch.
    clock = run_command(command("shell", "date", "+%s"), timeout)
    result["checks"]["device_clock"] = clock
    if clock["status"] != "ok" or not clock["stdout"].isdigit():
        result["classification"] = "device_clock_unavailable"
        return result
    since = f"{int(clock['stdout']) + 1}.000"

    install_attempted = False
    try:
        install_attempted = True
        result["install"] = run_command(command("install", str(apk)), timeout)
        if result["install"]["status"] != "ok" or "Success" not in result["install"]["stdout"]:
            result["classification"] = (
                "install_timeout" if result["install"]["status"] == "timeout"
                else "install_failed"
            )
            return result
        result["launch"] = run_command(
            command("shell", "am", "start", "-W", "-a", "android.intent.action.MAIN",
                    "-c", "android.intent.category.LAUNCHER", "-p", package), timeout)
        if not launch_succeeded(result["launch"]) and activity:
            result["launch_fallback"] = run_command(
                command("shell", "am", "start", "-W", "-n", f"{package}/{activity}"),
                timeout)
        launched = (launch_succeeded(result["launch"]) or
                    result["launch_fallback"] and launch_succeeded(result["launch_fallback"]))
        # Android's own launch timeout and an adb command that never returned
        # are both inconclusive, not evidence that the activity cannot start.
        timed_out = any("Status: timeout" in item.get("stdout", "") or
                        item.get("status") == "timeout" for item in
                        (result["launch"], result["launch_fallback"]) if item)
        if not launched and not timed_out:
            result["classification"] = "launch_failed"
            return result
        if settle:
            time.sleep(settle)
        result["process"] = run_command(command("shell", "pidof", package), timeout)
        running = (result["process"]["status"] == "ok" and
                   bool(result["process"]["stdout"].strip()))
        crash = run_command(command("shell", "logcat", "-b", "crash", "-d", "-T", since),
                            timeout, 100000)
        fatal_events = (package_fatal_events(crash["stdout"], package)
                        if crash["status"] == "ok" else None)
        fatal = len(fatal_events) if fatal_events is not None else None
        result["crash"] = {"status": crash["status"], "since": since,
                           "log_output_truncated": crash.get("stdout_truncated"),
                           "package_fatal_exceptions": fatal,
                           "events": fatal_events,
                           "distinct_fingerprints": sorted({
                               event["fingerprint"] for event in fatal_events
                               if event["fingerprint"]}) if fatal_events is not None else None,
                           "suspected_manifest_rejection_fingerprints": sorted({
                               event["fingerprint"] for event in fatal_events
                               if event["suspected_manifest_rejection"] and
                               event["fingerprint"]}) if fatal_events is not None else None,
                           "app_logic_candidate_fingerprints": sorted({
                               event["fingerprint"] for event in fatal_events
                               if not event["suspected_manifest_rejection"] and
                               event["fingerprint"]}) if fatal_events is not None else None,
                           "incomplete_fatal_blocks": sum(
                               event["fingerprint"] is None for event in fatal_events)
                           if fatal_events is not None else None,
                           "suspected_manifest_rejections": sum(
                               event["suspected_manifest_rejection"]
                               for event in fatal_events) if fatal_events is not None else None,
                           "app_logic_candidates": sum(
                               not event["suspected_manifest_rejection"] and
                               event["fingerprint"] is not None
                               for event in fatal_events) if fatal_events is not None else None,
                           "excerpt": crash.get("stdout", "")[:1500] if fatal else ""}
        if timed_out:
            anr_log = run_command(command("shell", "logcat", "-b", "main", "-b",
                                          "system", "-d", "-T", since), timeout, 100000)
            anr_events = (package_anr_events(anr_log["stdout"], package)
                          if anr_log["status"] == "ok" else None)
            result["anr"] = {"status": anr_log["status"], "since": since,
                             "log_output_truncated": anr_log.get("stdout_truncated"),
                             "package_anrs": len(anr_events) if anr_events is not None else None,
                             "events": anr_events,
                             "excerpt": anr_log.get("stdout", "")[:1500]
                             if anr_events else ""}
        result["resolved_activity"] = resolved_activity(result["launch"],
                                                        result["launch_fallback"])
        if fatal:
            # A logged fatal exception is direct evidence, even when the launch
            # command itself never returned because the app died under it.
            result["classification"] = "launched_crashed"
        elif timed_out and result["anr"] and result["anr"]["package_anrs"]:
            result["classification"] = "launched_anr"
        elif (fatal is None or crash.get("stdout_truncated") or
              (timed_out and (result["anr"]["status"] != "ok" or
                              result["anr"]["log_output_truncated"]))):
            result["classification"] = "runtime_evidence_unavailable"
        elif timed_out and not launched:
            if any(item.get("status") == "timeout" for item in
                   (result["launch"], result["launch_fallback"]) if item):
                result["classification"] = "launch_timeout_infrastructure"
            else:
                result["classification"] = "launch_timeout_unverified"
        elif not running:
            result["classification"] = "process_not_running"
        elif expected_activity and result["resolved_activity"] != expected_activity:
            result["classification"] = "launched_unexpected_activity"
        else:
            result["classification"] = "launched_process_running"
        return result
    finally:
        if install_attempted:
            present = run_command(command("shell", "pm", "path", package), timeout)
            result["cleanup"] = {"package_after": present, "force_stop": None,
                                 "uninstall": None, "complete": False,
                                 "uncertain": False}
            if package_absent(present):
                if result["install"]["status"] == "timeout":
                    # A timed-out install can still register its package later.
                    result["cleanup"]["uncertain"] = True
                else:
                    result["cleanup"]["complete"] = True
            elif "package:" in present.get("stdout", ""):
                result["cleanup"]["force_stop"] = run_command(
                    command("shell", "am", "force-stop", package), timeout)
                uninstall = run_command(command("uninstall", package), timeout)
                result["cleanup"]["uninstall"] = uninstall
                final = run_command(command("shell", "pm", "path", package), timeout)
                result["cleanup"]["package_final"] = final
                result["cleanup"]["complete"] = (
                    uninstall["status"] == "ok" and "Success" in uninstall["stdout"]
                    and package_absent(final)
                )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-manifest")
    parser.add_argument("--preflight-report")
    parser.add_argument("--queue-entry")
    parser.add_argument("--prepared-report", help="signed preparation report for one mutant")
    parser.add_argument("--use-prepared-baseline", action="store_true",
                        help="probe the equivalently signed original from --prepared-report")
    parser.add_argument("--baseline-probe-report",
                        help="healthy --use-prepared-baseline report from the same device; "
                             "required to execute a prepared mutant")
    parser.add_argument("--output", required=True, help="new JSON report; existing files are not overwritten")
    parser.add_argument("--execute", action="store_true", help="install, launch and remove on the named device")
    parser.add_argument("--serial", help="exact ADB device serial, required with --execute")
    parser.add_argument("--adb", default=shutil.which("adb") or "adb")
    parser.add_argument("--aapt", default=preflight.find_aapt())
    parser.add_argument("--apksigner", default=shutil.which("apksigner"))
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--settle", type=float, default=2.0)
    args = parser.parse_args(argv)
    if args.execute and not args.serial:
        parser.error("--execute requires --serial")
    if args.timeout < 1 or args.settle < 0:
        parser.error("--timeout must be positive and --settle nonnegative")
    if Path(args.output).exists():
        parser.error(f"output already exists: {args.output}")
    if args.prepared_report:
        if any((args.capture_manifest, args.preflight_report, args.queue_entry)):
            parser.error("--prepared-report is used alone")
    elif args.use_prepared_baseline:
        parser.error("--use-prepared-baseline requires --prepared-report")
    elif not all((args.capture_manifest, args.preflight_report, args.queue_entry)):
        parser.error("capture manifest, preflight report, and queue entry are required")
    mutant_run = bool(args.prepared_report) and not args.use_prepared_baseline
    if args.baseline_probe_report and not mutant_run:
        parser.error("--baseline-probe-report applies to a prepared mutant only")
    if args.execute and mutant_run and not args.baseline_probe_report:
        parser.error("executing a prepared mutant requires --baseline-probe-report")
    expected_activity = None
    try:
        if args.prepared_report:
            apk, prepared, reasons = prepared_eligibility(args.prepared_report)
            if args.use_prepared_baseline:
                apk = Path(prepared["prepared_baseline_path"]) if prepared.get(
                    "prepared_baseline_path") else None
            if args.baseline_probe_report:
                expected_activity = baseline_expectation(
                    args.baseline_probe_report, prepared, args.serial)
        else:
            base, captured, checked = select_candidate(
                args.capture_manifest, args.preflight_report, args.queue_entry)
            apk, reasons = eligibility(base, captured, checked)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    report = {"schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
              "launch_gate_version": LAUNCH_GATE_VERSION,
              "baseline_probe_report": str(Path(args.baseline_probe_report).absolute())
              if args.baseline_probe_report else None,
              "expected_activity": expected_activity,
              "source_kind": ("prepared_baseline" if args.use_prepared_baseline else
                              "prepared_mutant" if args.prepared_report else "exact_mutant"),
              "capture_manifest": str(Path(args.capture_manifest).absolute())
              if args.capture_manifest else None,
              "preflight_report": str(Path(args.preflight_report).absolute())
              if args.preflight_report else None,
              "prepared_report": str(Path(args.prepared_report).absolute())
              if args.prepared_report else None,
              "queue_entry": prepared.get("queue_entry") if args.prepared_report else args.queue_entry,
              "mutant_sha256": prepared.get("exact_mutant_sha256") if args.prepared_report
              else captured.get("mutant_sha256"),
              "tested_apk_sha256": (prepared.get("prepared_baseline_sha256")
                                    if args.use_prepared_baseline else
                                    prepared.get("prepared_apk_sha256"))
              if args.prepared_report else captured.get("mutant_sha256"),
              "baseline_apk_sha256": prepared.get("prepared_baseline_sha256")
              if args.prepared_report else None,
              "stored_apk": str(apk) if apk else None, "reasons": reasons,
              "signature": None, "baseline_signature": None,
              "metadata": None, "package": None, "launch_activity": None,
              "device_probe": None, "classification": None}
    if reasons:
        report["classification"] = "skipped_preparation" if args.prepared_report else "skipped_preflight"
    elif args.prepared_report and not args.apksigner:
        report["classification"] = "apksigner_unavailable"
    elif not args.aapt:
        report["classification"] = "aapt_unavailable"
    else:
        if args.prepared_report:
            report["signature"] = run_command(
                [args.apksigner, "verify", prepared["prepared_apk_path"]],
                                              args.timeout)
            report["baseline_signature"] = run_command(
                [args.apksigner, "verify", prepared["prepared_baseline_path"]],
                args.timeout)
        if args.prepared_report and report["signature"]["status"] != "ok":
            report["classification"] = "signature_invalid"
        elif args.prepared_report and report["baseline_signature"]["status"] != "ok":
            report["classification"] = "baseline_signature_invalid"
        else:
            meta, package, activity = package_metadata(args.aapt, apk, args.timeout)
            report.update(metadata=meta, package=package, launch_activity=activity)
            if meta["status"] != "ok" or not package:
                report["classification"] = "metadata_unavailable"
            elif not args.execute:
                report["classification"] = "ready_for_device_probe"
            else:
                runtime = device_probe(args.adb, args.serial, apk, package, activity,
                                       args.timeout, args.settle, expected_activity)
                report["device_probe"] = runtime
                report["classification"] = runtime["classification"]
                if runtime["cleanup"] and not runtime["cleanup"]["complete"]:
                    report["reasons"].append(
                        "cleanup_unverified" if runtime["cleanup"]["uncertain"]
                        else "cleanup_failed")
    try:
        with open(args.output, "x", encoding="utf-8") as target:
            json.dump(report, target, indent=2)
            target.write("\n")
    except OSError as exc:
        parser.error(str(exc))
    print(report["classification"])
    print(f"report: {Path(args.output).absolute()}")
    return 1 if any(reason in report["reasons"] for reason in
                    ("cleanup_failed", "cleanup_unverified")) else 0


if __name__ == "__main__":
    sys.exit(main())
