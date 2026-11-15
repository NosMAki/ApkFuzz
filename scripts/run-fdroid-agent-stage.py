#!/usr/bin/env python3
"""Post-AFL F-Droid agent stage; never call a model for an unverified APK pair."""

import argparse
import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE = ROOT / "results/fdroid-guided-2026-11-04/trace.json"
CONTROL = ROOT / "results/fdroid-guided-2026-11-04/original-original-control/pair-report.json"
SMOKE = ROOT / "results/fdroid-guided-2026-11-04/smoke-report.json"
USAGE = ROOT / "results/fdroid-guided-2026-11-04/droidbot-output/LLM-Usage.jsonl"
ORIGINAL = ROOT / "Evaluation-SSBSE-2026/apk/F-Droid.apk"
SIGNED_BASELINE = ROOT / "results/fdroid-prepared-baseline-2026-11-04.apk"
SIGNED_ROOT = ROOT / "results/fdroid-signed-guided-2026-11-04"
CHECKOUT = ROOT / ".deps/LLMDroid"
KEY = ROOT / "results/llmdroid-credentials/elm.key"
PYTHON = ROOT / ".venv-llmdroid/bin/python"

spec = importlib.util.spec_from_file_location("apkfuzz_queue", Path(__file__).with_name(
    "llmdroid-analysis-queue.py"))
queue_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue_module)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, report):
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def precheck(args):
    arm_dir = args.arm_dir.resolve()
    if not PYTHON.is_file() or not CHECKOUT.is_dir():
        raise ValueError("LLMDroid Python environment or checkout missing")
    if not KEY.is_file() or stat.S_IMODE(KEY.stat().st_mode) != 0o600:
        raise ValueError("ELM key file missing or not owner-only mode 600")
    if not args.baseline_apk.is_file() or load(args.trace).get("source_apk_sha256") != digest(args.baseline_apk):
        raise ValueError("trace source does not match the selected F-Droid baseline")
    smoke = load(args.smoke_report)
    if (smoke.get("status") != "completed" or
            smoke.get("apk_sha256") != digest(args.baseline_apk) or
            not args.usage.is_file() or not args.usage.read_text().strip()):
        raise ValueError("selected baseline lacks completed model-use evidence")
    control = load(args.control_report)
    if (control.get("status") != "no_divergence_observed" or
            control.get("baseline_apk_sha256") != digest(args.baseline_apk) or
            control.get("mutant_apk_sha256") != digest(args.baseline_apk)):
        raise ValueError("original/original trace control did not pass")
    outcome = dict(line.split("=", 1) for line in (arm_dir / "outcome.txt").read_text().splitlines()
                   if "=" in line)
    if outcome.get("final_exit_code") != "0":
        raise ValueError("AFL arm did not complete successfully")
    queue = arm_dir / "afl/candidates/analysis-queue.json"
    preflight = arm_dir / "candidate-preflight.json"
    plan = queue_module.plan(queue, preflight, args.trace, args.prepared_report,
                             args.device_report)
    return plan


def command(argv, log_path, timeout):
    with Path(log_path).open("w", encoding="utf-8") as log:
        try:
            run = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            return {"exit_code": run.returncode, "timed_out": False}
        except subprocess.TimeoutExpired:
            return {"exit_code": None, "timed_out": True}


def run_stage(args, plan):
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    save(output / "analysis-plan.json", plan)
    report = {"schema_version": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "arm_dir": str(args.arm_dir.resolve()), "trace_sha256": digest(args.trace),
              "baseline_sha256": digest(args.baseline_apk), "plan_summary": plan["summary"],
              "status": "running", "guided_runs": [], "confirmed_security_vulnerability": False}

    def finish(status, reason=None):
        report["status"] = status
        if reason:
            report["reason"] = reason
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save(output / "agent-stage-report.json", report)
        return 0 if status == "completed" else 4

    if plan["summary"]["ready"] == 0:
        return finish("blocked_no_runtime_eligible_pair", "no candidate passed the pair and trace gates")
    if not args.serial:
        return finish("inconclusive", "device serial required for ready candidates")

    control = command([str(PYTHON), "-B", str(ROOT / "scripts/run-llmdroid-pair.py"),
                       "--checkout", str(CHECKOUT), "--baseline-apk", str(args.baseline_apk),
                       "--mutant-apk", str(args.baseline_apk), "--trace", str(args.trace),
                       "--serial", args.serial, "--output-dir", str(output / "original-original-control")],
                      output / "control.log", 600)
    report["control"] = control
    control_report = output / "original-original-control/pair-report.json"
    if (control["exit_code"] != 0 or not control_report.is_file() or
            load(control_report).get("status") != "no_divergence_observed"):
        return finish("inconclusive", "fresh original/original control failed")

    queue_run = command([str(PYTHON), "-B", str(ROOT / "scripts/llmdroid-analysis-queue.py"),
                         "run", "--plan", str(output / "analysis-plan.json"),
                         "--checkout", str(CHECKOUT), "--serial", args.serial,
                         "--output-dir", str(output / "paired-replay"), "--repeat", "2"],
                        output / "paired-replay.log", 1300 * plan["summary"]["ready"])
    report["paired_replay"] = queue_run
    if queue_run["exit_code"] != 0:
        return finish("inconclusive", "paired replay failed or timed out")
    findings_path = output / "paired-replay/analysis-results.json"
    if not findings_path.is_file():
        return finish("inconclusive", "paired replay produced no analysis report")
    findings = load(findings_path).get("findings", [])
    report["paired_findings"] = [{"queue_entry": item.get("queue_entry"),
                                  "status": item.get("status"),
                                  "classification": item.get("classification")}
                                 for item in findings]

    # Independent model-guided exploration of each verified baseline/mutant.
    # These runs are not substituted for matched-action differential replay.
    for index, item in enumerate(plan["items"]):
        if item["status"] != "ready":
            continue
        for role in ("baseline", "mutant"):
            name = f"candidate-{index + 1}-{role}"
            guided_dir = output / name
            result = command([str(PYTHON), "-B", str(ROOT / "scripts/run-llmdroid-smoke.py"),
                              "--checkout", str(CHECKOUT), "--apk", item["pair"][role],
                              "--serial", args.serial, "--output-dir", str(guided_dir),
                              "--mode", "guided", "--event-count", "8", "--interval", "2",
                              "--timeout", "300", "--app-name", "F-Droid",
                              "--description", "Explore this local F-Droid test APK without downloading apps."],
                             output / f"{name}.log", 370)
            smoke_path = guided_dir / "smoke-report.json"
            usage_path = guided_dir / "droidbot-output/LLM-Usage.jsonl"
            report["guided_runs"].append({"candidate": index + 1, "role": role,
                                          **result,
                                          "smoke_status": load(smoke_path).get("status") if smoke_path.is_file() else None,
                                          "model_requests": (sum(1 for _ in usage_path.open())
                                                             if usage_path.is_file() else 0)})
            save(output / "agent-stage-report.json", report)
    if len(findings) != plan["summary"]["ready"] or any(
            item.get("status") not in ("no_divergence_observed", "reproduced_candidate")
            for item in findings):
        return finish("partial", "one or more paired comparisons were inconclusive")
    if any(run["exit_code"] != 0 or run["smoke_status"] != "completed" or
           run["model_requests"] == 0 for run in report["guided_runs"]):
        return finish("partial", "one or more guided roles did not complete with model use")
    return finish("completed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--arm-dir", required=True, type=Path)
    parser.add_argument("--prepared-report", action="append", type=Path, default=[])
    parser.add_argument("--device-report", action="append", type=Path, default=[],
                        help="device launch-gate report for a prepared or exact mutant")
    parser.add_argument("--signed-baseline", action="store_true",
                        help="use the verified test-signed F-Droid trace and control")
    parser.add_argument("--baseline-apk", type=Path, default=ORIGINAL)
    parser.add_argument("--trace", type=Path, default=TRACE)
    parser.add_argument("--smoke-report", type=Path, default=SMOKE)
    parser.add_argument("--usage", type=Path, default=USAGE)
    parser.add_argument("--control-report", type=Path, default=CONTROL)
    parser.add_argument("--serial")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.signed_baseline:
        args.baseline_apk = SIGNED_BASELINE
        args.trace = SIGNED_ROOT / "trace.json"
        args.smoke_report = SIGNED_ROOT / "smoke-report.json"
        args.usage = SIGNED_ROOT / "droidbot-output/LLM-Usage.jsonl"
        args.control_report = SIGNED_ROOT / "original-original-control/pair-report.json"
    if args.action == "run" and not args.output_dir:
        parser.error("run requires --output-dir")
    try:
        plan = precheck(args)
        print(json.dumps(plan["summary"], sort_keys=True))
        if args.action == "check":
            return 0
        return run_stage(args, plan)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
