#!/usr/bin/env python3
"""Create and process an independent, bounded LLMDroid candidate queue."""

import argparse
import hashlib
import json
import re
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


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def crash_fingerprint(finding):
    """Return a stable app-crash fingerprint, or None when evidence is missing."""
    divergence = finding.get("first_divergence") or {}
    step = next((divergence.get(role) for role in ("mutant", "baseline")
                 if isinstance(divergence.get(role), dict) and
                 divergence[role].get("status") == "crash"), None)
    path = step.get("logcat") if step else None
    if not path:
        return None
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    payloads = [line.split("AndroidRuntime:", 1)[1].strip() for line in lines
                if "AndroidRuntime:" in line]
    start = next((index for index, line in enumerate(payloads)
                  if line.startswith("FATAL EXCEPTION:")), None)
    if start is None:
        return None
    block = []
    for line in payloads[start + 1:]:
        if line.startswith("FATAL EXCEPTION:"):
            break
        block.append(line)
    process = next((line.removeprefix("Process: ").split(", PID:", 1)[0]
                    for line in block if line.startswith("Process: ")), None)
    exception = next((match.group(1) for line in block
                      if (match := re.match(r"(?:Caused by: )?([\w.$]+(?:Exception|Error))(?::|$)", line))), None)
    frames = [match.group(1) for line in block
              if (match := re.match(r"at\s+([^\s(]+)\(", line))]
    app_package = process.split(":", 1)[0] if process else None
    frame = next((item for item in frames if app_package and
                  item.startswith(app_package + ".")), None)
    if not (process and exception and frame):
        return None
    return hashlib.sha256(json.dumps({"process": process, "exception": exception,
                                      "first_app_frame": frame},
                                     sort_keys=True).encode()).hexdigest()


def summarize_runs(runs, repeat):
    signatures = [(run.get("classification"), run.get("first_divergence_index"),
                   run.get("crash_fingerprint"))
                  for run in runs if run.get("status") == "defect_candidate"]
    reproduced = (len(signatures) == repeat and len(set(signatures)) == 1 and
                  (signatures[0][0] != "crash_candidate" or signatures[0][2] is not None))
    if reproduced:
        return {"status": "reproduced_candidate", "classification": signatures[0][0],
                "dedup_signature": signatures[0][2]
                if signatures[0][0] == "crash_candidate" else None}
    if len(runs) == repeat and all(run.get("status") == "no_divergence_observed" for run in runs):
        return {"status": "no_divergence_observed", "classification": None,
                "dedup_signature": None}
    return {"status": "unconfirmed" if signatures else "inconclusive",
            "classification": None, "dedup_signature": None}


def enqueue(capture_path):
    capture_path = Path(capture_path).resolve()
    capture = load(capture_path)
    if capture.get("schema_version") != 1 or not isinstance(capture.get("candidates"), list):
        raise ValueError("invalid capture manifest")
    items = []
    seen = {}
    for candidate in capture["candidates"]:
        sha = candidate.get("mutant_sha256")
        origin_sha = candidate.get("origin_sha256")
        identity = (sha, origin_sha)
        if (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) and
                isinstance(origin_sha, str) and re.fullmatch(r"[0-9a-f]{64}", origin_sha) and
                identity in seen):
            seen[identity]["queue_entries"].append(candidate.get("queue_entry"))
            continue
        item = {"queue_entry": candidate.get("queue_entry"),
                "queue_entries": [candidate.get("queue_entry")],
                "exact_mutant_sha256": sha,
                "stored_apk": str(capture_path.parent / candidate["stored_apk"])
                if candidate.get("stored_apk") else None,
                "origin_path": candidate.get("origin_path"),
                "origin_sha256": origin_sha,
                "research_ready": candidate.get("research_ready") is True,
                "status": "pending_preflight" if candidate.get("research_ready") else "blocked",
                "reasons": [] if candidate.get("research_ready") else
                           list(candidate.get("reasons", []))}
        items.append(item)
        if (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) and
                isinstance(origin_sha, str) and re.fullmatch(r"[0-9a-f]{64}", origin_sha)):
            seen[identity] = item
    return {"schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
            "capture_manifest": str(capture_path), "items": items}


def choose_prepared(prepared, item):
    if (prepared.get("schema_version") != 1 or
            prepared.get("status") != "ready_for_install_attempt" or
            prepared.get("exact_mutant_sha256") != item["exact_mutant_sha256"] or
            prepared.get("origin_sha256") != item["origin_sha256"]):
        return None
    base_dir = Path(prepared["_report_path"]).parent
    result = {}
    for role, key, name in (("baseline", "prepared_baseline", "prepared-baseline.apk"),
                            ("mutant", "prepared_apk", "prepared-signed.apk")):
        expected = prepared[key + "_sha256"]
        paths = [base_dir / name, Path(prepared[key + "_path"])]
        chosen = next((path for path in paths if path.is_file() and digest(path) == expected), None)
        if chosen is None:
            return None
        result[role] = str(chosen.resolve())
        result[role + "_sha256"] = expected
    return result


def device_gate(reports, pair, kind):
    """Reason this pair lacks a healthy device launch of its mutant, else None.

    A prepared mutant must also have been compared with its baseline's resolved
    activity. Offline readiness alone admitted APKs that Android refused or
    that crashed at start (results/gen1-device-admission-2026-11-15).
    """
    source = "prepared_mutant" if kind == "prepared_pair" else "exact_mutant"
    tested = [report for report in reports
              if report.get("tested_apk_sha256") == pair["mutant_sha256"] and
              report.get("source_kind") == source]
    if not tested:
        return "device_launch_gate_missing"
    for report in tested:
        runtime = report.get("device_probe") or {}
        if (report.get("launch_gate_version") == 3 and
                report.get("classification") == "launched_process_running" and
                (kind != "prepared_pair" or
                 (report.get("baseline_apk_sha256") == pair["baseline_sha256"] and
                  report.get("expected_activity") and
                  runtime.get("resolved_activity") == report.get("expected_activity")))):
            return None
    return "device_launch_gate_failed"


def plan(queue, preflight, trace, prepared_reports, device_reports=()):
    queue = load(queue)
    preflight = load(preflight)
    trace_path = Path(trace).resolve()
    trace_data = load(trace_path)
    if (queue.get("schema_version") != 1 or not isinstance(queue.get("items"), list) or
            preflight.get("schema_version") != 1 or not isinstance(preflight.get("candidates"), list) or
            trace_data.get("schema_version") != 1):
        raise ValueError("invalid queue, preflight, or trace")
    prepared = []
    for path in prepared_reports:
        item = load(path)
        item["_report_path"] = str(Path(path).resolve())
        prepared.append(item)
    device = [load(path) for path in device_reports]
    candidates = {(item.get("mutant_sha256"), item.get("origin_sha256")): item
                  for item in preflight["candidates"]}
    items = []
    for source in queue["items"]:
        item = dict(source)
        item["reasons"] = list(item["reasons"])
        sha = item.get("exact_mutant_sha256")
        origin_sha = item.get("origin_sha256")
        if (not item.get("research_ready") or not isinstance(sha, str) or
                not re.fullmatch(r"[0-9a-f]{64}", sha) or
                not isinstance(origin_sha, str) or
                not re.fullmatch(r"[0-9a-f]{64}", origin_sha)):
            item["status"] = "blocked"
            item["reasons"].append("invalid_candidate_identity")
            items.append(item)
            continue
        exact = Path(item["stored_apk"]) if item.get("stored_apk") else None
        if exact is None or not exact.is_file() or digest(exact) != sha:
            item["reasons"].append("exact_mutant_missing_or_hash_mismatch")
        checked = candidates.get((sha, origin_sha))
        if checked is None:
            item["reasons"].append("preflight_missing")
        pair = next((found for report in prepared if
                     (found := choose_prepared(report, item)) is not None), None)
        if pair:
            item["artifact_kind"] = "prepared_pair"
        elif checked and checked.get("preflight") == "eligible_for_install_attempt":
            origin = Path(item["origin_path"]) if item.get("origin_path") else None
            if (origin is None or not origin.is_file() or
                    digest(origin) != item.get("origin_sha256")):
                item["reasons"].append("original_missing_or_hash_mismatch")
            else:
                pair = {"baseline": str(origin.resolve()), "mutant": str(exact.resolve()),
                        "baseline_sha256": digest(origin), "mutant_sha256": sha}
                item["artifact_kind"] = "exact_pair"
        else:
            item["reasons"].append("runtime_preparation_required")
        if pair and trace_data.get("source_apk_sha256") != pair["baseline_sha256"]:
            item["reasons"].append("trace_source_mismatch")
        if pair:
            gate = device_gate(device, pair, item["artifact_kind"])
            if gate:
                item["reasons"].append(gate)
        if not item["reasons"] and pair:
            item["status"] = "ready"
            item["pair"] = pair
        else:
            item["status"] = "blocked"
        items.append(item)
    return {"schema_version": 1, "planned_utc": datetime.now(timezone.utc).isoformat(),
            "trace": str(trace_path), "trace_sha256": digest(trace_path),
            "source_queue": str(Path(queue["capture_manifest"]).resolve()),
            "items": items,
            "summary": {"ready": sum(item["status"] == "ready" for item in items),
                        "blocked": sum(item["status"] == "blocked" for item in items)}}


def process(plan_path, checkout, serial, output_dir, repeat):
    plan_path = Path(plan_path).resolve()
    data = load(plan_path)
    if data.get("schema_version") != 1 or not isinstance(data.get("items"), list):
        raise ValueError("invalid analysis plan")
    if digest(data["trace"]) != data["trace_sha256"]:
        raise ValueError("trace changed since queue planning")
    output = Path(output_dir).resolve()
    if output.exists():
        raise ValueError("output directory already exists")
    output.mkdir(parents=True)
    findings = []
    for item in data["items"]:
        if item["status"] != "ready":
            continue
        pair = item["pair"]
        if (digest(pair["baseline"]) != pair["baseline_sha256"] or
                digest(pair["mutant"]) != pair["mutant_sha256"]):
            findings.append({"queue_entry": item["queue_entry"],
                             "status": "blocked_artifact_changed"})
            continue
        runs = []
        if (not re.fullmatch(r"[0-9a-f]{64}", item["exact_mutant_sha256"]) or
                not re.fullmatch(r"[0-9a-f]{64}", item["origin_sha256"])):
            raise ValueError("invalid candidate identity in analysis plan")
        candidate_dir = output / (item["exact_mutant_sha256"] + "-" + item["origin_sha256"])
        candidate_dir.mkdir()
        for number in range(repeat):
            run_dir = candidate_dir / f"repeat-{number + 1}"
            with (candidate_dir / f"repeat-{number + 1}.log").open("w") as log:
                try:
                    call = subprocess.run([
                        sys.executable, str(Path(__file__).with_name("run-llmdroid-pair.py")),
                        "--checkout", str(checkout), "--baseline-apk", pair["baseline"],
                        "--mutant-apk", pair["mutant"], "--trace", data["trace"],
                        "--serial", serial, "--output-dir", str(run_dir)],
                        stdout=log, stderr=subprocess.STDOUT, timeout=600)
                except subprocess.TimeoutExpired:
                    runs.append({"status": "inconclusive", "reason": "pair_timeout",
                                 "exit_code": None})
                    continue
            finding_path = run_dir / "comparison/finding.json"
            if finding_path.is_file():
                finding = load(finding_path)
                crash_id = (crash_fingerprint(finding)
                            if finding.get("classification") == "crash_candidate" else None)
                runs.append({"status": finding["status"],
                             "classification": finding["classification"],
                             "first_divergence_index": (finding.get("first_divergence") or {}).get("index"),
                             "crash_fingerprint": crash_id,
                             "finding": str(finding_path), "exit_code": call.returncode})
            else:
                runs.append({"status": "inconclusive", "exit_code": call.returncode})
        summary = summarize_runs(runs, repeat)
        findings.append({"queue_entry": item["queue_entry"],
                         "exact_mutant_sha256": item["exact_mutant_sha256"],
                         **summary, "runs": runs,
                         "confirmed_security_vulnerability": False})
    result = {"schema_version": 1, "processed_utc": datetime.now(timezone.utc).isoformat(),
              "plan": str(plan_path), "repeat": repeat, "findings": findings}
    write_new(output / "analysis-results.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("enqueue")
    p.add_argument("--capture-manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = subs.add_parser("plan")
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--trace", type=Path, required=True)
    p.add_argument("--prepared-report", type=Path, action="append", default=[])
    p.add_argument("--device-report", type=Path, action="append", default=[],
                   help="probe-android-runtime.py report for a candidate mutant")
    p.add_argument("--output", type=Path, required=True)
    p = subs.add_parser("run")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--serial", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args()
    try:
        if args.command == "enqueue":
            write_new(args.output, enqueue(args.capture_manifest))
        elif args.command == "plan":
            write_new(args.output, plan(args.queue, args.preflight, args.trace,
                                        args.prepared_report, args.device_report))
        else:
            if not 1 <= args.repeat <= 5:
                parser.error("repeat must be from 1 to 5")
            process(args.plan, args.checkout, args.serial, args.output_dir, args.repeat)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"{args.command} complete")


if __name__ == "__main__":
    main()
