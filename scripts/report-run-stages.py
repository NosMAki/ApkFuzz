#!/usr/bin/env python3
"""Summarize one AFL arm and optional later Android evidence without mixing stages."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load(path, sources):
    path = Path(path).resolve()
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError(f"unsupported report schema: {path}")
    sources.append({"path": str(path), "sha256": digest(path)})
    return value


def stats(path, sources):
    path = Path(path).resolve()
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            result[key.strip()] = value.strip()
    sources.append({"path": str(path), "sha256": digest(path)})
    return result


def config(path, sources):
    path = Path(path).resolve()
    result = dict(line.split("=", 1) for line in path.read_text().splitlines()
                  if "=" in line)
    sources.append({"path": str(path), "sha256": digest(path)})
    return result


def integer(value, label):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc


def device_counts(paths, sources):
    if not paths:
        return None  # No device measurement is different from zero successes.
    grouped = {}
    for path in paths:
        report = load(path, sources)
        kind = report.get("source_kind")
        if kind not in ("exact_mutant", "prepared_mutant", "prepared_baseline"):
            raise ValueError(f"unknown device artifact kind in {path}")
        row = grouped.setdefault(kind, Counter())
        row["reports"] += 1
        probe = report.get("device_probe")
        if not isinstance(probe, dict):
            continue
        install = probe.get("install")
        if isinstance(install, dict):
            row["install_attempts"] += 1
            if install.get("status") == "ok" and "Success" in install.get("stdout", ""):
                row["install_successes"] += 1
        if isinstance(probe.get("launch"), dict):
            row["launch_attempts"] += 1
        if probe.get("classification") == "launched_process_running":
            row["launch_process_running"] += 1
    fields = ("reports", "install_attempts", "install_successes", "launch_attempts",
              "launch_process_running")
    return {kind: {field: counts[field] for field in fields}
            for kind, counts in grouped.items()}


def pair_counts(paths, sources):
    if not paths:
        return None
    counts = Counter()
    for path in paths:
        report = load(path, sources)
        counts["reports"] += 1
        if report.get("status") in ("no_divergence_observed", "defect_candidate"):
            counts["comparable_pairs"] += 1
        runs = report.get("runs", {})
        if all(isinstance(runs.get(role), dict) and runs[role].get("exit_code") == 0
               for role in ("baseline", "mutant")):
            counts["runner_success_pairs"] += 1
        replay_statuses = []
        for role in ("baseline", "mutant"):
            replay_path = runs.get(role, {}).get("report") if isinstance(runs.get(role), dict) else None
            if replay_path and Path(replay_path).is_file():
                replay_statuses.append(load(replay_path, sources).get("status"))
        if replay_statuses == ["completed", "completed"]:
            counts["completed_matched_pairs"] += 1
    return {field: counts[field] for field in
            ("reports", "comparable_pairs", "runner_success_pairs", "completed_matched_pairs")}


def analysis_counts(paths, sources):
    if not paths:
        return None
    counts = Counter()
    for path in paths:
        report = load(path, sources)
        for finding in report.get("findings", []):
            counts["candidate_reports"] += 1
            if finding.get("status") == "reproduced_candidate":
                counts["reproduced_candidates"] += 1
    return {field: counts[field] for field in ("candidate_reports", "reproduced_candidates")}


def summarize(arm, device_reports=(), pair_reports=(), analysis_reports=()):
    arm = Path(arm).resolve()
    sources = []
    run_config = config(arm / "config.txt", sources)
    afl = stats(arm / "afl/default/fuzzer_stats", sources)
    capture = load(arm / "afl/candidates/manifest.json", sources)
    preflight = load(arm / "candidate-preflight.json", sources)
    selected = capture.get("summary", {}).get("selected")
    checked = preflight.get("summary", {}).get("candidates")
    if selected != checked:
        raise ValueError(f"capture/preflight denominator mismatch: {selected} != {checked}")
    new_queue = capture["summary"].get("new_queue_entries")
    if new_queue is not None and (not isinstance(new_queue, int) or new_queue < selected):
        raise ValueError(f"invalid new queue denominator: {new_queue!r}")
    return {
        "schema_version": 1, "arm_dir": str(arm), "sources": sources,
        "afl_harness": {**{key: integer(afl.get(key), key) for key in
                           ("execs_done", "corpus_count", "saved_crashes", "saved_hangs")},
                        "crash_reporter_pipe": run_config.get("crash_reporter_pipe"),
                        "missing_crashes_override": run_config.get("missing_crashes_override")},
        "capture": {"new_queue_entries": new_queue,
                    "selected": selected,
                    "unselected": (new_queue - selected if new_queue is not None else None),
                    "preserved_live_exact": capture["summary"].get("preserved"),
                    "provenance_verified": capture["summary"].get(
                        "provenance_verified", capture["summary"].get("research_ready")),
                    "selection": capture.get("selection")},
        "offline_preflight": {"denominator": checked,
                              "capture_referenced": preflight["summary"].get("capture_referenced"),
                              "captured_exact_verified": preflight["summary"].get(
                                  "captured_exact_verified"),
                              "reconstructed_only": preflight["summary"].get("reconstructed_only"),
                              "zip": preflight["summary"].get("zip"),
                              "manifest": preflight["summary"].get("manifest"),
                              "signature": preflight["summary"].get("signature"),
                              "eligible_for_install_attempt": preflight["summary"].get(
                                  "eligible_for_install_attempt")},
        "android_device": device_counts(device_reports, sources),
        "matched_pairs": pair_counts(pair_reports, sources),
        "analysis": analysis_counts(analysis_reports, sources),
        "manually_confirmed_application_defects": None,
        "note": "null means no evidence supplied; AFL crashes and coverage concern the harness",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-dir", type=Path, required=True)
    parser.add_argument("--device-report", action="append", default=[])
    parser.add_argument("--pair-report", action="append", default=[])
    parser.add_argument("--analysis-results", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")
    try:
        report = summarize(args.arm_dir, args.device_report, args.pair_report,
                           args.analysis_results)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(args.output.resolve())


if __name__ == "__main__":
    main()
