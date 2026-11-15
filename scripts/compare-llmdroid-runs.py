#!/usr/bin/env python3
"""Compare paired LLMDroid replay reports and write a conservative finding."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from llmdroid_runtime import first_divergence


def load_run(path, role):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if (report.get("schema_version") != 1 or report.get("role") != role or
            not isinstance(report.get("steps"), list) or
            report.get("status") not in {"completed", "inconclusive", "failed", "watchdog_timeout"} or
            not isinstance(report.get("trace_sha256"), str) or
            not isinstance(report.get("apk_sha256"), str)):
        raise ValueError(f"invalid {role} replay report")
    for index, step in enumerate(report["steps"]):
        if not isinstance(step, dict) or step.get("index") != index:
            raise ValueError(f"{role} action sequence is not ordered at {index}")
    return report


def compare(baseline, mutant):
    if baseline["trace_sha256"] != mutant["trace_sha256"]:
        raise ValueError("paired runs used different action traces")
    divergence = first_divergence(baseline["steps"], mutant["steps"])
    if divergence is None:
        if baseline.get("status") == mutant.get("status") == "completed":
            status, classification = "no_divergence_observed", None
        else:
            status, classification = "inconclusive", "incomplete_execution"
    else:
        classification = divergence["classification"]
        status = "inconclusive" if classification.startswith(("inconclusive", "synchronization")) \
            else "defect_candidate"
    if (divergence is not None and
            not classification.startswith(("inconclusive", "synchronization")) and
            baseline["apk_sha256"] == mutant["apk_sha256"]):
        status, classification = "inconclusive", "identical_apk_divergence"
    elif (divergence is not None and classification != "crash_candidate" and
          not classification.startswith(("inconclusive", "synchronization")) and
          (baseline.get("status") != "completed" or mutant.get("status") != "completed")):
        status, classification = "inconclusive", "incomplete_execution"
    if (baseline.get("status") in {"failed", "watchdog_timeout"} or
            mutant.get("status") in {"failed", "watchdog_timeout"}):
        status = "inconclusive"
        classification = "infrastructure_failure"
    return {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "classification": classification,
        "first_divergence": divergence,
        "trace_sha256": baseline["trace_sha256"],
        "baseline_apk_sha256": baseline["apk_sha256"],
        "mutant_apk_sha256": mutant["apk_sha256"],
        "baseline_steps": len(baseline["steps"]),
        "mutant_steps": len(mutant["steps"]),
        "baseline_run_status": baseline.get("status"),
        "mutant_run_status": mutant.get("status"),
        "reproductions": 0,
        "confirmed_defect": False,
        "confirmed_security_vulnerability": False,
    }


def render(result):
    lines = ["# LLMDroid paired replay comparison", "",
             f"Status: **{result['status']}**", "",
             f"Classification: `{result['classification'] or 'none'}`", "",
             f"Baseline APK SHA-256: `{result['baseline_apk_sha256']}`", "",
             f"Mutant APK SHA-256: `{result['mutant_apk_sha256']}`", "",
             f"Shared trace SHA-256: `{result['trace_sha256']}`", "",
             f"Actions compared: {min(result['baseline_steps'], result['mutant_steps'])}", ""]
    divergence = result["first_divergence"]
    if divergence:
        lines.extend([f"First divergence: action {divergence['index']}", ""])
        for role in ("baseline", "mutant"):
            step = divergence.get(role)
            if isinstance(step, dict):
                lines.extend([f"{role.title()} outcome: `{step.get('status', 'unknown')}`; "
                              f"activity: `{step.get('activity', 'unknown')}`", ""])
    lines.extend(["This is an automated comparison of recorded outcomes. "
                  "A candidate requires repeated reproduction and manual validation "
                  "before it can be called a confirmed defect or security vulnerability.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--mutant", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error(f"output directory already exists: {args.output_dir}")
    try:
        baseline = load_run(args.baseline, "baseline")
        mutant = load_run(args.mutant, "mutant")
        result = compare(baseline, mutant)
        result["baseline_report"] = str(args.baseline.resolve())
        result["mutant_report"] = str(args.mutant.resolve())
        args.output_dir.mkdir(parents=True)
        (args.output_dir / "finding.json").write_text(json.dumps(result, indent=2) + "\n")
        (args.output_dir / "report.md").write_text(render(result))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"{result['status']}: {args.output_dir / 'finding.json'}")


if __name__ == "__main__":
    sys.exit(main())
