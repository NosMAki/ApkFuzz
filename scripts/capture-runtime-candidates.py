#!/usr/bin/env python3
"""Preserve selected live AFL queue mutants before tmpfs scratch is removed.

This is an optional, post-run step. It never reconstructs an absent live APK and
never treats a patch as proof of the bytes AFL actually tested.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import random
import os
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT = Path(__file__).with_name("inspect-runtime-candidates.py")
spec = importlib.util.spec_from_file_location("apkfuzz_preflight", PREFLIGHT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def copy_stable(source, target):
    """Copy a small evidence file, rejecting a source that changed mid-copy."""
    digest = hashlib.sha256()
    created = False
    try:
        with open(source, "rb") as src, open(target, "xb") as dst:
            created = True
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if preflight.sha256_file(source) != digest.hexdigest():
            raise ValueError(f"source changed during copy: {source}")
        return digest.hexdigest()
    except (OSError, ValueError):
        if created:
            target.unlink(missing_ok=True)
        raise


def preserve_apk(source, apk_dir):
    """Store the live APK under its hash, after checking both source and copy."""
    digest = hashlib.sha256()
    size = 0
    with tempfile.NamedTemporaryFile(dir=apk_dir, prefix=".partial-", suffix=".apk",
                                     delete=False) as target:
        temporary = Path(target.name)
        try:
            with open(source, "rb") as live:
                for chunk in iter(lambda: live.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
                    target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
    sha256 = digest.hexdigest()
    try:
        if preflight.sha256_file(source) != sha256:
            raise ValueError("live APK changed during capture")
        if preflight.sha256_file(temporary) != sha256:
            raise ValueError("stored APK differs from captured bytes")
        stored = apk_dir / f"{sha256}.apk"
        if stored.exists():
            if preflight.sha256_file(stored) != sha256:
                raise ValueError(f"content-addressed artifact differs: {stored}")
        else:
            os.replace(temporary, stored)
        return sha256, size, stored
    finally:
        temporary.unlink(missing_ok=True)


def copy_patch_chain(patch_path, evidence_dir):
    """Keep the child and all named parent patches in one reconstructable folder."""
    current = Path(patch_path)
    seen = set()
    saved = []
    for _ in range(64):
        current = current.absolute()
        if current in seen:
            raise ValueError("patch parent cycle")
        seen.add(current)
        name = current.name
        if name in ("", ".", ".."):
            raise ValueError("invalid patch filename")
        target = evidence_dir / name
        digest = copy_stable(current, target)
        version, meta, _ = preflight.patch_tool.read_patch(target)
        saved.append({"path": str(target), "sha256": digest})
        parent = meta.get("parent")
        if not parent:
            return evidence_dir / Path(patch_path).name, saved
        if version != "v2" or Path(parent).name != parent or parent in (".", ".."):
            raise ValueError("invalid parent patch reference")
        current = current.parent / parent
    raise ValueError("patch chain exceeds 64 generations")


def read_meta(path):
    values = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(" ")
        if key in ("origin", "gen") and value:
            values[key] = value
    return values


def queue_rows(index, requested, limit, sample_seed=None):
    with open(index, newline="") as source:
        rows = [row for row in csv.DictReader(source, delimiter="\t")
                if "src:" in row.get("queue_entry", "")]
    rows.sort(key=lambda row: row["queue_entry"])
    if requested:
        known = {row["queue_entry"] for row in rows}
        missing = set(requested) - known
        if missing:
            raise ValueError(f"queue entries not found: {', '.join(sorted(missing))}")
        rows = [row for row in rows if row["queue_entry"] in requested]
        if len(rows) > limit:
            raise ValueError("requested queue entries exceed --limit")
    if sample_seed is not None and not requested and len(rows) > limit:
        rows = random.Random(sample_seed).sample(rows, limit)
        rows.sort(key=lambda row: row["queue_entry"])
    return rows[:limit]


def new_queue_count(index):
    with open(index, newline="") as source:
        return sum("src:" in row.get("queue_entry", "")
                   for row in csv.DictReader(source, delimiter="\t"))


def run_metadata(mutator, fuzzer_stats):
    details = {"mutator_path": None, "mutator_sha256": None,
               "fuzzer_stats_path": None, "stored_fuzzer_stats": None,
               "fuzzer_stats_sha256": None, "afl_version": None,
               "source_sha256": {
                   "capture": preflight.sha256_file(__file__),
                   "preflight": preflight.sha256_file(PREFLIGHT),
                   "patch_reconstruction": preflight.sha256_file(preflight.PATCH_TOOL)}}
    if mutator:
        path = Path(mutator).absolute()
        details.update(mutator_path=str(path), mutator_sha256=preflight.sha256_file(path))
    if fuzzer_stats:
        path = Path(fuzzer_stats).absolute()
        details["fuzzer_stats_path"] = str(path)
        with path.open() as source:
            for line in source:
                key, _, value = line.partition(":")
                if key.strip() == "afl_version":
                    details["afl_version"] = value.strip()
                    break
    return details


def capture_one(row, ordinal, output_dir, known_hashes):
    live = Path(row.get("apk_path", "")) if row.get("apk_path") else None
    patch = Path(row.get("patch_path", "")) if row.get("patch_path") else None
    result = {
        "queue_entry": row["queue_entry"], "live_apk_path": str(live) if live else None,
        "patch_path": str(patch) if patch else None, "stored_apk": None,
        "mutant_sha256": None, "mutant_size": None, "patch_chain": [],
        "patch_reconstruction_match": "unavailable", "mode": None,
        "seed": None, "iteration": None, "generation": None,
        "origin_path": None, "origin_sha256": None,
        "expected_origin_sha256": None, "meta_sidecar": None,
        "preserved": False, "research_ready": False, "reasons": [],
    }
    reasons = result["reasons"]
    if live and live.is_file():
        try:
            digest, size, stored = preserve_apk(live, output_dir / "apks")
            result.update(stored_apk=str(stored.relative_to(output_dir)),
                          mutant_sha256=digest, mutant_size=size, preserved=True)
        except (OSError, ValueError) as exc:
            reasons.append("live_capture_failed")
            result["capture_error"] = str(exc)[:300]
    else:
        reasons.append("live_apk_missing")

    sidecar = Path(str(live) + ".meta") if live else None
    sidecar_meta = {}
    if sidecar and sidecar.is_file():
        try:
            target = output_dir / "evidence" / f"{ordinal:04d}" / "mutant.meta"
            target.parent.mkdir(parents=True, exist_ok=True)
            sidecar_sha = copy_stable(sidecar, target)
            sidecar_meta = read_meta(target)
            result["meta_sidecar"] = {"path": str(target.relative_to(output_dir)),
                                      "sha256": sidecar_sha, "values": sidecar_meta}
        except (OSError, ValueError) as exc:
            reasons.append("meta_unreadable")
            result["meta_error"] = str(exc)[:300]

    patch_meta = {}
    if patch and patch.is_file():
        try:
            folder = output_dir / "evidence" / f"{ordinal:04d}"
            folder.mkdir(parents=True, exist_ok=True)
            child, saved = copy_patch_chain(patch, folder)
            result["patch_chain"] = [
                {"path": str(Path(p["path"]).relative_to(output_dir)), "sha256": p["sha256"]}
                for p in saved
            ]
            _, patch_meta, _ = preflight.patch_tool.read_patch(child)
            result.update(mode=patch_meta.get("mode"), seed=patch_meta.get("seed"),
                          iteration=patch_meta.get("iter"), generation=patch_meta.get("gen"))
            if result["preserved"]:
                rebuilt, _, _ = preflight.patch_tool.reconstruct(str(child), None, True)
                result["patch_reconstruction_match"] = (
                    "match" if hashlib.sha256(rebuilt).hexdigest() == result["mutant_sha256"]
                    else "mismatch"
                )
                if result["patch_reconstruction_match"] == "mismatch":
                    reasons.append("patch_live_mismatch")
        except (OSError, ValueError) as exc:
            reasons.append("patch_evidence_failed")
            result["patch_error"] = str(exc)[:300]
    else:
        reasons.append("patch_missing")

    patch_origin = patch_meta.get("origin")
    meta_origin = sidecar_meta.get("origin")
    if patch_origin and meta_origin and Path(patch_origin).resolve() != Path(meta_origin).resolve():
        reasons.append("origin_conflict")
    if patch_meta.get("gen") and sidecar_meta.get("gen") and patch_meta["gen"] != sidecar_meta["gen"]:
        reasons.append("generation_conflict")
    origin = patch_origin or meta_origin
    result["origin_path"] = origin
    if origin and Path(origin).is_file():
        try:
            result["origin_sha256"] = preflight.sha256_file(origin)
            expected = known_hashes.get(Path(origin).name)
            result["expected_origin_sha256"] = expected
            if expected is None:
                reasons.append("origin_hash_unrecorded")
            elif expected != result["origin_sha256"]:
                reasons.append("origin_hash_mismatch")
        except OSError as exc:
            reasons.append("origin_unreadable")
            result["origin_error"] = str(exc)[:300]
    else:
        reasons.append("origin_missing" if origin else "origin_unknown")
    result["research_ready"] = result["preserved"] and not reasons
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue-index", required=True)
    parser.add_argument("--output-dir", required=True, help="new directory for APKs and manifest")
    parser.add_argument("--corpus-csv", default=str(ROOT / "Evaluation-SSBSE-2026/corpus.csv"))
    parser.add_argument("--mutator", help="mutator library used for this run")
    parser.add_argument("--fuzzer-stats", help="AFL++ fuzzer_stats file for this run")
    parser.add_argument("--limit", type=int, default=10,
                        help="maximum mutant queue entries, in queue order (default: 10)")
    parser.add_argument("--sample-seed", type=int,
                        help="deterministically sample across the queue instead of taking its first entries")
    parser.add_argument("--queue-entry", action="append", default=[],
                        help="capture only this exact queue entry (repeatable)")
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be positive")
    output = Path(args.output_dir).absolute()
    if output.exists():
        parser.error(f"output directory already exists: {output}")
    try:
        hashes = preflight.corpus_hashes(args.corpus_csv)
        context = run_metadata(args.mutator, args.fuzzer_stats)
        rows = queue_rows(args.queue_index, set(args.queue_entry), args.limit,
                          args.sample_seed)
        pool_size = new_queue_count(args.queue_index)
        output.mkdir(parents=True)
        (output / "apks").mkdir()
        index_sha = copy_stable(Path(args.queue_index), output / "queue-index.tsv")
        if args.fuzzer_stats:
            context["fuzzer_stats_sha256"] = copy_stable(
                Path(args.fuzzer_stats), output / "fuzzer_stats")
            context["stored_fuzzer_stats"] = "fuzzer_stats"
        results = [capture_one(row, ordinal, output, hashes)
                   for ordinal, row in enumerate(rows, 1)]
        report = {
            "schema_version": 1, "captured_utc": datetime.now(timezone.utc).isoformat(),
            "source_queue_index": str(Path(args.queue_index).absolute()),
            "stored_queue_index_sha256": index_sha,
            "corpus_csv": str(Path(args.corpus_csv).absolute()),
            "corpus_csv_sha256": preflight.sha256_file(args.corpus_csv),
            "run": context,
            "selection": {"limit": args.limit, "queue_entries": args.queue_entry,
                          "sample_seed": args.sample_seed,
                          "method": ("explicit_queue_entries" if args.queue_entry else
                                     "seeded_random_sample" if args.sample_seed is not None
                                     and pool_size > args.limit else "queue_order"),
                          "new_queue_entries": pool_size},
            "summary": {"new_queue_entries": pool_size,
                        "selected": len(results),
                        "unselected": pool_size - len(results),
                        "preserved": sum(item["preserved"] for item in results),
                        "provenance_verified": sum(item["research_ready"] for item in results),
                        "research_ready": sum(item["research_ready"] for item in results),
                        "reasons": dict(Counter(reason for item in results for reason in item["reasons"]))},
            "candidates": results,
        }
        with (output / "manifest.json").open("x", encoding="utf-8") as target:
            json.dump(report, target, indent=2)
            target.write("\n")
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(report["summary"], sort_keys=True))
    print(f"manifest: {output / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
