#!/usr/bin/env python3
"""Read-only-to-campaign preflight for APKVulFuzz patch candidates.

The only persistent output is the new JSON report. Mutants are reconstructed in
a temporary directory for ZIP, manifest and signature checks, then discarded.
An eligible result means "worth an install attempt", not "installs".
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PATCH_TOOL = Path(__file__).with_name("apply-patch.py")
V2_EDIT_CAPACITY = 256  # src/custom_mutators/v2/strategies.h
spec = importlib.util.spec_from_file_location("apkfuzz_apply_patch", PATCH_TOOL)
patch_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_tool)
spec = importlib.util.spec_from_file_location(
    "apkfuzz_android_binary_xml", Path(__file__).with_name("android_binary_xml.py"))
axml = importlib.util.module_from_spec(spec)
spec.loader.exec_module(axml)
# aapt exits 0 after its resource parser rejects part of a manifest; Android
# refused every such APK in results/gen1-device-admission-2026-11-15.
AAPT_RESOURCE_WARNING = re.compile(r"Bad XML block|ResourceType\s+[WE]\b|[WE]/ResourceType")


def aapt_resource_warning(text):
    return bool(AAPT_RESOURCE_WARNING.search(text or ""))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def corpus_hashes(path):
    result = {}
    with open(path, newline="") as source:
        for row in csv.DictReader(source):
            name = Path(row["filename"]).name
            digest = row["sha256"].lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"invalid SHA-256 for {name} in {path}")
            if name in result and result[name] != digest:
                raise ValueError(f"conflicting SHA-256 entries for {name} in {path}")
            result[name] = digest
    return result


def candidates_from_inputs(patches, queue_indexes, capture_manifests=()):
    selected = {}

    def get_item(key, patch):
        return selected.setdefault(key, {"patch": patch, "queue_refs": [],
                                         "capture_refs": [], "live_apk_paths": [],
                                         "expected_live_hashes": {},
                                         "expected_origin_hashes": [],
                                         "capture_errors": []})

    for patch in patches:
        key = str(Path(patch).absolute())
        get_item(key, key)
    for index in queue_indexes:
        with open(index, newline="") as source:
            for row in csv.DictReader(source, delimiter="\t"):
                patch = row.get("patch_path", "")
                entry = row.get("queue_entry", "")
                if not patch and "src:" not in entry:
                    continue  # the original AFL seed has no mutant patch
                key = (str(Path(patch).absolute()) if patch else
                       f"missing:{Path(index).absolute()}:{entry}")
                item = get_item(key, str(Path(patch).absolute()) if patch else None)
                item["queue_refs"].append({"index": str(Path(index).absolute()),
                                           "entry": entry})
                if row.get("apk_path"):
                    item["live_apk_paths"].append(row["apk_path"])

    for manifest in capture_manifests:
        manifest_path = Path(manifest).absolute()
        base = manifest_path.parent
        with manifest_path.open(encoding="utf-8") as source:
            report = json.load(source)
        if report.get("schema_version") != 1:
            raise ValueError(f"unsupported capture manifest: {manifest_path}")

        def saved_path(relative):
            path = Path(relative)
            if path.is_absolute() or not path.parts or ".." in path.parts:
                raise ValueError(f"invalid stored path in {manifest_path}: {relative}")
            return str((base / path).absolute())

        for candidate in report.get("candidates", []):
            chain = candidate.get("patch_chain") or []
            patch = saved_path(chain[0]["path"]) if chain else None
            entry = candidate.get("queue_entry", "")
            key = patch or f"missing:{manifest_path}:{entry}"
            item = get_item(key, patch)
            item["capture_refs"].append({"manifest": str(manifest_path), "entry": entry})
            if not candidate.get("research_ready", False):
                item["capture_errors"].append("capture_not_research_ready")
            if candidate.get("origin_sha256"):
                item["expected_origin_hashes"].append(candidate["origin_sha256"])
            for evidence in chain:
                evidence_path = saved_path(evidence["path"])
                if not Path(evidence_path).is_file():
                    item["capture_errors"].append("captured_patch_missing")
                elif sha256_file(evidence_path) != evidence.get("sha256"):
                    item["capture_errors"].append("captured_patch_hash_mismatch")
            sidecar = candidate.get("meta_sidecar")
            if sidecar:
                sidecar_path = saved_path(sidecar["path"])
                if not Path(sidecar_path).is_file():
                    item["capture_errors"].append("captured_meta_missing")
                elif sha256_file(sidecar_path) != sidecar.get("sha256"):
                    item["capture_errors"].append("captured_meta_hash_mismatch")
            if candidate.get("stored_apk"):
                live = saved_path(candidate["stored_apk"])
                item["live_apk_paths"].append(live)
                if candidate.get("mutant_sha256"):
                    item["expected_live_hashes"][live] = candidate["mutant_sha256"]
    return [selected[key] for key in sorted(selected)]


def probe(argv, timeout):
    if not argv or not argv[0]:
        return {"status": "unavailable", "detail": "tool not found"}
    try:
        run = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                             timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": f"exceeded {timeout}s"}
    except OSError as exc:
        return {"status": "error", "detail": str(exc)[:300]}
    detail = (run.stderr or run.stdout).strip().replace("\n", " ")[:300]
    malformed_xml = (argv[1:3] == ["dump", "badging"] and
                     aapt_resource_warning(run.stderr + run.stdout))
    return {"status": "valid" if run.returncode == 0 and not malformed_xml else "invalid",
            "exit_code": run.returncode, "detail": detail}


def zip_check(path):
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if "AndroidManifest.xml" not in names:
                return {"status": "missing_manifest", "entries": len(names)}
            bad = archive.testzip()  # checks decompression and CRC of every entry
            if bad:
                return {"status": "bad_entry", "entry": bad, "entries": len(names)}
            return {"status": "valid", "entries": len(names)}
    except (OSError, RuntimeError, ValueError, zlib.error, zipfile.BadZipFile,
            zipfile.LargeZipFile, NotImplementedError) as exc:
        return {"status": "invalid", "detail": f"{type(exc).__name__}: {exc}"[:300]}


def inspect_candidate(item, known_hashes, apksigner, aapt, timeout):
    result = {"patch": item["patch"], "queue_refs": item["queue_refs"],
              "capture_refs": item.get("capture_refs", []),
              "mode": None, "seed": None, "iteration": None, "generation": None,
              "edit_count": None,
              "origin_path": None, "origin_sha256": None, "expected_origin_sha256": None,
              "mutant_sha256": None, "mutant_size": None, "live_apk_match": "unavailable",
              "capture_integrity": "unavailable",
              "zip": {"status": "not_checked"}, "manifest": {"status": "not_checked"},
              "signature": {"status": "not_checked"}, "preflight": "blocked",
              "reasons": list(dict.fromkeys(item.get("capture_errors", [])))}
    expected_live = item.get("expected_live_hashes", {})
    if expected_live:
        try:
            if any(not Path(path).is_file() for path in expected_live):
                result["capture_integrity"] = "missing"
                result["reasons"].append("captured_apk_missing")
            elif all(sha256_file(path) == digest for path, digest in expected_live.items()):
                result["capture_integrity"] = "match"
            else:
                result["capture_integrity"] = "mismatch"
                result["reasons"].append("capture_hash_mismatch")
        except OSError as exc:
            result["capture_integrity"] = "error"
            result["reasons"].append("captured_apk_unreadable")
            result["capture_error"] = str(exc)[:300]
    if not item["patch"]:
        result["reasons"].append("patch_missing")
        return result
    try:
        _, meta, edits = patch_tool.read_patch(item["patch"])
        result.update(mode=meta.get("mode"), seed=meta.get("seed"),
                      iteration=meta.get("iter"), generation=meta.get("gen"),
                      origin_path=meta.get("origin"), edit_count=len(edits))
    except (OSError, ValueError) as exc:
        result["reasons"].append("patch_unreadable")
        result["error"] = str(exc)[:300]
        return result

    origin = result["origin_path"]
    if not origin or not Path(origin).is_file():
        result["reasons"].append("origin_missing")
        return result
    origin = str(Path(origin).resolve())
    try:
        result["origin_sha256"] = sha256_file(origin)
    except OSError as exc:
        result["reasons"].append("origin_unreadable")
        result["error"] = str(exc)[:300]
        return result
    if any(digest != result["origin_sha256"]
           for digest in item.get("expected_origin_hashes", [])):
        result["reasons"].append("capture_origin_hash_mismatch")
    expected = known_hashes.get(Path(origin).name)
    result["expected_origin_sha256"] = expected
    if not expected:
        result["reasons"].append("origin_hash_unrecorded")
    elif expected != result["origin_sha256"]:
        result["reasons"].append("origin_hash_mismatch")
        return result

    try:
        mutant, _, _ = patch_tool.reconstruct(item["patch"], None, True)
    except (OSError, ValueError) as exc:
        result["reasons"].append("reconstruction_failed")
        result["error"] = str(exc)[:300]
        return result
    try:
        if sha256_file(origin) != result["origin_sha256"]:
            result["reasons"].append("origin_changed_during_inspection")
            return result
    except OSError as exc:
        result["reasons"].append("origin_unreadable")
        result["error"] = str(exc)[:300]
        return result
    result["mutant_sha256"] = hashlib.sha256(mutant).hexdigest()
    result["mutant_size"] = len(mutant)
    live = [Path(p) for p in item["live_apk_paths"] if Path(p).is_file()]
    if live:
        try:
            live_hashes = {str(p): sha256_file(p) for p in live}
            result["live_apk_match"] = "match" if all(
                digest == result["mutant_sha256"] for digest in live_hashes.values()) else "mismatch"
            if result["live_apk_match"] == "mismatch":
                result["reasons"].append("live_apk_mismatch")
        except OSError as exc:
            result["live_apk_match"] = "error"
            result["reasons"].append("live_apk_unreadable")
            result["live_error"] = str(exc)[:300]
    elif result["edit_count"] >= V2_EDIT_CAPACITY:
        # V2 stores at most 256 changed byte offsets, without an overflow marker.
        result["reasons"].append("edit_capacity_reached_unverified")

    with tempfile.TemporaryDirectory(prefix="apkfuzz-preflight-") as scratch:
        apk = Path(scratch) / "candidate.apk"
        apk.write_bytes(mutant)
        del mutant
        result["zip"] = zip_check(apk)
        if result["zip"]["status"] == "valid":
            result["manifest"] = probe([aapt, "dump", "badging", str(apk)], timeout)
            if result["manifest"]["status"] == "valid":
                structure = axml.apk_structure_error(apk)
                result["manifest"]["structure"] = structure or "valid"
                if structure:
                    result["manifest"]["status"] = "invalid"
                    result["manifest"]["detail"] = f"binary XML structure: {structure}"
        result["signature"] = probe([apksigner, "verify", str(apk)], timeout)

    if result["zip"]["status"] != "valid":
        result["reasons"].append("zip_invalid")
    if result["manifest"]["status"] != "valid":
        result["reasons"].append("manifest_unverified")
    if result["signature"]["status"] != "valid":
        result["reasons"].append("signature_invalid_or_unverified")
    if not result["reasons"]:
        result["preflight"] = "eligible_for_install_attempt"
    return result


def stage_summary(results, name):
    statuses = Counter(result[name]["status"] for result in results)
    return {"valid": statuses.get("valid", 0),
            "checked": sum(count for status, count in statuses.items()
                           if status not in ("not_checked", "unavailable")),
            "statuses": dict(statuses)}


def find_aapt():
    found = shutil.which("aapt")
    if found:
        return found
    for root in (os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"),
                 str(Path.home() / "android-sdk")):
        if root:
            tools = sorted((Path(root) / "build-tools").glob("*/aapt"), reverse=True)
            if tools:
                return str(tools[0])
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch", action="append", default=[], help="saved .apk.patch (repeatable)")
    parser.add_argument("--queue-index", action="append", default=[], help="queue-index.tsv (repeatable)")
    parser.add_argument("--capture-manifest", action="append", default=[],
                        help="candidate capture manifest.json (repeatable)")
    parser.add_argument("--corpus-csv", default=str(ROOT / "Evaluation-SSBSE-2026/corpus.csv"))
    parser.add_argument("--apksigner", default=shutil.which("apksigner"))
    parser.add_argument("--aapt", default=find_aapt())
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", required=True, help="new JSON report path; existing files are not overwritten")
    args = parser.parse_args(argv)
    if not args.patch and not args.queue_index and not args.capture_manifest:
        parser.error("provide --patch, --queue-index, or --capture-manifest")
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    try:
        known_hashes = corpus_hashes(args.corpus_csv)
        items = candidates_from_inputs(args.patch, args.queue_index, args.capture_manifest)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    results = [inspect_candidate(item, known_hashes, args.apksigner, args.aapt,
                                 args.timeout) for item in items]
    report = {
        "schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
        "corpus_csv": str(Path(args.corpus_csv).absolute()),
        "tools": {"apksigner": args.apksigner, "aapt": args.aapt},
        "tool_versions": {"apksigner": probe([args.apksigner, "--version"], args.timeout),
                          "aapt": probe([args.aapt, "version"], args.timeout)},
        "source_sha256": {"preflight": sha256_file(__file__),
                          "patch_reconstruction": sha256_file(PATCH_TOOL)},
        "summary": {"candidates": len(results),
                    "capture_referenced": sum(bool(r["capture_refs"]) for r in results),
                    "captured_exact_verified": sum(
                        bool(r["capture_refs"]) and r["capture_integrity"] == "match"
                        and r["live_apk_match"] == "match" for r in results),
                    "reconstructed_only": sum(not r["capture_refs"] and
                                              r["mutant_sha256"] is not None and
                                              r["live_apk_match"] == "unavailable"
                                              for r in results),
                    "zip": stage_summary(results, "zip"),
                    "manifest": stage_summary(results, "manifest"),
                    "signature": stage_summary(results, "signature"),
                    "eligible_for_install_attempt": sum(
                        r["preflight"] == "eligible_for_install_attempt" for r in results),
                    "preflight": dict(Counter(r["preflight"] for r in results)),
                    "reasons": dict(Counter(reason for r in results for reason in r["reasons"]))},
        "candidates": results,
    }
    try:
        with open(args.output, "x", encoding="utf-8") as target:
            json.dump(report, target, indent=2)
            target.write("\n")
    except OSError as exc:
        parser.error(str(exc))
    print(json.dumps(report["summary"], sort_keys=True))
    print(f"report: {Path(args.output).absolute()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
