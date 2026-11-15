#!/usr/bin/env python3
"""Verify sampled live APK lineage and screen signed Android derivatives offline."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import tempfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load_module("live_preflight", ROOT / "scripts/inspect-runtime-candidates.py")
prepare = load_module("live_prepare", ROOT / "scripts/prepare-manifest-runtime-candidate.py")


def digest(path):
    return preflight.sha256_file(path)


def validate_patch_chain(path, layout):
    count = 0
    seen = set()
    current = path
    while current:
        if current in seen or len(seen) > 64:
            raise ValueError("patch parent cycle")
        seen.add(current)
        _, meta, changes = preflight.patch_tool.read_patch(str(current))
        mode = meta.get("mode")
        compressed = [(off, old, new) for off, old, new in changes
                      if layout["data_start"] <= off < layout["data_end"]]
        crc_offsets = (set(range(layout["local_crc_offset"],
                                 layout["local_crc_offset"] + 4)) |
                       set(range(layout["central_crc_offset"],
                                 layout["central_crc_offset"] + 4)))
        if (len(compressed) != 1 or
                (compressed[0][1] ^ compressed[0][2]).bit_count() != 1):
            raise ValueError("expected one compressed-manifest bit edit")
        if mode == "manifest-bitflip":
            if len(changes) != 1:
                raise ValueError("unexpected legacy manifest edit count")
        elif mode in prepare.VALID_MANIFEST_MODES:
            if (not 3 <= len(changes) <= 9 or
                    any(off not in crc_offsets and not
                        layout["data_start"] <= off < layout["data_end"]
                        for off, _, _ in changes)):
                raise ValueError("valid mode edited bytes outside manifest and CRC fields")
        else:
            raise ValueError("unexpected mutation mode")
        count += 1
        parent = meta.get("parent")
        current = current.parent / parent if parent else None
    return count


def raw_zip_status(path):
    try:
        with zipfile.ZipFile(path) as archive:
            bad = archive.testzip()
        return "valid" if bad is None else "bad_entry"
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, EOFError, zlib.error):
        return "invalid"


def analyze_one(source_row, output, original, original_manifest, baseline,
                baseline_package, key, cert, aapt, apksigner):
    row = {"iteration": source_row["iteration"],
           "generation": source_row["generation"],
           "exact_apk": source_row["stored_apk"],
           "exact_sha256": source_row["mutant_sha256"],
           "patch": source_row["patch_path"],
           "patch_sha256": source_row["patch_sha256"],
           "lineage": "unchecked", "raw_zip": "not_checked",
           "repair": "not_checked", "aapt": "not_checked",
           "sign": "not_checked", "signature": "not_checked",
           "pair": "not_checked", "admission": "blocked"}
    try:
        exact_path = Path(source_row["stored_apk"])
        patch_path = Path(source_row["patch_path"])
        if (digest(exact_path) != source_row["mutant_sha256"] or
                digest(patch_path) != source_row["patch_sha256"]):
            raise ValueError("stored exact APK or patch hash mismatch")
        exact = exact_path.read_bytes()
        reconstructed, meta, generation = preflight.patch_tool.reconstruct(
            str(patch_path), None, True)
        if (bytes(reconstructed) != exact or generation != source_row["generation"] or
                Path(meta["origin"]).resolve() != original.resolve()):
            raise ValueError("saved patch does not reconstruct captured bytes")
        layout = prepare.manifest_layout(exact)
        if validate_patch_chain(patch_path, layout) != generation:
            raise ValueError("patch chain length differs from generation")
        row["lineage"] = "verified"
        row["mode"] = meta.get("mode")
    except (OSError, ValueError, KeyError) as exc:
        row["lineage"] = "failed"
        row["reason"] = type(exc).__name__
        return row
    row["raw_zip"] = raw_zip_status(exact_path)
    try:
        mutated_manifest = prepare.manifest_bytes(exact, layout)
        if mutated_manifest == original_manifest:
            raise ValueError("mutation did not change manifest content")
        if row["raw_zip"] == "valid":
            repaired, changes = exact, []
            row["repair"] = "not_needed"
        else:
            repaired, _, changes = prepare.repair_crc(exact, layout)
            row["repair"] = "valid"
        row["crc_changed_bytes"] = len(changes)
    except ValueError as exc:
        row["repair"] = "blocked"
        row["reason"] = type(exc).__name__
        return row
    structure = preflight.axml.structure_error(mutated_manifest)
    row["structure"] = structure or "valid"
    if structure:
        return row
    with tempfile.TemporaryDirectory(prefix="apkfuzz-live-prepare-") as scratch:
        repaired_path = Path(scratch) / "repaired.apk"
        signed_path = Path(scratch) / "signed.apk"
        repaired_path.write_bytes(repaired)
        try:
            if prepare.zip_valid(repaired_path) != mutated_manifest:
                raise ValueError("CRC repair changed manifest")
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            row["repair"] = "blocked"
            row["reason"] = type(exc).__name__
            return row
        try:
            prepared_metadata = prepare.run_ok(
                [aapt, "dump", "badging", str(repaired_path)], 20).stdout
            if "package: name='" not in prepared_metadata:
                raise ValueError("package metadata missing")
            row["aapt"] = "valid"
        except ValueError as exc:
            row["aapt"] = "invalid"
            row["bad_xml_warning"] = preflight.aapt_resource_warning(str(exc))
            return row
        try:
            prepare.run_ok([apksigner, "sign", "--key", str(key), "--cert",
                            str(cert), "--out", str(signed_path),
                            str(repaired_path)], 30)
            row["sign"] = "valid"
        except ValueError as exc:
            row["sign"] = "invalid"
            row["sign_error_type"] = "MinSdkVersionException" if "MinSdkVersionException" in str(exc) else "other"
            return row
        try:
            prepare.run_ok([apksigner, "verify", str(signed_path)], 20)
            if prepare.zip_valid(signed_path) != mutated_manifest:
                raise ValueError("signed manifest changed")
            signed_metadata = prepare.run_ok(
                [aapt, "dump", "badging", str(signed_path)], 20).stdout
            if signed_metadata.partition("\n")[0] != prepared_metadata.partition("\n")[0]:
                raise ValueError("signed package metadata changed")
            row["signature"] = "valid"
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            row["signature"] = "invalid"
            row["reason"] = type(exc).__name__
            return row
        try:
            if signed_metadata.partition("\n")[0] != baseline_package:
                raise ValueError("baseline and mutant package metadata differ")
            row["other_payload_entries_unchanged"] = (
                prepare.shared_payload_unchanged(baseline, signed_path))
            row["pair"] = "valid"
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            row["pair"] = "invalid"
            row["reason"] = type(exc).__name__
            return row
        destination = output / "prepared" / f"iter-{row['iteration']:09d}-g{generation}.apk"
        shutil.copyfile(signed_path, destination)
        row["prepared_apk"] = str(destination)
        row["prepared_sha256"] = digest(destination)
        row["mutated_manifest_sha256"] = hashlib.sha256(mutated_manifest).hexdigest()
        row["admission"] = "ready_for_install_attempt"
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("output directory already exists")
    sample_summary = json.loads((args.sample_dir / "summary.json").read_text())
    if not sample_summary.get("stopped_by_file"):
        parser.error("live sampler did not stop after arm completion")
    samples = [json.loads(line) for line in
               (args.sample_dir / "captures.jsonl").read_text().splitlines()]
    if len(samples) != sample_summary["counts"].get("selected", 0):
        parser.error("sampler row count mismatch")
    original = ROOT / "Evaluation-SSBSE-2026/apk/F-Droid.apk"
    key = ROOT / "results/llmdroid-positive-control-2026-10-21/signing/key.pk8"
    cert = ROOT / "results/llmdroid-positive-control-2026-10-21/signing/cert.pem"
    aapt = preflight.find_aapt()
    apksigner = shutil.which("apksigner")
    if not all((original.is_file(), key.is_file(), cert.is_file(), aapt, apksigner)):
        parser.error("original APK, test signing material, or Android SDK tools missing")
    original_manifest = prepare.zip_valid(original)
    args.output_dir.mkdir(parents=True)
    (args.output_dir / "prepared").mkdir()
    baseline = args.output_dir / "prepared-baseline.apk"
    prepare.run_ok([apksigner, "sign", "--key", str(key), "--cert", str(cert),
                    "--out", str(baseline), str(original)], 30)
    prepare.run_ok([apksigner, "verify", str(baseline)], 20)
    if prepare.zip_valid(baseline) != original_manifest:
        raise ValueError("baseline signing changed original manifest")
    baseline_package = prepare.run_ok(
        [aapt, "dump", "badging", str(baseline)], 20).stdout.partition("\n")[0]
    rows = []
    for index, sample in enumerate(samples, 1):
        if sample["status"] == "captured":
            rows.append(analyze_one(sample, args.output_dir, original,
                                    original_manifest, baseline, baseline_package,
                                    key, cert, aapt, apksigner))
        else:
            rows.append({"iteration": sample["iteration"],
                         "generation": sample["generation"],
                         "lineage": sample["status"], "admission": "blocked"})
        if index % 25 == 0:
            print(f"analyzed {index}/{len(samples)} live selections", flush=True)
    stages = ("lineage", "raw_zip", "repair", "structure", "aapt", "sign", "signature", "pair",
              "admission")
    report = {"schema_version": 1,
              "generated_utc": datetime.now(timezone.utc).isoformat(),
              "sample_summary": str(args.sample_dir / "summary.json"),
              "sample_summary_sha256": digest(args.sample_dir / "summary.json"),
              "sample_rows_sha256": digest(args.sample_dir / "captures.jsonl"),
              "original_apk_sha256": digest(original),
              "baseline_apk": str(baseline), "baseline_sha256": digest(baseline),
              "tools": {"aapt": aapt, "apksigner": apksigner},
              "source_sha256": {"analysis": digest(Path(__file__)),
                                "preparation": digest(ROOT / "scripts/prepare-manifest-runtime-candidate.py"),
                                "patch_reconstruction": digest(ROOT / "scripts/apply-patch.py")},
              "summary": {stage: dict(Counter(row.get(stage, "not_checked") for row in rows))
                          for stage in stages},
              "candidates": rows}
    (args.output_dir / "analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
