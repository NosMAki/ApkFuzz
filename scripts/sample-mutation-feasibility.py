#!/usr/bin/env python3
"""Bounded exact-mutant validity and Android install sample across V2 variants."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(args, timeout=30, env=None):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None


def archive_status(path):
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            structure_ok = "AndroidManifest.xml" in names
            return structure_ok, structure_ok and archive.testzip() is None
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, ValueError, zlib.error):
        return False, False


def package_name(aapt, apk):
    result = command([str(aapt), "dump", "badging", str(apk)], timeout=30)
    if result is None or result.returncode != 0:
        return None
    match = re.search(r"^package: name='([^']+)'", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def device_status(serial, apk, package):
    base = ["adb", "-s", serial]
    command(base + ["uninstall", package], timeout=20)
    installed = command(base + ["install", "-r", "-t", str(apk)], timeout=45)
    if installed is None:
        return {"install": "timeout", "launch": "not_attempted"}
    if installed.returncode != 0 or "Success" not in installed.stdout:
        return {"install": "failed", "launch": "not_attempted"}
    try:
        launch = command(base + ["shell", "monkey", "-p", package,
                                 "-c", "android.intent.category.LAUNCHER", "1"], timeout=30)
        time.sleep(2)
        alive = command(base + ["shell", "pidof", package], timeout=10)
        status = ("process_alive" if launch is not None and launch.returncode == 0 and
                  alive is not None and bool(alive.stdout.strip()) else "not_observed")
        return {"install": "succeeded", "launch": status}
    finally:
        command(base + ["uninstall", package], timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, action="append", required=True)
    parser.add_argument("--driver", type=Path, default=Path("build/tests/mutator_driver"))
    parser.add_argument("--mutators", type=Path, default=Path("build/mutators"))
    parser.add_argument("--aapt", type=Path,
                        default=Path("/home/sahar/android-sdk/build-tools/34.0.0/aapt"))
    parser.add_argument("--apksigner", type=Path,
                        default=Path("/home/sahar/android-sdk/build-tools/34.0.0/apksigner"))
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--seed", type=int, default=5)
    parser.add_argument("--serial")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10:
        parser.error("rounds must be from 1 to 10")
    variants = sorted(args.mutators.resolve().glob("cm-ApkVulFuzz2-*.so"))
    if not variants:
        parser.error("no built V2 variants found")
    for path in [args.driver, args.aapt, args.apksigner, *args.apk]:
        if not path.is_file():
            parser.error(f"missing input: {path}")
    if args.output_dir.exists():
        parser.error("output directory already exists")
    output = args.output_dir.resolve()
    output.mkdir(parents=True)
    report = {"schema_version": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "rounds_per_variant_and_app": args.rounds, "seed": args.seed,
              "mutator_variants": len(variants), "device_serial": args.serial,
              "driver_sha256": sha256(args.driver),
              "variant_sha256": {v.stem: sha256(v) for v in variants},
              "aapt_path": str(args.aapt.resolve()),
              "apksigner_path": str(args.apksigner.resolve()),
              "original_controls": [],
              "samples": []}
    if args.serial:
        fingerprint = command(["adb", "-s", args.serial, "shell", "getprop",
                               "ro.build.fingerprint"], timeout=15)
        report["android_fingerprint"] = fingerprint.stdout.strip() if fingerprint else None
    report_path = output / "feasibility.json"

    def save():
        report["updated_utc"] = datetime.now(timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save()
    for apk in args.apk:
        source = apk.resolve()
        source_hash = sha256(source)
        package = package_name(args.aapt, source)
        if args.serial and package:
            report["original_controls"].append({"apk": str(source),
                                                "sha256": source_hash,
                                                **device_status(args.serial, source, package)})
            save()
        for variant in variants:
            name = variant.stem.removeprefix("cm-ApkVulFuzz2-")
            folder = output / source.stem / name
            folder.mkdir(parents=True)
            env = dict(os.environ, APKFUZZ_OUT_DIR=str(folder))
            run = command([str(args.driver.resolve()), str(variant), str(source),
                           str(args.rounds), str(args.seed)], timeout=60, env=env)
            (folder / "driver.txt").write_text(run.stdout if run else "timeout\n")
            for candidate in sorted(folder.glob("*.apk")):
                structure_ok, crc_ok = archive_status(candidate)
                parsed = command([str(args.aapt), "dump", "badging", str(candidate)], timeout=30)
                signed = command([str(args.apksigner), "verify", str(candidate)], timeout=30)
                candidate_hash = sha256(candidate)
                item = {"source_apk": str(source), "source_sha256": source_hash,
                        "variant": name, "exact_apk": str(candidate),
                        "exact_sha256": candidate_hash, "size": candidate.stat().st_size,
                        "mutant_differs": candidate_hash != source_hash,
                        "zip_structure_readable": structure_ok,
                        "zip_crc_valid": crc_ok,
                        "manifest_readable": parsed is not None and parsed.returncode == 0,
                        "signature_valid": signed is not None and signed.returncode == 0,
                        "install": "not_attempted", "launch": "not_attempted"}
                if args.serial and package:
                    item.update(device_status(args.serial, candidate, package))
                report["samples"].append(item)
                save()
    samples = report["samples"]
    report["summary"] = {"expected": len(args.apk) * len(variants) * args.rounds,
                         "generated": len(samples),
                         "mutant_differs": sum(x["mutant_differs"] for x in samples),
                         "zip_structure_readable": sum(x["zip_structure_readable"] for x in samples),
                         "zip_crc_valid": sum(x["zip_crc_valid"] for x in samples),
                         "manifest_readable": sum(x["manifest_readable"] for x in samples),
                         "signature_valid": sum(x["signature_valid"] for x in samples),
                         "install_attempted": sum(x["install"] != "not_attempted" for x in samples),
                         "install_succeeded": sum(x["install"] == "succeeded" for x in samples),
                         "launch_attempted": sum(x["launch"] != "not_attempted" for x in samples),
                         "launch_process_alive": sum(x["launch"] == "process_alive" for x in samples)}
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
