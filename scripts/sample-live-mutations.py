#!/usr/bin/env python3
"""Preserve a deterministic, bounded sample of live mutator outputs.

Reads the append-only mutator log while AFL runs. Each sampled APK is copied
from the scratch file after the mutator logged its completed write. This is a
separate observation cohort from AFL's saved queue entries.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


FIELDS = re.compile(r"(?:^| )([a-z_]+)=([^ \r\n]+)")
MAX_APK_BYTES = 30 * 1024 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def selected(seed, iteration, generation, rate):
    value = hashlib.blake2s(f"{seed}:{generation}:{iteration}".encode(),
                            digest_size=8).digest()
    return int.from_bytes(value, "big") < (1 << 64) // rate


def parse_line(line):
    fields = dict(FIELDS.findall(line))
    if fields.get("status") != "ok":
        return None
    try:
        fields["iter"] = int(fields["iter"])
        fields["gen"] = int(fields["gen"])
    except (KeyError, ValueError):
        return None
    return fields


def capture(fields, output, scratch_base, patch_dir):
    source = Path(fields.get("out", ""))
    if (not source.is_absolute() or source.parent.parent != scratch_base or
            not source.parent.name.startswith("apkfuzz-scratch-") or
            not source.name.endswith(".apk") or source.name in (".", "..")):
        raise ValueError("output path outside the expected scratch directory")
    patch = patch_dir / (source.name + ".patch")
    if not patch.is_file():
        raise FileNotFoundError("matching patch missing")
    patch_hash = sha256_file(patch)
    destination = output / f"iter-{fields['iter']:09d}-g{fields['gen']}.apk"
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_APK_BYTES:
            raise ValueError("invalid scratch APK type or size")
        digest = hashlib.sha256()
        copied = 0
        try:
            with destination.open("xb") as target:
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    target.write(block)
                    digest.update(block)
                    copied += len(block)
            if copied != info.st_size:
                raise ValueError("scratch APK size changed during capture")
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    finally:
        os.close(descriptor)
    return {"stored_apk": str(destination), "mutant_sha256": digest.hexdigest(),
            "mutant_size": copied, "patch_path": str(patch),
            "patch_sha256": patch_hash}


def run(args):
    if args.output.exists():
        raise ValueError(f"output already exists: {args.output}")
    args.output.mkdir(parents=True)
    rows_path = args.output / "captures.jsonl"
    started = datetime.now(timezone.utc).isoformat()
    deadline = time.monotonic() + args.max_seconds
    counts = Counter()
    position = 0
    with rows_path.open("x") as rows:
        while time.monotonic() < deadline:
            if args.log.is_file():
                with args.log.open("r", errors="replace") as stream:
                    stream.seek(position)
                    while True:
                        line = stream.readline()
                        if not line or not line.endswith("\n"):
                            break
                        position = stream.tell()
                        fields = parse_line(line)
                        if fields is None:
                            continue
                        counts[f"seen_gen{fields['gen']}"] += 1
                        rate = args.gen1_rate if fields["gen"] == 1 else args.descendant_rate
                        targeted = (fields["gen"] == 1 and
                                    counts["targeted_gen1_selected"] < args.gen1_first)
                        if not targeted and not selected(args.seed, fields["iter"], fields["gen"], rate):
                            continue
                        counts["selected"] += 1
                        if targeted:
                            counts["targeted_gen1_selected"] += 1
                        row = {"iteration": fields["iter"], "generation": fields["gen"],
                               "mutator_seed": fields.get("seed"), "source_path": fields.get("out"),
                               "selection_method": "first_gen_prefix" if targeted else "hash_rate",
                               "sample_rate_denominator": None if targeted else rate}
                        if counts["captured_bytes"] >= args.max_capture_bytes:
                            row["status"] = "skipped_budget"
                        else:
                            try:
                                row.update(capture(fields, args.output, args.scratch_base,
                                                   args.patch_dir))
                                row["status"] = "captured"
                                counts["captured_bytes"] += row["mutant_size"]
                            except (OSError, ValueError) as exc:
                                row["status"] = "capture_failed"
                                row["error_type"] = type(exc).__name__
                        counts[row["status"]] += 1
                        rows.write(json.dumps(row, sort_keys=True) + "\n")
                        rows.flush()
            if args.stop_file.is_file():
                break
            time.sleep(0.1)
    report = {"schema_version": 1, "started_utc": started,
              "finished_utc": datetime.now(timezone.utc).isoformat(),
              "log": str(args.log), "patch_dir": str(args.patch_dir),
              "scratch_base": str(args.scratch_base), "sample_seed": args.seed,
              "gen1_rate_denominator": args.gen1_rate,
              "first_gen_prefix_limit": args.gen1_first,
              "descendant_rate_denominator": args.descendant_rate,
              "max_capture_bytes": args.max_capture_bytes,
              "max_seconds": args.max_seconds,
              "stopped_by_file": args.stop_file.is_file(),
              "source_sha256": sha256_file(Path(__file__)),
              "counts": dict(counts)}
    with (args.output / "summary.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--patch-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--stop-file", required=True, type=Path)
    parser.add_argument("--scratch-base", type=Path, default=Path("/dev/shm"))
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--gen1-rate", type=int, default=1000)
    parser.add_argument("--gen1-first", type=int, default=24,
                        help="target the first N generation-one outputs separately")
    parser.add_argument("--descendant-rate", type=int, default=2000)
    parser.add_argument("--max-capture-bytes", type=int, default=4_000_000_000)
    parser.add_argument("--max-seconds", type=int, default=7600)
    args = parser.parse_args()
    if args.seed < 0 or args.gen1_first < 0 or min(args.gen1_rate, args.descendant_rate,
                            args.max_seconds, args.max_capture_bytes) < 1:
        parser.error("seed must be nonnegative; rates, budget, and max-seconds must be positive")
    print(json.dumps(run(args), sort_keys=True))


if __name__ == "__main__":
    main()
