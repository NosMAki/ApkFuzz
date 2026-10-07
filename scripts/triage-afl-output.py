#!/usr/bin/env python3
"""
triage-afl-output.py  (task 7)

Summarize an AFL++ output directory after a run: key stats, crashes, hangs,
coverage progression, seed/queue diversity, and (for the path-file custom-mutator
workflow) it resolves each crashing/hanging input back to the real mutant APK it
points at.

Usage:
  triage-afl-output.py OUTDIR [--collect DIR] [--patch-dir DIR]
    OUTDIR is an afl-fuzz -o directory (it will use OUTDIR/default if present).
    --collect DIR  copy crash/hang inputs and reconstructed APKs into DIR.
    --patch-dir DIR  reconstruct mutants whose temporary APKs were reaped.
"""
import argparse
import csv
import os
import re
import shutil
import subprocess
import sys


def read_stats(path):
    stats = {}
    if not os.path.isfile(path):
        return stats
    with open(path, errors="ignore") as f:
        for line in f:
            if ":" in line:
                k, _, v = line.partition(":")
                stats[k.strip()] = v.strip()
    return stats


def list_inputs(d):
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, f) for f in sorted(os.listdir(d))
            if f != "README.txt" and os.path.isfile(os.path.join(d, f))]


def resolve_pathfile(p):
    """If input is a small text file containing an APK path, return it."""
    try:
        if os.path.getsize(p) > 4096:
            return None
        raw = open(p, "rb").read()
        text = raw.replace(b"\x00", b"").decode("utf-8", "ignore").strip()
        if text.lower().endswith(".apk"):
            return text
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--collect")
    ap.add_argument("--patch-dir")
    ap.add_argument("--queue-index", help="write a TSV index of queue path-files and saved patches")
    args = ap.parse_args()

    base = args.outdir
    if os.path.isdir(os.path.join(base, "default")):
        base = os.path.join(base, "default")
    if not os.path.isdir(base):
        print(f"error: not a directory: {base}", file=sys.stderr)
        return 2

    stats = read_stats(os.path.join(base, "fuzzer_stats"))
    print(f"== AFL output triage: {base} ==\n")

    keys = ["afl_version", "command_line", "run_time", "cycles_done",
            "execs_done", "execs_per_sec", "corpus_count", "corpus_found",
            "bitmap_cvg", "saved_crashes", "saved_hangs", "last_crash",
            "last_hang", "stability", "slowest_exec_ms", "exec_timeout"]
    for k in keys:
        if k in stats:
            print(f"   {k:18}: {stats[k]}")

    crashes = list_inputs(os.path.join(base, "crashes"))
    hangs = list_inputs(os.path.join(base, "hangs"))
    print(f"\n   crashes on disk    : {len(crashes)}")
    print(f"   hangs on disk      : {len(hangs)}")

    # queue diversity: how many distinct original seeds + how many new finds
    qdir = os.path.join(base, "queue")
    q = [f for f in os.listdir(qdir)] if os.path.isdir(qdir) else []
    q = [f for f in q if f.startswith("id:")]
    origs = set()
    finds = 0
    for name in q:
        m = re.search(r"orig:([^,]+)", name)
        if m:
            origs.add(m.group(1))
        if "src:" in name:
            finds += 1
    print(f"\n   queue entries      : {len(q)}")
    print(f"   original seeds loaded: {len(origs)}  -> {', '.join(sorted(origs)) if origs else '(none tagged)'}")
    print("   (check mutator log src= entries for seeds actually mutated)")
    print(f"   new finds (src:)   : {finds}")

    missing_queue = 0
    if args.queue_index:
        rows = []
        for name in sorted(q):
            target = resolve_pathfile(os.path.join(qdir, name))
            patch = (os.path.join(args.patch_dir, os.path.basename(target) + ".patch")
                     if target and args.patch_dir and "src:" in name else "")
            patch_exists = bool(patch and os.path.isfile(patch))
            if "src:" in name and args.patch_dir and not patch_exists:
                missing_queue += 1
            rows.append({"queue_entry": name, "apk_path": target or "",
                         "patch_path": patch, "patch_exists": int(patch_exists)})
        with open(args.queue_index, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["queue_entry", "apk_path", "patch_path", "patch_exists"],
                                    delimiter="\t")
            writer.writeheader()
            writer.writerows(rows)
        print(f"   queue index        : {args.queue_index}")
        if missing_queue:
            print(f"   WARNING: {missing_queue} new queue item(s) lack saved patches")

    def show(kind, items):
        if not items:
            return
        print(f"\n== {kind} ({len(items)}) ==")
        for p in items:
            apk = resolve_pathfile(p)
            if apk:
                exists = os.path.isfile(apk)
                print(f"   {os.path.basename(p)}")
                print(f"      -> mutant APK: {apk}  ({'present' if exists else 'MISSING (cleaned up)'})")
            else:
                print(f"   {os.path.basename(p)}  (size={os.path.getsize(p)})")

    show("CRASHES", crashes)
    show("HANGS", hangs)

    # coverage progression from plot_data — parse the header, don't assume column order
    pd = os.path.join(base, "plot_data")
    if os.path.isfile(pd):
        raw = open(pd).read().splitlines()
        header = None
        data = []
        for l in raw:
            if not l.strip():
                continue
            if l.startswith("#"):
                header = [c.strip() for c in l.lstrip("#").split(",")]
            else:
                data.append([c.strip() for c in l.split(",")])
        if data:
            def col(cols, names, default_idx):
                if header:
                    for n in names:
                        if n in header:
                            i = header.index(n)
                            if i < len(cols):
                                return cols[i]
                return cols[default_idx] if abs(default_idx) <= len(cols) else "?"
            def tcol(cols):
                return col(cols, ["relative_time"], 0)
            # prefer edges_found; fall back to map_size / total_edges across AFL versions
            def ecol(cols):
                return col(cols, ["edges_found", "total_edges"], -1) if header else cols[-1]
            def mcol(cols):
                return col(cols, ["map_size"], None) if header and "map_size" in (header or []) else None
            print(f"\n== coverage progression (plot_data) ==")
            if not header:
                print("   (no header row; showing raw first/last columns)")
            f, ln = data[0], data[-1]
            print(f"   first: t={tcol(f)}s edges_found={ecol(f)}" + (f" map_size={mcol(f)}" if mcol(f) else ""))
            print(f"   last : t={tcol(ln)}s edges_found={ecol(ln)}" + (f" map_size={mcol(ln)}" if mcol(ln) else ""))

    missing = 0
    if args.collect and (crashes or hangs):
        n = reconstructed = 0
        for kind, items in (("crashes", crashes), ("hangs", hangs)):
            for p in items:
                dest = os.path.join(args.collect, kind)
                input_dir = os.path.join(dest, "inputs")
                apk_dir = os.path.join(dest, "apks")
                os.makedirs(input_dir, exist_ok=True)
                os.makedirs(apk_dir, exist_ok=True)
                shutil.copy2(p, os.path.join(input_dir, os.path.basename(p)))
                n += 1
                apk = resolve_pathfile(p)
                if not apk:
                    print(f"warning: cannot resolve APK path from {p}", file=sys.stderr)
                    missing += 1
                    continue
                target = os.path.join(apk_dir, os.path.basename(apk))
                if os.path.isfile(apk):
                    shutil.copy2(apk, target)
                    continue
                patch = (os.path.join(args.patch_dir, os.path.basename(apk) + ".patch")
                         if args.patch_dir else None)
                if patch and os.path.isfile(patch):
                    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "apply-patch.py"),
                           patch, "-o", target]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        reconstructed += 1
                        continue
                    print(f"warning: failed to reconstruct {apk}: {result.stderr.strip()}", file=sys.stderr)
                else:
                    print(f"warning: missing APK and patch for {apk}", file=sys.stderr)
                missing += 1
        print(f"\n>> collected {n} crash/hang input(s), reconstructed {reconstructed} APK(s) into {args.collect}")
        if missing:
            print(f">> WARNING: {missing} crash/hang APK(s) could not be preserved")

    # nonzero exit if anything interesting was found
    return 4 if (missing or missing_queue) else (3 if (crashes or hangs) else 0)


if __name__ == "__main__":
    sys.exit(main())
