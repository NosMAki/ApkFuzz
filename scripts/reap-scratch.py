#!/usr/bin/env python3
"""
reap-scratch.py  -  bound the transient-mutant scratch dir during a campaign.

The mutator writes a full APK per exec so the harness can read it. On tmpfs that
is RAM, and at ~90 exec/s it would fill in seconds. This reaper keeps only the
mutants AFL still needs -- the ones referenced by a queue entry (or the current
input), plus anything younger than a grace window (in-flight) -- and deletes the
rest, together with their .meta sidecars. AFL's queue stays valid because every
file it points at is preserved.

It reads the live set from AFL's own files, so it never guesses:
  <output>/*/queue/*        each file's content is a mutant path string
  <output>/*/.cur_input     the exec in flight right now

Usage:
  reap-scratch.py --scratch DIR --output DIR [--grace 20] [--interval 5] [--once]
Runs until SIGINT/SIGTERM (the campaign script backgrounds it and kills on exit).
"""
import argparse
import glob
import os
import signal
import sys
import time

_stop = False


def _handle(_sig, _frame):
    global _stop
    _stop = True


def live_paths(output_dir):
    live = set()
    for qf in glob.glob(os.path.join(output_dir, "*", "queue", "*")):
        if os.path.basename(qf).startswith("."):
            continue
        try:
            with open(qf, "rb") as f:
                p = f.read(4096).split(b"\x00", 1)[0].decode("utf-8", "ignore").strip()
            if p:
                live.add(os.path.realpath(p))
        except OSError:
            pass
    for cur in glob.glob(os.path.join(output_dir, "*", ".cur_input")):
        try:
            with open(cur, "rb") as f:
                p = f.read(4096).split(b"\x00", 1)[0].decode("utf-8", "ignore").strip()
            if p:
                live.add(os.path.realpath(p))
        except OSError:
            pass
    return live


MIN_GRACE = 0.5   # never delete a file younger than this (an in-flight exec)


def _rm(apk):
    freed = removed = 0
    for path in (apk, apk + ".meta"):
        try:
            sz = os.path.getsize(path)
            os.remove(path)
            freed += sz
            removed += 1
        except OSError:
            pass
    return removed, freed


def sweep(scratch_dir, output_dir, grace, max_bytes):
    live = live_paths(output_dir)
    now = time.time()
    freed = removed = 0

    # candidates: non-live scratch mutants with their age + size
    cands = []
    total = 0
    for apk in glob.glob(os.path.join(scratch_dir, "*.apk")):
        try:
            st = os.stat(apk)
        except OSError:
            continue
        total += st.st_size
        if os.path.realpath(apk) in live:
            continue
        cands.append((st.st_mtime, st.st_size, apk))

    # 1. normal pass: delete anything older than grace
    for mtime, _sz, apk in cands:
        if now - mtime >= grace:
            r, f = _rm(apk)
            removed += r
            freed += f
            total -= f

    # 2. pressure valve: if still over cap, delete oldest-first down to MIN_GRACE
    if max_bytes and total > max_bytes:
        for mtime, _sz, apk in sorted(cands):        # oldest first
            if total <= max_bytes:
                break
            if now - mtime < MIN_GRACE or not os.path.exists(apk):
                continue
            r, f = _rm(apk)
            removed += r
            freed += f
            total -= f
    return removed, freed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--grace", type=float, default=2.0)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--max-bytes", type=float, default=4e9,
                    help="hard cap on scratch bytes; over it, delete oldest first")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    if not os.path.isdir(args.scratch):
        print(f"reaper: scratch dir missing: {args.scratch}", file=sys.stderr)
        return 2

    while not _stop:
        try:
            removed, freed = sweep(args.scratch, args.output, args.grace, args.max_bytes)
            if removed:
                print(f"reaper: removed {removed} mutants, freed {freed/1e6:.1f} MB",
                      flush=True)
        except Exception as e:                      # never let the reaper crash the run
            print(f"reaper: sweep error: {e}", file=sys.stderr, flush=True)
        if args.once:
            break
        # sleep in small slices so a stop signal is honored promptly
        slept = 0.0
        while slept < args.interval and not _stop:
            time.sleep(0.2)
            slept += 0.2
    return 0


if __name__ == "__main__":
    sys.exit(main())
