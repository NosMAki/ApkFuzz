#!/usr/bin/env python3
"""
apply-patch.py  -  reconstruct a full mutant APK from a saved apkfuzz patch.

The mutator saves a tiny patch (origin path + byte edits) per mutant instead of
a multi-MB APK copy, so a 144h campaign costs kilobytes instead of terabytes.
This tool turns a patch back into the exact mutant for triage / external tools.

Patch format (written by cm_ApkVulFuzz2.c):
    # apkfuzz-patch v1
    origin <path>
    mode <mode>
    seed <n>
    iter <n>
    gen <n>
    status <status>
    edits <count>
    <off> <oldhex> <newhex>
    ...

Usage:
    apply-patch.py PATCH [-o OUT.apk] [--origin PATH] [--no-verify] [--sha256]
Exit code 0 on success, 1 on a verification mismatch, 2 on usage/IO error.
"""
import argparse
import hashlib
import os
import sys


def read_patch(path):
    meta, edits = {}, []
    with open(path) as f:
        header = f.readline()
        if not header.startswith("# apkfuzz-patch"):
            raise ValueError("not an apkfuzz patch (missing header)")
        in_edits = False
        for line in f:
            line = line.strip()
            if not line:
                continue
            if in_edits:
                off, oldh, newh = line.split()
                edits.append((int(off), int(oldh, 16), int(newh, 16)))
            elif line.startswith("edits "):
                in_edits = True
            else:
                k, _, v = line.partition(" ")
                meta[k] = v
    return meta, edits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("patch")
    ap.add_argument("-o", "--out", help="output APK (default: <patch-basename>.apk)")
    ap.add_argument("--origin", help="override the origin path from the patch")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip checking that origin bytes match the patch's old values")
    ap.add_argument("--sha256", action="store_true", help="print the mutant sha256")
    args = ap.parse_args()

    try:
        meta, edits = read_patch(args.patch)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    origin = args.origin or meta.get("origin")
    if not origin or not os.path.isfile(origin):
        print(f"error: origin not found: {origin}", file=sys.stderr)
        return 2

    with open(origin, "rb") as f:
        buf = bytearray(f.read())

    mismatches = 0
    for off, oldv, newv in edits:
        if off >= len(buf):
            print(f"error: edit offset {off} past origin size {len(buf)}", file=sys.stderr)
            return 1
        if not args.no_verify and buf[off] != oldv:
            mismatches += 1
            if mismatches <= 5:
                print(f"verify: off {off} expected {oldv:#04x} but origin has {buf[off]:#04x}",
                      file=sys.stderr)
        buf[off] = newv
    if mismatches:
        print(f"error: {mismatches} origin byte(s) did not match the patch "
              f"(wrong origin? use --origin or --no-verify)", file=sys.stderr)
        return 1

    out = args.out or (os.path.splitext(os.path.basename(args.patch))[0] + ".apk")
    with open(out, "wb") as f:
        f.write(buf)

    line = f">> wrote {out} ({len(buf)} bytes, {len(edits)} edits, mode={meta.get('mode','?')}"
    if args.sha256:
        line += f", sha256={hashlib.sha256(buf).hexdigest()}"
    print(line + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
