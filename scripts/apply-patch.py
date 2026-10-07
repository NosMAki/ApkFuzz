#!/usr/bin/env python3
"""
apply-patch.py  -  reconstruct a full mutant APK from a saved apkfuzz patch.

The mutator saves a tiny patch (origin path + byte edits) per mutant instead of
a multi-MB APK copy, so a 144h campaign costs kilobytes instead of terabytes.
This tool turns a patch back into the exact mutant for triage / external tools.

Patch format (written by cm_ApkVulFuzz2.c):
    # apkfuzz-patch v2
    origin <path>
    parent <parent patch filename>  # only for descendants
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
Exit code 0 on success, 1 on patch/verification/IO error, 2 on usage error.
"""
import argparse
import hashlib
import os
import sys


def read_patch(path):
    meta, edits = {}, []
    with open(path) as f:
        header = f.readline().strip()
        if header not in ("# apkfuzz-patch v1", "# apkfuzz-patch v2"):
            raise ValueError("unsupported apkfuzz patch version")
        in_edits = False
        for line in f:
            line = line.strip()
            if not line:
                continue
            if in_edits:
                off, oldh, newh = line.split()
                edits.append((int(off), int(oldh, 16), int(newh, 16)))
            elif line.startswith("edits "):
                meta["edits"] = line.partition(" ")[2]
                in_edits = True
            else:
                k, _, v = line.partition(" ")
                meta[k] = v
    if "edits" not in meta or int(meta["edits"]) != len(edits):
        raise ValueError("patch edit count mismatch")
    return header.rsplit(" ", 1)[1], meta, edits


def reconstruct(path, origin_override, verify, seen=None):
    path = os.path.abspath(path)
    seen = seen or set()
    if path in seen or len(seen) >= 64:
        raise ValueError("patch parent cycle or excessive chain length")
    seen.add(path)
    version, meta, edits = read_patch(path)
    origin = origin_override or meta.get("origin")
    if not origin or not os.path.isfile(origin):
        raise FileNotFoundError(f"origin not found: {origin}")
    gen = int(meta.get("gen", "1"))
    parent = meta.get("parent")
    if parent:
        if version != "v2" or os.path.basename(parent) != parent:
            raise ValueError("invalid parent patch reference")
        parent_path = os.path.join(os.path.dirname(path), parent)
        buf, parent_meta, parent_gen = reconstruct(parent_path, origin_override, verify, seen)
        if parent_gen + 1 != gen or parent_meta.get("origin") != meta.get("origin"):
            raise ValueError("patch parent generation or origin mismatch")
    else:
        if gen != 1:
            raise ValueError("descendant patch has no parent; legacy v1 patches cannot be reconstructed safely")
        with open(origin, "rb") as f:
            buf = bytearray(f.read())

    for off, oldv, newv in edits:
        if off < 0 or off >= len(buf):
            raise ValueError(f"edit offset {off} past source size {len(buf)}")
        if verify and buf[off] != oldv:
            raise ValueError(f"source mismatch at offset {off}: expected {oldv:#04x}, got {buf[off]:#04x}")
        buf[off] = newv
    return buf, meta, gen


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
        buf, meta, _ = reconstruct(args.patch, args.origin, not args.no_verify)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out = args.out or (os.path.splitext(os.path.basename(args.patch))[0] + ".apk")
    with open(out, "wb") as f:
        f.write(buf)

    line = f">> wrote {out} ({len(buf)} bytes, {meta.get('edits','?')} edits, mode={meta.get('mode','?')}"
    if args.sha256:
        line += f", sha256={hashlib.sha256(buf).hexdigest()}"
    print(line + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
