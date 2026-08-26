#!/usr/bin/env python3
"""
Compare an original APK with a mutated APK.

This is intentionally lightweight: it reports raw byte-diff ranges even when the
mutant is no longer a valid ZIP, then adds ZIP-entry differences when Python's
zipfile module can still parse both files.
"""
import argparse
import hashlib
import os
import sys
import zipfile


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def byte_ranges(a, b, limit):
    ranges = []
    start = None
    max_len = max(len(a), len(b))
    for i in range(max_len):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        if av != bv:
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i))
            if len(ranges) >= limit:
                return ranges, True
            start = None
    if start is not None:
        ranges.append((start, max_len))
    return ranges[:limit], len(ranges) > limit


def zip_index(path):
    try:
        with zipfile.ZipFile(path) as zf:
            return {
                info.filename: {
                    "crc": info.CRC,
                    "compress_size": info.compress_size,
                    "file_size": info.file_size,
                    "header_offset": info.header_offset,
                    "compress_type": info.compress_type,
                }
                for info in zf.infolist()
            }, None
    except Exception as exc:
        return None, str(exc)


def print_zip_diff(orig, mut):
    oi, oe = zip_index(orig)
    mi, me = zip_index(mut)
    if oe or me:
        print("\nZIP parse:")
        if oe:
            print(f"  original: FAILED: {oe}")
        else:
            print("  original: OK")
        if me:
            print(f"  mutated : FAILED: {me}")
        else:
            print("  mutated : OK")
        return

    print("\nZIP entry differences:")
    all_names = sorted(set(oi) | set(mi))
    changed = 0
    for name in all_names:
        if name not in oi:
            print(f"  ADDED   {name}")
            changed += 1
        elif name not in mi:
            print(f"  REMOVED {name}")
            changed += 1
        elif oi[name] != mi[name]:
            fields = [k for k in oi[name] if oi[name][k] != mi[name][k]]
            print(f"  CHANGED {name}: {', '.join(fields)}")
            changed += 1
    if changed == 0:
        print("  no ZIP metadata differences")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("original")
    ap.add_argument("mutated")
    ap.add_argument("--ranges", type=int, default=20,
                    help="maximum raw byte-diff ranges to print")
    args = ap.parse_args()

    for path in (args.original, args.mutated):
        if not os.path.isfile(path):
            print(f"error: not a file: {path}", file=sys.stderr)
            return 2

    with open(args.original, "rb") as f:
        ob = f.read()
    with open(args.mutated, "rb") as f:
        mb = f.read()

    print("Files:")
    print(f"  original: {args.original}")
    print(f"    size={len(ob)} sha256={sha256(args.original)}")
    print(f"  mutated : {args.mutated}")
    print(f"    size={len(mb)} sha256={sha256(args.mutated)}")

    ranges, truncated = byte_ranges(ob, mb, args.ranges)
    print("\nRaw byte differences:")
    if not ranges:
        print("  no byte differences")
    else:
        total = sum(e - s for s, e in ranges)
        for s, e in ranges:
            print(f"  [{s},{e}) len={e - s}")
        if truncated:
            print(f"  ... truncated after {args.ranges} ranges")
        print(f"  shown differing bytes: {total}")

    print_zip_diff(args.original, args.mutated)
    return 0


if __name__ == "__main__":
    sys.exit(main())
