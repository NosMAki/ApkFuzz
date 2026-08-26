#!/usr/bin/env python3
"""
build-corpus-csv.py  -  write Evaluation-SSBSE-2026/corpus.csv describing the corpus.

Per APK it records what can be derived automatically:
    filename, sha256, size, entry_count, manifest_offset, manifest_size
and leaves columns that need human/provenance input blank for you to fill:
    source_url, download_date, min_sdk

manifest_size matters for comparing manifest-family strategies across APKs: 16
flips into a 2 KB manifest is a very different density than 16 into 9 KB, so a
per-APK comparison is meaningless without it.

Usage: build-corpus-csv.py [--apk-dir DIR] [--out FILE]
"""
import argparse
import csv
import hashlib
import os
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

COLUMNS = ["filename", "sha256", "size", "entry_count",
           "manifest_offset", "manifest_size", "min_sdk",
           "source_url", "download_date"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_range(path, info):
    with open(path, "rb") as f:
        f.seek(info.header_offset)
        header = f.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        return None
    name_len, extra_len = struct.unpack_from("<HH", header, 26)
    start = info.header_offset + 30 + name_len + extra_len
    return (start, info.compress_size)


def describe(path):
    row = {c: "" for c in COLUMNS}
    row["filename"] = os.path.basename(path)
    row["sha256"] = sha256(path)
    row["size"] = os.path.getsize(path)
    try:
        with zipfile.ZipFile(path, "r") as z:
            row["entry_count"] = len(z.namelist())
            if "AndroidManifest.xml" in z.namelist():
                rng = manifest_range(path, z.getinfo("AndroidManifest.xml"))
                if rng:
                    row["manifest_offset"], row["manifest_size"] = rng
    except (OSError, zipfile.BadZipFile):
        pass
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk-dir", default=os.path.join(ROOT, "Evaluation-SSBSE-2026", "apk"))
    ap.add_argument("--out", default=os.path.join(ROOT, "Evaluation-SSBSE-2026", "corpus.csv"))
    args = ap.parse_args()

    if not os.path.isdir(args.apk_dir):
        print(f"error: apk dir not found: {args.apk_dir}", file=sys.stderr)
        return 2
    apks = sorted(os.path.join(args.apk_dir, f) for f in os.listdir(args.apk_dir)
                  if f.lower().endswith(".apk"))

    # keep any manually-entered provenance from an existing csv
    prior = {}
    if os.path.isfile(args.out):
        with open(args.out) as f:
            for r in csv.DictReader(f):
                prior[r["filename"]] = r

    rows = []
    for p in apks:
        row = describe(p)
        old = prior.get(row["filename"], {})
        for col in ("source_url", "download_date", "min_sdk"):
            if old.get(col):
                row[col] = old[col]
        rows.append(row)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    print(f">> wrote {args.out} ({len(rows)} apks)")
    for r in rows:
        print(f"   {r['filename']:28} {r['size']:>10}B  entries={r['entry_count']}  "
              f"manifest=@{r['manifest_offset']}+{r['manifest_size']}")
    blanks = [c for c in ("source_url", "download_date", "min_sdk")
              if any(not r[c] for r in rows)]
    if blanks:
        print(f"\n   fill in by hand: {', '.join(blanks)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
