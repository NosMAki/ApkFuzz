#!/usr/bin/env python3
"""
check_variant_window.py LABEL   < driver-output

Reads mutator_driver output (a LAYOUT line + R<k> edit lines) on stdin and
asserts that every byte the variant LABEL edited falls inside the ZIP structure
its name promises. Prints one PASS/FAIL line and exits non-zero on failure.
"""
import re
import sys


def parse(stream):
    layout, offs = {}, []
    for line in stream:
        line = line.strip()
        if line.startswith("LAYOUT"):
            if "none" in line:
                return None, []
            for tok in line.split()[1:]:
                if "=" not in tok:
                    continue
                k, v = tok.split("=", 1)
                m = re.match(r"\[(\d+),(\d+)\)", v)
                if m:                       # key=[start,end) -> key, key_end
                    layout[k] = int(m.group(1))
                    layout[k + "_end"] = int(m.group(2))
                elif v.isdigit():
                    layout[k] = int(v)
        elif line.startswith("R"):
            for off, _xor in re.findall(r"(\d+):([0-9a-f]{2})", line):
                offs.append(int(off))
    return layout, offs


def field_set(base):
    return set(range(base, base + 4))


def expected(label, L):
    """Return (name, predicate(off)->bool) for the label, or None for 'any'."""
    ds, de = L["manifest"], L["manifest_end"]           # manifest data range
    mlen = de - ds
    lh, ld = L["local_header"], L["local_header_end"]
    cds, cde = L["cd"], L["cd_end"]
    fields = {
        "local_crc": L["local_crc"], "cd_crc": L["cd_crc"],
        "local_csize": L["local_csize"], "local_usize": L["local_usize"],
        "cd_csize": L["cd_csize"], "cd_usize": L["cd_usize"],
    }

    def rng(lo, hi):
        return lambda o: lo <= o < hi

    def inset(*names):
        s = set()
        for n in names:
            s |= field_set(fields[n])
        return lambda o: o in s

    # segment variants are named manifest-segment-<offset>-<size>
    seg = re.match(r"manifest-segment-(\d+)-(\d+)$", label)
    if seg:
        off, sz = int(seg.group(1)), int(seg.group(2))
        lo, hi = ds + off, min(ds + off + sz, de)
        return (f"manifest[+{off},+{off + sz})", rng(lo, hi))

    table = {
        "manifest-bitflip":        ("manifest",        rng(ds, de)),
        "manifest-start":          ("manifest[0/3]",   rng(ds, ds + (mlen // 3 or mlen))),
        "manifest-middle":         ("manifest[1/3]",   rng(ds + mlen // 3, ds + 2 * mlen // 3)),
        "manifest-end":            ("manifest[2/3]",   rng(ds + 2 * mlen // 3, de)),
        "zip-local-header":        ("local_header",    rng(lh, ld)),
        "zip-central-directory":   ("central_dir",     rng(cds, cde)),
        "crc-fields":              ("crc(local+cd)",   inset("local_crc", "cd_crc")),
        "crc-both-different":      ("crc(local+cd)",   inset("local_crc", "cd_crc")),
        "crc-local-only-zero":     ("crc(local)",      inset("local_crc")),
        "crc-cd-only-zero":        ("crc(cd)",         inset("cd_crc")),
        "size-fields":             ("size(all)",       inset("local_csize", "local_usize", "cd_csize", "cd_usize")),
        "size-both-different":     ("size(all)",       inset("local_csize", "local_usize", "cd_csize", "cd_usize")),
        "size-local-only-plusone": ("size(local)",     inset("local_csize", "local_usize")),
        "size-cd-only-plusone":    ("size(cd)",        inset("cd_csize", "cd_usize")),
        "random-range":            ("any", None),
    }
    return table.get(label)


def main():
    label = sys.argv[1]
    layout, offs = parse(sys.stdin)
    if layout is None:
        print(f"FAIL  {label}: driver found no manifest layout")
        return 1
    exp = expected(label, layout)
    if exp is None:
        print(f"FAIL  {label}: no expectation defined for this variant")
        return 1
    name, pred = exp
    if not offs:
        # random-range and a no-op field pattern (KEEP) can legitimately produce
        # nothing; every targeted mode must have touched something.
        if label in ("random-range",):
            print(f"PASS  {label:26} -> {name} (no bytes required)")
            return 0
        print(f"FAIL  {label}: produced no edits at all")
        return 1
    if pred is None:
        print(f"PASS  {label:26} -> {name} ({len(offs)} edits, unconstrained)")
        return 0
    bad = [o for o in offs if not pred(o)]
    if bad:
        print(f"FAIL  {label}: {len(bad)}/{len(offs)} edits outside {name}, "
              f"e.g. {bad[:4]}")
        return 1
    print(f"PASS  {label:26} -> {name} ({len(offs)} edits all in window)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
