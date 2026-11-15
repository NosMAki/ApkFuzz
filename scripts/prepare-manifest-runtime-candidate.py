#!/usr/bin/env python3
"""Prepare one captured, single-bit manifest mutant as a separate signed APK.

This narrow experiment repairs only the manifest ZIP CRC fields, then signs a
new artifact. It never changes the exact mutant or its original APK. The
manifest content must remain different from the original and identical before
and after signing. The output directory must be new.
"""

import argparse
import hashlib
import importlib.util
import json
import shutil
import ssl
import struct
import subprocess
import sys
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("apkfuzz_probe", HERE / "probe-android-runtime.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
preflight = probe.preflight
ENTRY = b"AndroidManifest.xml"
# One compressed-manifest bit per generation with ZIP data and CRC kept valid.
VALID_MANIFEST_MODES = ("manifest-valid-onebit", "manifest-axml-onebit")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(base, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"invalid capture path: {relative}")
    return base / path


def manifest_layout(data):
    """Return the compressed manifest and both CRC offsets in a single-disk ZIP."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("ZIP end record missing")
    _, disk, central_disk, disk_count, count, central_size, central, comment = (
        struct.unpack_from("<4s4H2IH", data, eocd))
    if (disk or central_disk or disk_count != count or
            eocd + 22 + comment != len(data) or central + central_size != eocd):
        raise ValueError("unsupported ZIP layout")
    matches = []
    pos = central
    for _ in range(count):
        if data[pos:pos + 4] != b"PK\x01\x02" or pos + 46 > eocd:
            raise ValueError("invalid ZIP central record")
        flags, method = struct.unpack_from("<HH", data, pos + 8)
        crc, compressed, uncompressed = struct.unpack_from("<III", data, pos + 16)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        local = struct.unpack_from("<I", data, pos + 42)[0]
        end = pos + 46 + name_len + extra_len + comment_len
        if end > eocd:
            raise ValueError("truncated ZIP central record")
        if data[pos + 46:pos + 46 + name_len] == ENTRY:
            matches.append((pos, flags, method, crc, compressed, uncompressed, local))
        pos = end
    if pos != eocd or len(matches) != 1:
        raise ValueError("expected exactly one manifest ZIP entry")
    central_pos, flags, method, crc, compressed, uncompressed, local = matches[0]
    if flags & 0x0009 or method != 8 or compressed == 0xffffffff or local == 0xffffffff:
        raise ValueError("unsupported manifest compression or data descriptor")
    if data[local:local + 4] != b"PK\x03\x04" or local + 30 > central:
        raise ValueError("invalid manifest local header")
    local_flags, local_method = struct.unpack_from("<HH", data, local + 6)
    local_crc, local_compressed, local_uncompressed = struct.unpack_from(
        "<III", data, local + 14)
    name_len, extra_len = struct.unpack_from("<HH", data, local + 26)
    data_start = local + 30 + name_len + extra_len
    if (data[data_start - extra_len - name_len:data_start - extra_len] != ENTRY or
            (local_flags, local_method, local_crc, local_compressed,
             local_uncompressed) != (flags, method, crc, compressed, uncompressed) or
            data_start + compressed > central):
        raise ValueError("manifest ZIP headers disagree")
    return {"data_start": data_start, "data_end": data_start + compressed,
            "local_crc_offset": local + 14, "central_crc_offset": central_pos + 16,
            "stored_crc32": crc, "uncompressed_size": uncompressed}


def manifest_bytes(data, layout):
    try:
        content = zlib.decompress(data[layout["data_start"]:layout["data_end"]], -15)
    except zlib.error as exc:
        raise ValueError(f"manifest deflate invalid: {exc}") from exc
    if len(content) != layout["uncompressed_size"]:
        raise ValueError("manifest decompressed size changed")
    return content


def repair_crc(data, layout):
    result = bytearray(data)
    crc = zlib.crc32(manifest_bytes(data, layout))
    struct.pack_into("<I", result, layout["local_crc_offset"], crc)
    struct.pack_into("<I", result, layout["central_crc_offset"], crc)
    changes = [i for i, (old, new) in enumerate(zip(data, result)) if old != new]
    allowed = set(range(layout["local_crc_offset"], layout["local_crc_offset"] + 4))
    allowed.update(range(layout["central_crc_offset"], layout["central_crc_offset"] + 4))
    if not changes or not set(changes) <= allowed:
        raise ValueError("CRC repair changed unexpected bytes or made no change")
    return bytes(result), crc, changes


def zip_valid(path):
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError(f"ZIP entry failed after preparation: {bad}")
        return archive.read(ENTRY.decode())


def shared_payload_unchanged(baseline_path, mutant_path):
    """Check all non-signature ZIP entries other than the mutated manifest."""
    def signature_entry(name):
        # APK signing may replace these JAR signature records. Other META-INF
        # files are application payload and must still match byte for byte.
        if not name.startswith("META-INF/"):
            return False
        leaf = name[len("META-INF/"):]
        return bool(leaf) and "/" not in leaf and (
            leaf == "MANIFEST.MF" or leaf.upper().endswith((".SF", ".RSA", ".DSA", ".EC")))

    with zipfile.ZipFile(baseline_path) as baseline, zipfile.ZipFile(mutant_path) as mutant:
        names_a = {name for name in baseline.namelist() if not signature_entry(name)}
        names_b = {name for name in mutant.namelist() if not signature_entry(name)}
        if names_a != names_b or ENTRY.decode() not in names_a:
            raise ValueError("prepared baseline and mutant payload entry sets differ")
        for name in names_a - {ENTRY.decode()}:
            if baseline.read(name) != mutant.read(name):
                raise ValueError(f"non-manifest payload changed: {name}")
    return len(names_a) - 1


def run_ok(argv, timeout=60):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"tool timed out: {Path(argv[0]).name}") from exc
    if result.returncode or (argv[1:3] == ["dump", "badging"] and
                             preflight.aapt_resource_warning(result.stderr + result.stdout)):
        raise ValueError(f"{Path(argv[0]).name} failed: {result.stderr.strip()[:350]}")
    return result


def prepare(args):
    base, captured, checked = probe.select_candidate(
        args.capture_manifest, args.preflight_report, args.queue_entry)
    apk, reasons = probe.eligibility(base, captured, checked)
    # Provenance and byte identity must pass before any signed derivative is made.
    allowed = {"preflight_blocked"}
    if set(reasons) != allowed:
        raise ValueError(f"capture provenance failed: {reasons}")
    mode = checked.get("mode")
    generation = int(checked.get("generation", 0))
    legacy = mode == "manifest-bitflip" and generation == 1
    valid_mode = mode in VALID_MANIFEST_MODES and 1 <= generation <= 20
    if not (legacy or valid_mode):
        raise ValueError("requires a supported one-bit manifest mutation")
    if legacy and (checked.get("edit_count") != 1 or
                   checked.get("zip", {}).get("entry") != ENTRY.decode()):
        raise ValueError("requires one generation-one manifest-bitflip ZIP failure")
    if valid_mode and checked.get("zip", {}).get("status") != "valid":
        raise ValueError("valid-manifest mode requires a ZIP-valid exact APK")
    if checked.get("origin_sha256") != captured.get("origin_sha256"):
        raise ValueError("original hash mismatch")
    chain = captured.get("patch_chain", [])
    if len(chain) != generation:
        raise ValueError("captured patch chain length differs from generation")
    patch = checked_path(base, chain[0]["path"])
    _, meta, edits = preflight.patch_tool.read_patch(str(patch))
    if (meta.get("mode") != mode or int(meta.get("gen", 0)) != generation or
            len(edits) != checked.get("edit_count")):
        raise ValueError("captured patch metadata differs from preflight")
    origin = Path(meta["origin"])
    original = origin.read_bytes()
    exact = apk.read_bytes()
    if (sha256(original) != captured.get("origin_sha256") or
            sha256(exact) != captured.get("mutant_sha256") or
            sha256(exact) != checked.get("mutant_sha256")):
        raise ValueError("original or exact mutant hash changed")
    reconstructed, _, _ = preflight.patch_tool.reconstruct(str(patch), None, True)
    if bytes(reconstructed) != exact:
        raise ValueError("patch no longer reconstructs captured mutant")
    layout = manifest_layout(exact)
    crc_offsets = (set(range(layout["local_crc_offset"], layout["local_crc_offset"] + 4)) |
                   set(range(layout["central_crc_offset"], layout["central_crc_offset"] + 4)))
    for index, link in enumerate(chain):
        link_path = checked_path(base, link["path"])
        if preflight.sha256_file(link_path) != link["sha256"]:
            raise ValueError("saved patch changed since capture")
        _, link_meta, link_edits = preflight.patch_tool.read_patch(str(link_path))
        if (link_meta.get("mode") != mode or
                int(link_meta.get("gen", 0)) != generation - index):
            raise ValueError("patch chain mode or generation changed")
        compressed = [(off, old, new) for off, old, new in link_edits
                      if layout["data_start"] <= off < layout["data_end"]]
        if (len(compressed) != 1 or
                (compressed[0][1] ^ compressed[0][2]).bit_count() != 1):
            raise ValueError("patch is not one compressed-manifest bit flip")
        if legacy and len(link_edits) != 1:
            raise ValueError("legacy patch has unexpected extra edits")
        if valid_mode and (not 3 <= len(link_edits) <= 9 or
                           any(off not in crc_offsets and not
                               layout["data_start"] <= off < layout["data_end"]
                               for off, _, _ in link_edits)):
            raise ValueError("valid-mode patch edited outside manifest and CRC")
        if index == 0:
            offset, old, new = compressed[0]
    if legacy and (old != original[offset] or new != exact[offset]):
        raise ValueError("legacy patch does not match original and exact bytes")
    original_manifest = zip_valid(origin)
    exact_manifest = manifest_bytes(exact, layout)
    if exact_manifest == original_manifest:
        raise ValueError("mutation did not change manifest content")
    structure = preflight.axml.structure_error(exact_manifest)
    if structure:
        raise ValueError(f"mutated manifest binary XML structure invalid: {structure}")
    if legacy:
        repaired, new_crc, changed_offsets = repair_crc(exact, layout)
    else:
        if zip_valid(apk) != exact_manifest:
            raise ValueError("valid-mode exact APK failed all-entry ZIP check")
        repaired, new_crc, changed_offsets = exact, layout["stored_crc32"], []

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=False)
    repaired_path = output / "crc-repaired.apk"
    signed_path = output / "prepared-signed.apk"
    baseline_path = output / "prepared-baseline.apk"
    repaired_path.write_bytes(repaired)
    if zip_valid(repaired_path) != exact_manifest:
        raise ValueError("prepared input changed manifest content")
    run_ok([args.aapt, "dump", "badging", str(repaired_path)])
    run_ok([args.apksigner, "sign", "--key", str(args.key), "--cert",
            str(args.cert), "--out", str(signed_path), str(repaired_path)])
    run_ok([args.apksigner, "verify", str(signed_path)])
    if zip_valid(signed_path) != exact_manifest:
        raise ValueError("signing changed manifest content")
    metadata = run_ok([args.aapt, "dump", "badging", str(signed_path)]).stdout
    if "package: name='" not in metadata:
        raise ValueError("prepared APK has no parsed package")
    run_ok([args.apksigner, "sign", "--key", str(args.key), "--cert",
            str(args.cert), "--out", str(baseline_path), str(origin)])
    run_ok([args.apksigner, "verify", str(baseline_path)])
    if zip_valid(baseline_path) != original_manifest:
        raise ValueError("baseline signing changed original manifest content")
    baseline_metadata = run_ok([args.aapt, "dump", "badging", str(baseline_path)]).stdout
    if baseline_metadata.partition("\n")[0] != metadata.partition("\n")[0]:
        raise ValueError("prepared baseline and mutant package metadata differ")
    unchanged_entries = shared_payload_unchanged(baseline_path, signed_path)
    cert_pem = Path(args.cert).read_text(encoding="ascii")
    report = {
        "schema_version": 1, "prepared_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ready_for_install_attempt", "queue_entry": args.queue_entry,
        "capture_manifest": str(Path(args.capture_manifest).absolute()),
        "exact_preflight_report": str(Path(args.preflight_report).absolute()),
        "origin_path": str(origin), "origin_sha256": sha256(original),
        "exact_mutant_path": str(apk), "exact_mutant_sha256": sha256(exact),
        "patch_path": str(patch), "patch_sha256": sha256(patch.read_bytes()),
        "patch_mode": meta["mode"], "patch_seed": meta.get("seed"),
        "patch_iteration": meta.get("iter"), "patch_chain_length": len(chain),
        "patch_edit": {
            "offset": offset, "old": f"{old:02x}", "new": f"{new:02x}"},
        "crc_repair_path": str(repaired_path), "crc_repair_sha256": sha256(repaired),
        "crc32_before": f"{layout['stored_crc32']:08x}", "crc32_after": f"{new_crc:08x}",
        "crc_changed_offsets": changed_offsets,
        "crc_repair_needed": legacy,
        "prepared_apk_path": str(signed_path),
        "prepared_apk_sha256": preflight.sha256_file(signed_path),
        "prepared_baseline_path": str(baseline_path),
        "prepared_baseline_sha256": preflight.sha256_file(baseline_path),
        "signing_certificate_sha256": sha256(ssl.PEM_cert_to_DER_cert(cert_pem)),
        "original_manifest_sha256": sha256(original_manifest),
        "baseline_manifest_sha256": sha256(original_manifest),
        "mutated_manifest_sha256": sha256(exact_manifest),
        "prepared_manifest_sha256": sha256(exact_manifest),
        "manifest_changed_bytes": (sum(a != b for a, b in zip(original_manifest,
                                                                exact_manifest)) +
                                   abs(len(original_manifest) - len(exact_manifest))),
        "other_payload_entries_unchanged": unchanged_entries,
        "manifest_content_retained": True,
        "transformation": (["replace manifest ZIP local and central CRC32 fields"] if legacy
                           else ["retain already valid manifest ZIP data and CRC32 fields"]) + [
                           "replace mutant APK signatures with supplied test certificate",
                           "replace baseline APK signatures with the same certificate"],
    }
    (output / "preparation.json").write_text(json.dumps(report, indent=2) + "\n")
    return output / "preparation.json"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-manifest", required=True)
    parser.add_argument("--preflight-report", required=True)
    parser.add_argument("--queue-entry", required=True)
    parser.add_argument("--key", required=True, type=Path, help="PKCS#8 DER test signing key")
    parser.add_argument("--cert", required=True, type=Path, help="matching X.509 PEM certificate")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--apksigner", default=shutil.which("apksigner"))
    parser.add_argument("--aapt", default=preflight.find_aapt())
    args = parser.parse_args(argv)
    if not args.apksigner or not args.aapt:
        parser.error("Android SDK apksigner and aapt are required")
    if Path(args.output_dir).exists():
        parser.error(f"output directory already exists: {args.output_dir}")
    try:
        report = prepare(args)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        parser.error(str(exc))
    print(f"ready_for_install_attempt\nreport: {report.absolute()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
