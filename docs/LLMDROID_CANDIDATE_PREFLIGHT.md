# LLMDroid differential extension: candidate capture and preflight

The optional capture step preserves selected live AFL++ mutants before the run
clears temporary storage. The offline preflight checks whether a candidate is
worth an Android installation attempt. Neither step installs, launches,
instruments, signs, or changes an APK. The fuzzing loop and DroidBot checkout
are unaffected.

## Capture exact live mutants

Set `APKFUZZ_CAPTURE_LIMIT` when starting a bounded run to preserve up to N
mutant queue entries after AFL++ stops and before scratch is removed. Without
`APKFUZZ_CAPTURE_SAMPLE_SEED`, capture uses queue order; with a seed and more
than N entries, it draws a deterministic sample from the new queue entries.
Unselected entries are unmeasured, not classified as invalid. Capture is off
when the limit is unset. Set `APKFUZZ_SAVE_DIR` as
well to retain the patches needed to check mutation provenance.

```bash
APKFUZZ_SAVE_DIR=/path/to/patches APKFUZZ_CAPTURE_LIMIT=10 \
  bash scripts/run-corpus-smoke.sh 20
```

The new `<run-output>/candidates/` directory contains `manifest.json`, a copy
of `queue-index.tsv`, exact live APKs named by SHA-256, and copied patch chains
and `.meta` sidecars. A run copies at most N mutants, so plan disk space for
N complete APKs. The capture report distinguishes `preserved` (exact live bytes
stored) from `research_ready` (also has a matching known original hash and a
saved patch chain that reconstructs to those bytes). A mismatch keeps the live
APK for investigation and records the discrepancy. Missing live APKs are never
silently replaced with reconstructed bytes. The manifest also records the
mutator library hash and AFL++ version when capture is launched by the run
script. The additive `provenance_verified` count has the same meaning as the
legacy `research_ready` count; neither indicates ZIP validity or installability.

For an already running campaign, capture while its scratch APKs are still
present. Use exact queue entry names to choose particular candidates:

```bash
python3 -B scripts/capture-runtime-candidates.py \
  --queue-index /path/to/run/queue-index.tsv \
  --queue-entry 'id:000001,src:000000,+cov' \
  --output-dir /path/to/new-capture-directory
```

The output directory must be new. The `--limit` option defaults to 10 and caps
both automatic and manual selection.

## Offline runtime preflight

`scripts/inspect-runtime-candidates.py` accepts a capture `manifest.json`
(`--capture-manifest`), saved V2 `.apk.patch` files (`--patch`), or
`queue-index.tsv` files (`--queue-index`). Queue indexes are
produced by `scripts/triage-afl-output.py`; original seed rows are skipped, while
mutant rows without a saved patch are reported as `patch_missing`.
The output is a new JSON report. Existing output files are never overwritten.

Prefer a capture manifest when available. It checks the saved APK against both
the reconstructed patch and the SHA-256 recorded during capture. It also checks
the copied patch and sidecar hashes, and the original hash recorded at capture:

```bash
python3 -B scripts/inspect-runtime-candidates.py \
  --capture-manifest /path/to/run/candidates/manifest.json \
  --output /path/to/new-preflight-report.json
```

```bash
python3 -B scripts/inspect-runtime-candidates.py \
  --patch docs/evidence/random-2026-10-05/F-Droid_1365908812_44.apk.patch \
  --output /tmp/apkfuzz-preflight-example.json
```

For a campaign that retained `APKFUZZ_SAVE_DIR` patches:

```bash
python3 -B scripts/inspect-runtime-candidates.py \
  --queue-index /path/to/campaign/runs/F-Droid/queue-index.tsv \
  --queue-index /path/to/campaign/runs/flashlight/queue-index.tsv \
  --output /path/to/new-preflight-report.json
```

The tool reconstructs each candidate using `scripts/apply-patch.py`, checks the
original APK's complete SHA-256 against `Evaluation-SSBSE-2026/corpus.csv`, and
computes the reconstructed mutant's complete SHA-256. If a queue index still
points to an existing full mutant, it compares the mutant's hash too. This is
the direct check of byte-identical reconstruction. An absent transient APK is
reported as `live_apk_match: unavailable`; the exactness of that historical
instance cannot be established from a patch alone because the old patch format
did not record a mutant hash.

The temporary reconstructed APK is checked with Python `zipfile` (all entries
decompress and pass CRC), `aapt dump badging` (Android manifest parsing), and
`apksigner verify` (signature). The temporary file is removed after each case.
The summary reports valid and checked counts separately for each stage; an
unavailable tool or a manifest skipped after ZIP failure is not a valid check.
`eligible_for_install_attempt` requires all three checks, a recorded matching
original hash, and no mismatch with a still available mutant. A patch containing
256 edits is blocked unless its live mutant is available and has the same hash;
the patch format cannot reveal whether additional edits were discarded. It does not mean
the APK installs or launches. Missing tools and timeouts are reported explicitly.
You can pass `--aapt` and `--apksigner` paths if autodetection misses the SDK.

An original absent from `corpus.csv` is classified as
`origin_hash_unrecorded` and cannot be called eligible until its known-good hash
is recorded. A changed original is rejected even if the edited bytes still
match. Patch parents must all remain available for chained mutants.

## Bounded Android installation and launch probe

`scripts/probe-android-runtime.py` accepts one captured queue entry and its
preflight report. By default it makes a device-free plan and writes a new JSON
report. It skips any candidate whose capture or preflight is not verified.

```bash
python3 -B scripts/probe-android-runtime.py \
  --capture-manifest /path/to/run/candidates/manifest.json \
  --preflight-report /path/to/new-preflight-report.json \
  --queue-entry 'id:000001,src:000000,+cov' \
  --output /path/to/new-runtime-plan.json
```

To perform the device check, start a suitable test emulator separately and
provide its exact ADB serial with `--execute --serial SERIAL`. The probe checks
that it is booted and that the app is not already installed. It then attempts
installation, asks Android to resolve the package's launcher intent, checks for a live
process after a short settling interval, and uninstalls the app it installed.
If Android cannot resolve the package launcher, the probe tries the activity
declared by `aapt dump badging` explicitly. The report keeps both outcomes.
Only a completed `adb install` with `Success` proceeds to launch; an install
timeout is inconclusive even when `pm path` briefly lists the package.
It records each command's outcome and reports a cleanup failure if uninstall
does not succeed. If installation times out while the package is still absent,
cleanup is marked unverified because Android could register it later. It never
signs or rewrites the APK. A successful launch
command or running process is only a preliminary runtime result, not evidence
of a defect or vulnerability. The script does not start or configure emulators.

A bounded API 34 control check and its device reports are recorded in
[`evidence/runtime-probe-2026-10-21/`](evidence/runtime-probe-2026-10-21/README.md).
These controls contain no AFL++ mutation and do not establish mutant runtime
compatibility.

## Narrow manifest runtime preparation

`scripts/prepare-manifest-runtime-candidate.py` is an optional preparation
experiment for a captured, generation-one `manifest-bitflip` mutant with one
changed bit inside the compressed manifest. It requires the offline preflight
to verify the captured bytes and patch, even though that preflight blocks the
exact mutant because its ZIP CRC and signature are invalid. The tool checks
that the changed manifest still decompresses and differs from the original.
It changes only the local and central manifest CRC32 fields in a separate
copy, then signs that copy with a supplied test key. It also signs a separate
baseline copy of the original with the same certificate.

The new output directory contains the CRC-repaired APK, prepared mutant APK,
prepared baseline APK, and `preparation.json`. The report records a distinct
SHA-256 for each APK, the exact patch edit, CRC byte offsets, certificate
digest, and hashes of the decompressed manifests. Preparation succeeds only
when the prepared mutant's manifest matches the exact mutant's decompressed
manifest, differs from the original's, and both prepared APKs pass ZIP,
manifest, and signature checks. The exact mutant and original are untouched.
This does not claim that arbitrary manifest mutations can be repaired or that
signing preserves all app behavior.

The tool accepts a PKCS#8 DER private key and matching PEM certificate via
`--key` and `--cert`. Keep the private key outside the repository. For one
captured candidate, run:

```bash
python3 -B scripts/prepare-manifest-runtime-candidate.py \
  --capture-manifest /path/to/candidates/manifest.json \
  --preflight-report /path/to/exact-preflight.json \
  --queue-entry 'id:000006,src:000000' \
  --key /path/to/test-key.pk8 \
  --cert /path/to/test-cert.pem \
  --output-dir /path/to/new-preparation-directory
```

The device probe accepts the resulting report with `--prepared-report`,
instead of the exact mutant's capture and preflight arguments. Before any
installation it rechecks all artifact hashes, the manifest content, and both
prepared APK signatures. It installs only the prepared mutant and removes it
after the bounded launch check. Add `--use-prepared-baseline` to probe the
separately signed original from the same report. Probe that baseline first:
executing a prepared mutant requires `--baseline-probe-report` naming a
healthy baseline report from the same device. `launched_process_running` now
means a running process, no fatal exception logged for the package since the
probe began, and the baseline's resolved activity; a start-up crash is
`launched_crashed`. Offline, any `aapt` resource-parser warning or a manifest
failing `scripts/android_binary_xml.py` is invalid even when `aapt` exits 0. A paired comparison still
requires equivalent initial device state; these isolated launch probes do not
establish a differential defect.

## Observed limits

- The historical V2 patch format has no full original or mutant hash. This tool
  verifies against the repository corpus catalog and computes a mutant hash at
  reconstruction time. The capture step now records the live mutant's hash for
  selected queue entries. The saved edit list also has a 256-byte capacity;
  with `APKFUZZ_NO_DEDUP` and more than 256 distinct edited bytes, it can be
  truncated. A focused local check with 512 flips produced a 256-edit patch.
  When the transient mutant still exists, its hash comparison detects this.
  Without that mutant or a selection-time hash, byte identity remains
  unverified even if the patch reconstructs successfully.
- ZIP validity, Android manifest parsing, valid signing, installation, and
  launch are separate outcomes. The offline preflight measures the first three;
  the bounded device probe attempts the last two for one selected candidate.
- Re-signing or instrumentation would create another artifact with another hash.
  They require a separate, controlled preparation stage after this preflight.
- A campaign's ignored local patch directory must be retained. A queue path-file
  alone is insufficient once its transient APK and patch are gone.

Run focused tests with:

```bash
python3 -B tests/test_candidate_capture.py
python3 -B tests/test_runtime_candidate_preflight.py
python3 -B tests/test_android_runtime_probe.py
```
