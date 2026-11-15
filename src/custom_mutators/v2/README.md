# Multi-strategy APK mutator (v2)

A **separate** AFL++ custom mutator that lives alongside the frozen baseline
(`../cm_ApkVulFuzz.c`, `../bitflip.c`, `../apk.c` are **not** modified). It keeps
the same path-file workflow but the mutation is dispatched to a selectable
strategy, with a configurable region, configurable intensity, and opt-in logging.

## Build

```bash
cd src
AFLPP_DIR=~/AFLplusplus bash compile_afl_mutator_v2.sh
# -> build/cm-ApkVulFuzz2.so   (+ build/mut2-standalone for offline testing)
```

For long comparisons, build one locked `.so` per strategy:

```bash
cd src
AFLPP_DIR=~/AFLplusplus bash compile_afl_mutator_variants.sh
# -> build/mutators/cm-ApkVulFuzz2-*.so
```

These variants use compile-time flags such as `APKFUZZ_COMPILED_MODE`,
`APKFUZZ_COMPILED_MAX_FLIPS`, `APKFUZZ_COMPILED_SEGMENT_OFFSET`, and
`APKFUZZ_COMPILED_SEGMENT_SIZE`. They are built with
`APKFUZZ_LOCK_COMPILED_MODE=1`, so the strategy is fixed for the campaign and
cannot be changed accidentally through the environment.

## Use with AFL

```bash
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=build/cm-ApkVulFuzz2.so
export APKFUZZ_MUTATOR_MODE=manifest-segment   # pick a strategy (see below)
afl-fuzz -i Evaluation-SSBSE-2026/input -o out -- .venv/bin/python3 afl/apk_pathfile_harness.py @@
```

## Files

| File | Role |
|---|---|
| `zip2.c/.h` | Extended ZIP analyzer: manifest data range **plus** local header, CRC/size fields, central directory extents. |
| `strategies.c/.h` | Mode parsing, per-mode region selection, mutation, logging. |
| `cm_ApkVulFuzz2.c` | AFL `afl_custom_*` glue + a `main()` (built with `-D APKFUZZ_STANDALONE`) for offline testing. |

## Modes (`APKFUZZ_MUTATOR_MODE`)

Default is `manifest-bitflip`, which reproduces the baseline behavior.

| Mode | Region targeted |
|---|---|
| `manifest-bitflip` | whole compressed `AndroidManifest.xml` data (baseline) |
| `manifest-segment` | `[start+OFFSET, start+OFFSET+SIZE)` inside the manifest |
| `manifest-start` / `manifest-middle` / `manifest-end` | first / middle / last third of the manifest |
| `zip-local-header` | the manifest's local file header |
| `zip-central-directory` | the whole central directory (usually breaks ZIP open) |
| `crc-fields` | manifest CRC-32 fields (local + central) |
| `size-fields` | manifest compressed/uncompressed size fields (local + central) |
| `random-range` | anywhere in the file, or `[OFFSET, OFFSET+SIZE)` if set |
| `manifest-axml-onebit` | as `manifest-valid-onebit`, and the decoded manifest must also stay a structurally sound Android binary XML document (chunk framing, string-pool bounds and termination, string references); a descendant that fails this restarts from the origin. Structure only: Android may still refuse the result |
| `manifest-valid-onebit` | one compressed manifest bit whose full deflate stream still decodes to the same length; updates both ZIP CRC fields |

## Tuning env vars

| Var | Meaning | Default |
|---|---|---|
| `APKFUZZ_SEGMENT_OFFSET` | region offset (relative to manifest start; absolute for `random-range`) | 0 |
| `APKFUZZ_SEGMENT_SIZE` | region size in bytes | manifest length / rest of file |
| `APKFUZZ_MAX_FLIPS` | fixed number of bit flips | random 1..50 (baseline) |
| `APKFUZZ_LOG` | `1` to append a structured line per fuzz iteration | off |
| `APKFUZZ_LOG_FILE` | log destination | `apkfuzz_mutator.log` |
| `APKFUZZ_OUT_DIR` | write each transient mutant here instead of next to the seed APK — keeps `Evaluation-SSBSE-2026/apk/` clean (created if missing) | next to seed |
| `APKFUZZ_SAVE_DIR` | if set, also copy every mutant APK into this dir (survives cleanup, so post-run tools have specimens) | off |

## Runtime mode vs compiled variants

`build/cm-ApkVulFuzz2.so` is flexible: `APKFUZZ_MUTATOR_MODE` can select a mode
when the AFL process starts. This is useful for debugging and short smoke tests.

For real comparisons, prefer the locked variants in `build/mutators/`. One AFL
campaign should use one compiled mutator, then the next campaign should use a
different compiled mutator. Do not change strategies during a single campaign;
otherwise crashes, hangs, and generated seeds cannot be attributed cleanly to one
strategy.

## Log line format

```
ts=<sec.nsec> mode=<mode> src=<seed.apk> manifest_found=<0|1> \
manifest=[start,end) region=[start,end) region_len=<n> flips=<k> out=<mutant.apk>
```

Grep `src=` across the log to prove AFL cycles multiple APKs; `mode=`/`region=`
show exactly what each iteration mutated.
