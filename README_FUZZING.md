# ApkVulFuzz — Structure-Aware APK Fuzzer

Fuzzing Android APKs as ZIP archives, the smart way. Instead of flipping random
bytes across a whole file, ApkVulFuzz locates meaningful structures **inside** the
APK — primarily the compressed `AndroidManifest.xml` — and mutates only those, so
almost every generated APK actually exercises real ZIP/manifest parsing code
instead of being rejected instantly.

> Built on **AFL++** using its **custom-mutator** API. The mutator finds the
> manifest dynamically from the ZIP structure (no hardcoded offsets) and supports
> **10 selectable mutation strategies**.

---

## Table of contents
- [1. Overview](#1-overview)
- [2. Requirements & download (installation)](#2-requirements--download-installation)
- [3. Repository layout](#3-repository-layout)
- [4. How it works (the workflow)](#4-how-it-works-the-workflow)
- [5. The two mutators: V1 vs V2](#5-the-two-mutators-v1-vs-v2)
- [6. How to operate it](#6-how-to-operate-it)
- [7. Configuration reference](#7-configuration-reference)
- [8. Verify your setup (2-minute test)](#8-verify-your-setup-2-minute-test)
- [9. Key finding: fuzzing multiple APKs](#9-key-finding-fuzzing-multiple-apks)
- [10. Limitations & notes](#10-limitations--notes)
- [11. Reproducible campaigns (readiness)](#11-reproducible-campaigns-readiness)

---

## 1. Overview

An APK is a ZIP archive. A normal fuzzer mutating an APK produces garbage that
fails the first ZIP check, so it never reaches interesting behavior. ApkVulFuzz is
**structure-aware**: it understands the ZIP layout, targets a specific region
(the manifest, a ZIP header, the central directory, a CRC field, …), and mutates
only there. The mutated APKs are then run through parsers and external tools to
find crashes, hangs, CRC/parse failures, and tool bugs.

**Pipeline in one line:** `AFL++` drives the loop → our **custom mutator** makes
each mutation APK-aware → a **harness** (or external ZIP/APK tools) executes the
mutant → we **triage and classify** the results.

---

## 2. Requirements & download (installation)

### 2.1 System requirements
- Linux (x86-64 recommended)
- `git`, `clang`, `make`, Python 3.8+
- **AFL++** (provides `afl-fuzz`, and its source is needed to compile the mutator)
- *(optional, for dynamic testing)* Android SDK + emulator + DroidBot — see the
  original project `README.md` for that setup.

### 2.2 Get the code
```bash
git clone https://github.com/NosMAki/ApkFuzz.git
cd ApkFuzz
```

### 2.3 Install AFL++ (engine + headers)
The mutator compiles against the AFL++ source, so clone it to `~/AFLplusplus`:
```bash
git clone https://github.com/AFLplusplus/AFLplusplus ~/AFLplusplus
cd ~/AFLplusplus && make && sudo make install     # provides afl-fuzz on PATH
cd -
afl-fuzz --version                                # sanity check
```

### 2.4 Python environment (for the harnesses)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install python-afl        # lets the Python harness report coverage to AFL
```

### 2.5 Build the mutators
```bash
cd src
AFLPP_DIR=~/AFLplusplus bash compile_afl_mutators.sh      # V1 → build/cm-ApkVulFuzz.so
AFLPP_DIR=~/AFLplusplus bash compile_afl_mutator_v2.sh    # V2 → build/cm-ApkVulFuzz2.so
AFLPP_DIR=~/AFLplusplus bash compile_afl_mutator_variants.sh
# V2 locked variants → build/mutators/cm-ApkVulFuzz2-*.so
cd ..
nm -D build/cm-ApkVulFuzz2.so | grep afl_custom          # expect init / fuzz / deinit
```

You're ready to fuzz.

---

## 3. Repository layout

```
src/custom_mutators/
  cm_ApkVulFuzz.c, bitflip.c, apk.c   V1 baseline mutator (frozen)
  v2/                                 V2 multi-strategy mutator
    zip2.c/.h        ZIP analyzer (manifest range + header/CRC/size/central-dir offsets)
    strategies.c/.h  the 10 strategies, region selection, logging, env config
    cm_ApkVulFuzz2.c AFL glue + standalone tester
  compile_afl_mutators.sh      builds V1  → build/cm-ApkVulFuzz.so
  compile_afl_mutator_v2.sh    builds V2  → build/cm-ApkVulFuzz2.so

afl/
  apk_pathfile_harness.py   target for the custom-mutator workflow
  apk_zip_harness.py        target for the plain py-AFL workflow

scripts/
  validate-corpus.py            validate APKs + (re)generate path-files
  run-corpus-smoke.sh           run a bounded fuzzing pass over the whole corpus
  triage-afl-output.py          summarize an AFL run (crashes/hangs/coverage)
  test-apk-tools.py             run mutants through external ZIP/APK tools + classify
  compare-mutators.py           compare several runs into one table

docs/
  QUICKSTART.md            short operate/test guide
  FUZZER_OVERVIEW.md       detailed architecture + talking points
  VERIFICATION_RUNBOOK.md  exact verification commands
  MUTATOR_COMPARISON.md    methodology for comparing strategies

Evaluation-SSBSE-2026/
  apk/     seed APKs
  input/   .txt path-files (one per APK; machine-specific absolute paths)
```

---

## 4. How it works (the workflow)

The one idea to understand: **AFL's seeds are not APKs — they are tiny text files
that each contain the path to an APK.** The mutator reads that path, does the
heavy APK work itself, and hands AFL back the path of the mutated APK.

```
 input/F-Droid.txt  ── contains ──►  "/…/apk/F-Droid.apk"
        │
        ▼
 afl-fuzz ── calls ──►  afl_custom_fuzz()  in cm-ApkVulFuzz2.so
        │                    1. read the APK path from the seed
        │                    2. load the real APK bytes
        │                    3. parse the ZIP → find AndroidManifest.xml's exact
        │                       byte range (EOCD → central directory → local header)
        │                    4. flip bits inside the chosen region (per strategy)
        │                    5. write the mutant to a scratch dir
        │                    6. return the mutant's PATH to AFL
        ▼
 afl-fuzz  writes that path into @@ and runs the target:
        │
        ▼
 python3 afl/apk_pathfile_harness.py @@   → opens the mutant as a ZIP, touches
        │                                    manifest / classes.dex / resources.arsc
        ▼
 AFL records coverage, saves crashes / hangs.
        │
        ▼
 (after the run)  triage-afl-output.py  +  test-apk-tools.py
                  summarize results and run mutants through external tools.
```

**Why the manifest?** It's stored *compressed* in the ZIP. Flipping bytes there
corrupts the DEFLATE stream and its CRC-32 — a malformed-but-structurally-valid
input that is exactly what stresses manifest/ZIP error handling.

---

## 5. The two mutators: V1 vs V2

Both are AFL++ custom mutators that locate the manifest dynamically and flip bits
inside it. The difference is control.

| | **V1** — `cm-ApkVulFuzz.so` | **V2** — `cm-ApkVulFuzz2.so` |
|---|---|---|
| Mutation | one fixed behavior: 1–50 random bit-flips across the whole compressed manifest | same by default, **plus 9 more strategies** |
| Choose target region | no | yes — manifest sub-parts, ZIP local header, central directory, CRC/size fields, random |
| Intensity control | no | yes — `APKFUZZ_MAX_FLIPS`, segment offset/size |
| Per-iteration logging | no | yes — `APKFUZZ_LOG` |
| Clean output / kept specimens | no | yes — `APKFUZZ_OUT_DIR`, `APKFUZZ_SAVE_DIR` |

> **Rule of thumb:** V1 is the simple baseline; V2 is for real experiments and
> comparisons. Use `build/cm-ApkVulFuzz2.so` for smoke/debug, and use the locked
> `build/mutators/cm-ApkVulFuzz2-*.so` variants for clean long-run comparisons.
> With no environment variables set, V2 behaves exactly like V1.

**V2 strategies** (`APKFUZZ_MUTATOR_MODE=<name>`):

| Strategy | Region mutated | Stresses |
|---|---|---|
| `manifest-bitflip` *(default)* | whole compressed manifest | the manifest (AXML) parser |
| `manifest-segment` | a sub-window inside the manifest | a localized manifest region |
| `manifest-start` / `-middle` / `-end` | first / middle / last third of the manifest | which part trips the parser |
| `zip-local-header` | the manifest's local file header | the ZIP local-header reader |
| `zip-central-directory` | the whole central directory | the ZIP directory reader |
| `crc-fields` | the manifest's CRC-32 fields | CRC validation logic |
| `size-fields` | the manifest's size fields | size/bounds handling |
| `random-range` | anywhere in the file | a blind baseline for comparison |

---

## 6. How to operate it

All commands run from the project root, with the Python venv activated
(`source .venv/bin/activate`).

**Step 1 — validate the corpus** (also regenerates the `input/*.txt` path-files
for your machine):
```bash
python3 scripts/validate-corpus.py --write-inputs
```

**Step 2 — run a fuzzing pass.** Arguments are `<seconds> <mutator.so> <strategy>`:
```bash
# short 20-second smoke with V2, default strategy:
bash scripts/run-corpus-smoke.sh 20 build/cm-ApkVulFuzz2.so manifest-bitflip

# a different strategy:
bash scripts/run-corpus-smoke.sh 20 build/cm-ApkVulFuzz2.so crc-fields
```
A healthy run prints `fuzzer_stats` (with `execs_done > 0`), lists the APKs it
mutated, and does **not** print `Smoke test FAILED`.

**Step 3 — keep the mutants and analyze** (for longer runs):
```bash
export APKFUZZ_SAVE_DIR=mutants-run1
bash scripts/run-corpus-smoke.sh 300 build/cm-ApkVulFuzz2.so crc-fields

python3 scripts/triage-afl-output.py afl-corpus-smoke-*/            # crashes/hangs/coverage
python3 scripts/test-apk-tools.py mutants-run1 --preserve crashers  # run mutants through unzip/7z/…
```

**Step 4 — compare strategies** (optional): run several modes into separate dirs,
then:
```bash
python3 scripts/compare-mutators.py bitflip=cmp-bitflip crc=cmp-crc \
  --tools bitflip=tools-bitflip.csv --tools crc=tools-crc.csv --csv comparison.csv
```

> For a campaign that must exercise **every** APK, run one AFL instance per APK
> (see §9 for why).

---

## 7. Configuration reference

**AFL++ variables**

| Variable | Meaning |
|---|---|
| `AFL_CUSTOM_MUTATOR_LIBRARY` | path to the mutator `.so` to load |
| `AFL_CUSTOM_MUTATOR_ONLY=1` | use only our mutator (disable AFL's own mutations) |

**Mutator variables (V2)**

| Variable | Meaning | Default |
|---|---|---|
| `APKFUZZ_MUTATOR_MODE` | which strategy (see §5) | `manifest-bitflip` |
| `APKFUZZ_SEGMENT_OFFSET` | region offset (from manifest start; absolute for `random-range`) | 0 |
| `APKFUZZ_SEGMENT_SIZE` | region size in bytes | manifest length / rest of file |
| `APKFUZZ_MAX_FLIPS` | fixed number of bit-flips | random 1–50 |
| `APKFUZZ_LOG` / `APKFUZZ_LOG_FILE` | log each iteration / where | off / `apkfuzz_mutator.log` |
| `APKFUZZ_OUT_DIR` | write transient mutants here (keeps the corpus clean) | next to the seed |
| `APKFUZZ_SAVE_DIR` | also keep a copy of every mutant here | off |

> The mutator reads these **once at startup**, so you pick the strategy **before**
> a run; it stays fixed for that run. To use a different strategy, start another run.

For the long experiments, prefer compiled variants instead of changing
`APKFUZZ_MUTATOR_MODE` manually. Each compiled `.so` fixes the strategy at build
time, so a 72-hour or 12-hour campaign has one clear mutator identity.

---

## 8. Verify your setup (2-minute test)

Hand this to a new teammate to confirm everything works:

```bash
# A. the mutator builds and exports the AFL hooks
cd src && AFLPP_DIR=~/AFLplusplus bash compile_afl_mutator_v2.sh && cd ..
nm -D build/cm-ApkVulFuzz2.so | grep afl_custom
#    EXPECT: afl_custom_init, afl_custom_fuzz, afl_custom_deinit

# B. the corpus is valid
python3 scripts/validate-corpus.py
#    EXPECT: every APK "USABLE" with a manifest_range

# C. a 1-second smoke actually runs AFL with our mutator
bash scripts/run-corpus-smoke.sh 1 build/cm-ApkVulFuzz2.so manifest-bitflip
#    EXPECT: prints fuzzer_stats; AFL says the custom mutator loaded;
#            does NOT print "Smoke test FAILED"
```
No-AFL sanity check of a single mutation:
```bash
APKFUZZ_MUTATOR_MODE=manifest-bitflip build/mut2-standalone Evaluation-SSBSE-2026/apk/F-Droid.apk
#    EXPECT: prints the path of a newly created mutant APK
```

---

## 9. Key finding: fuzzing multiple APKs

AFL loads every APK seed, but it only keeps fuzzing a seed that reaches **new
coverage**. Because seeds are path-files, AFL's coverage sees only the path
string, not the APK bytes — so if the harness does the same work for every APK,
AFL treats all but one as redundant and **fuzzes a single APK**. We confirmed this
with real `afl-fuzz` runs (a run stayed on one seed through 87 cycles; making
coverage depend on APK content immediately spread it across all seeds).

**Practical takeaway:** to fairly cover a whole corpus, run **one AFL instance per
APK**, or make the target's coverage depend on APK content. Details in
`docs/FUZZER_OVERVIEW.md` and `docs/VERIFICATION_RUNBOOK.md`.

---

## 10. Limitations & notes

- **Installability:** mutating compressed manifest bytes breaks the CRC, so most
  mutants won't install on a device. Reaching install/runtime (DroidBot/emulator)
  bugs needs a CRC-repair / re-zip step — future work.
- **Corpus:** grow it to ~20 *distinct* open-source APKs; avoid byte-identical
  duplicates (they add nothing). `validate-corpus.py` flags duplicates.
- **ZIP scope:** the parser targets standard ZIP/APK; Zip64 is not handled.
- **Path-files** in `Evaluation-SSBSE-2026/input/` contain machine-specific
  absolute paths — regenerate them locally rather than relying on committed ones.

---

*More depth: `docs/FUZZER_OVERVIEW.md` (architecture), `docs/MUTATOR_COMPARISON.md`
(strategy comparison method), `docs/VERIFICATION_RUNBOOK.md` (verification steps).*

---

## 11. Reproducible campaigns (readiness)

The mutator is **reproducible** and **cheap on disk**, so long runs are
attributable and repeatable.

### Reproducibility

Randomness is a per-instance xoshiro256++ seeded from AFL's seed (no global
`rand()`), so:

```
same AFL seed + same corpus + same mutator  =>  identical mutation sequence
different seed                              =>  different sequence
```

This holds across machines and libc versions. Pin the seed with
`APKFUZZ_AFL_SEED=<n>` (passed to `afl-fuzz -s`); it is recorded in every CSV row
and in each mutant's log line (`seed=`, `iter=`), so any queue entry or crash can
be reproduced exactly.

### Cheap disk

Transient mutants are written to tmpfs (`/dev/shm`) and reaped continuously
(`scripts/reap-scratch.py`), so physical disk I/O stays near zero regardless of
run length. For post-run analysis set `APKFUZZ_SAVE_DIR=dir`: the mutator saves a
small **patches** (origin + byte edits, with a parent patch for later generations)
per mutant instead of a multi-MB APK. Keep the entire patch directory: a
descendant depends on its ancestors. Legacy v1 descendant patches do not record
that dependency and `apply-patch.py` rejects them to avoid a false reconstruction.
Reconstruct the exact mutant when you need it:

```bash
python3 scripts/apply-patch.py path/to/mutant.patch -o mutant.apk --sha256
```

### Tests (gate every build)

```bash
bash scripts/run-tests.sh     # reproducibility + 17 variants + patch lineage
```

For the bounded, serial random-mutator experiment, see
[`docs/RANDOM_CAMPAIGN_READY_2026-10-05_HE.md`](docs/RANDOM_CAMPAIGN_READY_2026-10-05_HE.md).

`test_variant_sanity.sh` asserts each locked `.so` only edits the ZIP structure
its name promises (computed independently from the ZIP layout, not the mutator's
own log), so a mis-compiled variant can't silently burn a run.

### The two campaign questions (keep them separate)

```bash
# Q1: does splitting the budget help?  one long run vs many short runs.
LONG_SECONDS=600 SHORT_SECONDS=100 SHORT_RUNS=6 \
  scripts/run-duration-comparison.sh          # rehearsal; raise to 259200/43200 for 72h/12h
# 1x72h vs 6x12h is n=1 vs n=6 -> read it as union-of-coverage. For mean+variance
# set REPEATS=3 (=> 3x72h vs 18x12h) and budget the machine time.

# Q2: which strategy is best?  loops every locked variant with repeats.
SECONDS_PER=60 REPEATS=2 \
  scripts/run-mutator-comparison.sh           # rehearsal; raise SECONDS_PER for real runs
```

Both write a normalized CSV (`run_id, arm, repeat, mutator, effective_mode, seed,
metrics…, fallback_count, machine_state, git_sha`), a `machine-state.txt`
snapshot, and per-run patches. `effective_mode` comes from the mutator itself, so
a locked variant is reported by what it actually did, not the environment.

### Before the long runs

1. `scripts/run-tests.sh` is green.
2. Rehearse both scripts (above) and eyeball the CSVs + `machine-state.txt`.
3. Confirm physical disk I/O stays low (printed in each smoke summary).
4. Only then raise the durations.
