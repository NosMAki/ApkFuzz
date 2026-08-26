# Next Meeting Status

## Working

- AFL++ is installed and `/usr/bin/afl-fuzz` runs.
- py-AFL is installed in the project virtual environment.
- AFL++ source is available under `~/AFLplusplus`.
- The custom mutator compiles successfully.
- `build/cm-ApkVulFuzz.so` exports:
  - `afl_custom_init`
  - `afl_custom_fuzz`
  - `afl_custom_deinit`
- Corpus path files validate.
- The py-AFL smoke test runs and produces `afl-smoke-output/default/fuzzer_stats`.
- The custom-mutator smoke test runs and produces `afl-custom-smoke-output/default/fuzzer_stats`.
- Local `apk.c` dynamically finds `AndroidManifest.xml`; it does not rely on a hardcoded APK offset table.
- DroidBot `-aa <path-file>` support has been added to the local DroidBot checkout under `/home/sahar/Projects/droidbot`.

## Fixed

- `src/custom_mutators/bitflip.c` no longer reuses the manifest start offset as the loop counter.
- Bit flips are constrained to the dynamically located compressed `AndroidManifest.xml` byte range.
- `src/compile_afl_mutators.sh` now supports `AFLPP_DIR`, defaulting to `$HOME/AFLplusplus`.
- The corpus setup flow can regenerate `.txt` path-file seeds from the local checkout.
- Smoke scripts run AFL++ with short default durations and print the beginning of `fuzzer_stats`.
- Generated build and AFL smoke output directories are ignored by Git.

## Tests Run

```bash
bash -n scripts/setup-evaluation-corpus.sh
bash -n scripts/run-py-afl-smoke.sh
bash -n scripts/run-custom-mutator-smoke.sh
python3 -m py_compile afl/apk_pathfile_harness.py
cd src && bash compile_afl_mutators.sh
nm -D ../build/cm-ApkVulFuzz.so | grep afl_custom
cd .. && bash scripts/setup-evaluation-corpus.sh
bash scripts/run-py-afl-smoke.sh 1
bash scripts/run-custom-mutator-smoke.sh 1
```

## What The Successful Outputs Prove

- AFL++ can start the Python APK harness with real APK seeds.
- py-AFL integration is available enough for the Python harnesses to initialize under AFL++.
- AFL++ can load `build/cm-ApkVulFuzz.so` as a custom mutator.
- The custom mutator can process path-file seeds and produce AFL queue activity.
- The generated `fuzzer_stats` files prove both smoke modes reached AFL's normal run loop instead of failing during setup or dry-run validation.

## Still To Discuss

- Whether APK CRC repair/rebuilding is required after mutating compressed APK bytes.
- Whether DroidBot should treat install failures as crashes, hangs, or normal invalid mutations.
- Whether the py-AFL harness is only a smoke test or part of the evaluation.
- How many APKs should be used for the final corpus.
- Whether mutated APKs should be saved for post-analysis.

## Next Meeting Plan

- Build many v2 mutators with compile-time strategy flags instead of relying only
  on runtime mode selection. Runtime mode remains useful for smoke/debug, but the
  long experiments should use one locked `.so` per strategy so the results are
  attributable.
- Keep AFL seeds as path-files only. Extra metadata in the seed is not useful for
  the current custom mutator because AFL mutates the seed bytes, while the mutator
  only needs the APK path. If metadata is needed later, keep it in a sidecar
  manifest/CSV instead of inside the AFL seed.
- Run long campaigns on Harel's laptop to verify AFL stability over time.
- Expand the APK corpus with small APKs, preferably under 1 MB each.
- Compare one 72-hour run against six 12-hour runs. Aggregate:
  - generated queue entries / seeds
  - hangs
  - crashes
  - odd ZIP/APK/tool results
- Compare mutated APKs against their originals to understand what changed and
  which changes might be exploitable.
- Ask Aidan about additional target programs/tools that should consume mutated
  APKs.

## New Tooling For The Next Phase

- `src/compile_afl_mutator_variants.sh` builds locked v2 `.so` files under
  `build/mutators/`, one per strategy/region configuration.
- `scripts/run-campaign-comparison.sh` runs the planned `72h` vs `6 x 12h`
  campaign shape. It uses AFL's time limit, so runs stop automatically.
- `scripts/diff-mutated-apk.py` compares an original APK to a mutant using raw
  byte ranges and ZIP metadata, even when the mutant is not a valid ZIP.
