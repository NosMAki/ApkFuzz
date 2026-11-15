# Bounded exact-mutant feasibility sample, 2026-10-28

The sampler ran one deterministic mutation from each of the 17 built V2
operators against each of the two existing evaluation APKs (seed 5): 34 exact
mutants. It used `scripts/sample-mutation-feasibility.py` and stored the bytes,
per-mutant hashes, tool hashes, emulator fingerprint, and classifications in
ignored `results/mutation-feasibility-corpus-2026-10-28/feasibility.json`.
This was a bounded sample, not a fuzzing campaign or a population estimate.

| Input | Exact mutants | ZIP structure readable | All ZIP CRCs valid | Manifest parsed by `aapt` | APK signature valid | Installed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| F-Droid | 17 | 12 | 3 | 2 | 0 | 0 |
| Flashlight | 17 | 11 | 3 | 2 | 0 | 0 |
| Total | 34 | 23 | 6 | 4 | 0 | 0 |

All 34 outputs were byte-distinct from their originals and all 34 were
attempted on the isolated Android 29 emulator. Neither exact mutant installed,
so none reached a process-start check. Both unmodified source APKs installed
and had a live process after launch on the same emulator. The 0/34 runtime
eligibility observation is therefore about these exact mutants, with a working
device control, and should not be generalized beyond this seed and corpus.

The previously prepared manifest pair remains a separate runtime track: its
repaired and re-signed APKs have different hashes from the exact AFL mutant.
The preparation and installation evidence is in
[the earlier artifact study](../manifest-runtime-preparation-2026-10-21/README.md).
Runtime studies must label the transformed pair accordingly; they cannot
attribute its behavior to the unchanged exact-mutant bytes.
