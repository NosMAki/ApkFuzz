# Bounded F-Droid locked-arm acceptance, 2026-11-04

## Scope and procedure

Authorized local target: `Evaluation-SSBSE-2026/apk/F-Droid.apk` (SHA-256
`1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`).
Question: can the existing AFL++ path-file harness run each selected locked
mutator independently while preserving exact candidates and preflight evidence?
The independent variable was the locked mutator. Each arm used a single path
file pointing to that APK, a fixed AFL seed, ten seconds, candidate capture
limit three, and its own new output directory. This was acceptance testing,
not the planned 72-hour experiment.

```bash
bash scripts/run-fdroid-locked-arm.sh random-range 10 10407 results/fdroid-locked-random-2026-11-04
bash scripts/run-fdroid-locked-arm.sh manifest-bitflip 10 10408 results/fdroid-locked-manifest-2026-11-04
```

The wrapper checked disk/tmpfs headroom and absence of another AFL process,
then recorded Git HEAD, working-tree status, source hashes, APK/mutator hashes,
seed, duration, AFL++ version, raw run log, fuzzer stats, patch files, exact
captured candidates, and candidate preflight under ignored `results/`.
AFL++ was `4.09c`; Git HEAD was `96f82a05f0376d4f79b897b72f6a6d17d907143d`
with substantial uncommitted integration work. The random-range `.so` SHA-256
was `473051b51f5b2316480bbfa841d1bc7ea78f816939dbad0e190d4f3736600ef8`;
manifest-bitflip was `b0df959e80771f92ff380f6d5ef9fb77ef3b666a9247bd0b1f76457fc433204e`.

## Observations

| Arm | Exit | Effective mode | Executions | Corpus count | AFL crashes / hangs | Exact candidates captured | Preflight |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| random-range, seed 10407 | 0 | random-range, locked | 433 | 6 | 0 / 0 | 3 | 3 blocked |
| manifest-bitflip, seed 10408 | 0 | manifest-bitflip, locked | 423 | 2 | 0 / 0 | 1 | 1 blocked |

Each capture's patch integrity and preserved APK hash matched. The four ZIP
checks failed (one `bad_entry`, three `invalid`), and all four signature
checks failed. Manifest validation could not proceed. None was installed or
sent to paired replay. `research_ready` in the capture manifest indicates
preservation and provenance, not Android runtime eligibility. No application
defect or vulnerability is claimed.

`bash scripts/run-tests.sh` passed, including the two APK-tool classification
tests added in the prior handoff. `python3 scripts/validate-corpus.py --report
results/fdroid-corpus-validation-2026-11-04.json` exited 0 and found both
corpus APKs usable as source files. The wrapper's sequential `--check`
preflights passed for both modes. `bash -n` and `git diff --check` passed.
After these runs, the wrapper's post-run checks were tightened to require
the expected source/mode log entries and capture manifest. The saved logs
and manifests satisfy those checks, but the tightened wrapper has not yet
been exercised in another AFL run.

## Limits and next action

Ten seconds per arm tests setup and preservation, not long-run stability,
coverage, crash rate, or relative effectiveness. The fixed seeds differ
between arms and are for traceability, not a controlled comparative result.
Review these results before starting the selected sequential 72-hour arms.
For LLMDroid acceptance, pursue a runtime-eligible original/mutant pair and
clean-state original/original replay separately.
