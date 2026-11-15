# F-Droid two-arm 72-hour readiness, 2026-11-04

## Design and launch

The authorized target is the local `Evaluation-SSBSE-2026/apk/F-Droid.apk`
(SHA-256 `1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`).
The planned experiment has two separate continuous 72-hour arms on that APK:
locked `random-range` first, then locked `manifest-bitflip`. No 72-hour arm
has started. `scripts/run-fdroid-72h-sequence.sh` makes the order explicit,
rechecks both arms before starting, and stops before the second if the first
fails. Each arm has a separate fixed seed, output directory, patch store,
candidate capture, preflight report, and source/configuration hashes.
The sequence now freezes non-mode mutator overrides and selects up to 12
queue candidates per arm using a deterministic sample seeded by the AFL seed.
The [agent readiness evidence](../fdroid-agent-readiness-2026-11-04/README.md)
records the matching original and test-signed F-Droid traces, paired controls,
and a bounded prepared-mutant check. Agent analysis runs after AFL stops and
only for a verified install-eligible pair.

The launch identifier used for readiness is `2026-11-04a`. Run a new check
immediately before launch, using a fresh identifier if these output names
exist:

```bash
cd /home/sahar/Projects/ApkVulFuzz
bash scripts/run-fdroid-72h-sequence.sh --check 2026-11-04a
```

For a persistent terminal, start a `tmux` session, then run the sequence
inside it with sleep inhibition. Detach with Ctrl-b, then d. To inspect it
later, use `tmux attach -t apkfuzz72h`.

```bash
tmux new-session -s apkfuzz72h
systemd-inhibit --what=sleep:idle --mode=block --why='APKVulFuzz two 72-hour AFL runs' bash scripts/run-fdroid-72h-sequence.sh --start 2026-11-04a
```

The start command has **not** been run. It would occupy up to six days in
total. `tmux` and `systemd-inhibit` are installed; a read-only sleep-inhibitor
probe succeeded outside the restricted command environment. AC mains was
online at readiness time. Do not replace the two arms with the older
duration-comparison schedule.

## Final bounded verification

The current wrapper and inode guard were exercised in separate 30-second
runs with the same seeds selected for the long arms:

```bash
bash scripts/run-fdroid-locked-arm.sh random-range 30 10407 results/fdroid-readiness-random-2026-11-04
bash scripts/run-fdroid-locked-arm.sh manifest-bitflip 30 10408 results/fdroid-readiness-manifest-2026-11-04
```

| Arm | Exit | Executions | Corpus | Patches | AFL crashes / hangs | Captures | Android preflight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| random-range | 0 | 1,167 | 10 | 1,058 | 0 / 0 | 3 | 3 blocked |
| manifest-bitflip | 0 | 1,129 | 2 | 1,075 | 0 / 0 | 1 | 1 blocked |

Both mutator logs reported the requested effective mode and `locked=1` on
the F-Droid source. Captured APK hashes and patch chains matched. All four
candidates failed ZIP/signature preflight, so none was an Android runtime
result. The source APK is usable in corpus validation. `bash scripts/run-tests.sh`,
shell syntax checks, and `git diff --check` passed. The sequence's `--check`
passed for both arms without creating output directories.

Mutator SHA-256 values: `random-range`
`473051b51f5b2316480bbfa841d1bc7ea78f816939dbad0e190d4f3736600ef8`;
`manifest-bitflip`
`b0df959e80771f92ff380f6d5ef9fb77ef3b666a9247bd0b1f76457fc433204e`.
The runs used AFL++ `4.09c`. Exact commands, source hashes, config, stats,
patches, and preserved candidate hashes are under the ignored `results/`
paths named above.

## Capacity and stop conditions

At readiness time `/dev/shm` had about 7.6 GiB free; the project filesystem
had about 267 GiB and 26.6 million inodes free. AC mains was online. The
30-second runs saved about 35–36 patch files per second and about 4.3 MiB
of patch data each. A straight-line projection is roughly 9.1–9.3 million
patch files and 37 GiB of patch data per 72-hour arm, or 18.4 million files
and 74 GiB across both. This is a planning estimate, not a measured 72-hour
rate; AFL queue growth and metadata overhead may change it substantially.

The wrapper refuses an existing output path, concurrent AFL instance, low
initial tmpfs/disk/inodes, or missing APK/mutator. During each arm, the
existing runner stops if the scratch reaper dies, the mutator reports a
load/write failure, free tmpfs falls below 1 GiB, free output disk falls
below 2 GiB, or free output inodes fall below one million. The AFL queue
retains live mutant APKs on tmpfs, so queue growth could still end an arm
early. Inspect `outcome.txt`, `run.log`, `afl/default/fuzzer_stats`, and
`afl/watchdog-error.txt` for each arm. A stopped arm is incomplete, not a
72-hour result.

The long runs measure AFL campaign behavior. Exact candidate capture and
preflight do not establish Android installability, a target-app crash, or a
security vulnerability. No long-run results have been claimed.
