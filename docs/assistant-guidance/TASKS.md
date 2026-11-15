# APKVulFuzz active task board

## Current objective

Complete and verify the LLMDroid differential-testing extension described in
[LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md). Report experimental
limits without claiming a coverage gain or vulnerability that was not measured.

## Now

- [x] Define gate-v3 fatal/manifest-rejection and ANR/transport-timeout
  classes, with bounded log evidence and fingerprint fields. The local
  baseline/inert/crasher/baseline device controls passed; the known crasher
  produced one fingerprint in 15 raw fatal blocks during one install.
  Three 120-second AFL seeds passed source/input integrity checks and each
  preserved one exact ZIP/manifest-valid but signature-invalid mutant.
  The full regression suite passes. See [oracle](../ORACLE.md),
  [control review](../../results/oracle-controls-2026-11-15/REVIEW.md), and
  [three-seed review](../../results/paper-afl-seeds-2026-11-15/REVIEW.md).

- [x] Classify the 16,024 accepted first-generation flips by what they change
  (2026-11-15, offline). 4,528 change no tag, attribute identity, or typed
  value; 3,247 change exactly one thing; the rest change several. The parser
  matches Androguard exactly on the original manifest. One of four
  pre-stated predictions missed by a single case and exposed a model gap:
  1,123 flips change only an attribute's raw value, which Android read for a
  `<category>` name and which Androguard reads generally. See
  [semantics review](../../results/gen1-flip-semantics-2026-11-15/REVIEW.md).

- [x] Enumerate the whole first-generation space offline (2026-11-15): of
  71,368 one-bit flips of F-Droid's compressed manifest, 16,024 are accepted by
  `manifest-axml-onebit`; three cross-checks against saved C-mutator patches
  agree exactly. In a uniform sample of 120 accepted flips, 93 passed the
  device launch gate (77.5%, Wilson 95% 69.2–84.1%); 37 of 37 repeated probes
  agreed. A harness decoding fault was fixed and launch-command timeouts are
  now classified by crash evidence. See
  [enumeration review](../../results/gen1-enumeration-2026-11-15/REVIEW.md).

- [x] Measure device admission for generation one and trace the 2026-11-12
  generation-two failure (2026-11-15). The diagnostic's single queue parent
  fails to install by itself, so its 30 "ready" children measured one
  inherited defect. Of 38 generation-one offline-ready mutants, 22 launched
  healthily, 13 failed to install, 3 crashed at start. See
  [generation-one check](../../results/gen1-device-admission-2026-11-15/REVIEW.md).

- [x] Add the opt-in `manifest-axml-onebit` variant (binary-XML structure kept
  sound; broken descendants restart from the origin), reject `aapt` resource
  warnings offline, strengthen the device launch gate, and require it before
  LLMDroid admission. Full suite passes (20 variants). In a 120-second run
  (seed 10435), 28 of 40 probed generation-two mutants passed the device gate;
  an original/original control and one generation-two pair replayed eight
  actions with no divergence. All samples descend from one parent. See
  [gate and variant check](../../results/axml-admission-gate-2026-11-15/REVIEW.md).

- [x] Complete the local 12-hour readiness checks: the eight-action
  original/original control and real first-generation queue pair both
  completed without observed divergence. A ten-minute locked run was stable
  but produced two manifest-invalid queue entries; its seven selected live
  descendants failed `aapt`. A separate dense 120-second diagnostic found
  30/55 generation-two offline-ready signed pairs, but only 2/30 installed
  on Android and none had a running F-Droid process after the launcher check;
  LLMDroid's parser accepted 0/30. **No-go** for a 12-hour Android-candidate
  run. See the [readiness review](../../results/manifest-valid-onebit-readiness-2026-11-12/REVIEW.md).

- [x] Add an opt-in ZIP-preserving, one-bit manifest mode and bounded
  first-generation live capture. In a 30-second local run, one real queue
  mutant had verified exact lineage and valid ZIP/manifest; 20/25 selected
  live samples passed offline signed-pair checks. Its separate test-signed
  mutant and matched baseline both installed and launched on a fresh offline
  Android 29 emulator. Full suite passes. See the
  [acceptance report](../../results/manifest-valid-onebit-local-30s-2026-11-12-10432/REVIEW.md).

- [x] Complete the authorized 7,200-second local F-Droid `manifest-onebit`
  arm: 275,810 harness executions, three exact queue captures, 144 separate
  exact live-mutation captures, and zero raw or prepared runtime candidates
  from those captured sets. A reconstructed-only screen of all 848
  generation-one patches found 271 transient signed derivatives; the live
  sampler selected none from that generation. Full local suite passes. See
  [two-hour review](../../results/fdroid-local-2h-2026-11-12-onebit-10420/REVIEW.md).

- [x] Run the local 600-second locked `manifest-onebit` pilot: 23,133 harness
  executions, two new queue entries, 2/2 captured and provenance-verified
  exact APKs, 0/2 ZIP/signature valid, and 0/2 eligible for install. A narrow
  CRC-repair attempt exposed malformed Android XML despite `aapt` exit 0;
  preparation and signing did not complete. The three offline metadata gates
  now reject that warning, and the full suite passes. See
  [pilot evidence](../../results/fdroid-pilot-2026-11-12-local-manifest-onebit-10415/REVIEW.md).

- [x] Screen a fixed-seed offline sample of 248 saved pilot patches: all 48
  generation-one and 200 of 23,011 generation-two. All raw reconstructions
  failed ZIP/signature preflight; CRC repair and signing passed local tool
  gates for 12 and 6 respectively. These were transient, reconstructed-only
  artifacts, not live captured or installed candidates. See the same pilot
  evidence for the ancestry and denominator limits.

- [x] Complete a local evidence-driven readiness review after the user-reported
  VM `random-range` 72-hour arm. Fix stage denominators, fallback reason
  logging, provenance snapshots, and Python AFL dependency checks; build and
  offline-check a separate one-bit manifest pilot variant. Full local suite
  passes. VM raw artifacts and Android runtime results remain unverified. See
  [review report](../../results/local-readiness-review-2026-11-12/REVIEW_REPORT.md).

- [x] Complete a sequential 20-minute F-Droid acceptance test: ten minutes
  per locked mode, both exit 0, no saved AFL crash/hang, 14/14 exact captures
  verified, and 0/14 candidates runtime-eligible. The agent gate recorded
  zero ready pairs without API calls. See
  [evidence](../evidence/fdroid-20min-2026-11-04/README.md).
- [x] Verify F-Droid agent controls before the long campaign: original and
  test-signed guided traces made ELM requests, each passed an identical-APK
  replay, and one separate prepared one-bit AFL mutant completed repeated
  paired replay plus guided exploration of both roles. See
  [agent evidence](../evidence/fdroid-agent-readiness-2026-11-04/README.md).
- [x] Add a post-AFL agent stage with exact/prepared pair admission, a fresh
  identical-baseline control, repeated replay, bounded guided roles, and an
  explicit no-eligible-pair result. The two main long arms now select at most
  12 exact queue candidates each with seeded sampling after AFL stops.
- [x] Prepare the two sequential 72-hour F-Droid arms. The current wrapper,
  inode guard, two 30-second readiness runs, suite, corpus validation, and
  `--check` passed. See [runbook](../evidence/fdroid-72h-readiness-2026-11-04/README.md).
- [x] Add an isolated single-F-Droid locked-arm wrapper and complete bounded
  ten-second acceptance for `random-range` and `manifest-bitflip`. Both passed;
  all four captured candidates failed runtime preflight. See
  [evidence](../evidence/fdroid-locked-arms-2026-11-04/README.md).
- [x] Mark a guided run that stops below its configured action limit as
  `partial` and return a nonzero command status.
- [x] Surface the observed upstream event-generation exception explicitly even
  if the action limit was reached. The runner now reports `inconclusive` and
  preserves the separate budget outcome; focused and full tests pass. A new
  device run has not yet exercised this path.
- [ ] Establish a repeatable clean device state for paired replay, then rerun
  original/original controls on the onboarding app. Record synchronization and
  infrastructure failures separately.

## Next

- [ ] Run a stratified paired-replay batch (about 100 pairs) drawn by class
  from the 3,247 single-difference flips, with inert flips as negative
  controls. A long AFL run in this mode would only resample the population in
  `results/gen1-enumeration-2026-11-15/enumeration.tsv`. Not started.
- [ ] Reader-disagreement study of the 1,123 raw-value-only flips: compare the
  value reported by `aapt`, Androguard, and Android's package manager for the
  affected attribute. Relevant because LLMDroid parses with Androguard. Not
  started; do not call all 1,123 verified three-reader disagreements.
- [ ] Optional: full device pass of all 16,024 accepted flips (about 25 hours),
  a multi-generation check, or AFL feedback that reflects Android. None is
  started or authorized.
- [ ] Independently inspect the user-reported completed VM `random-range` arm's
  raw artifacts before treating its counts as verified. The second
  `manifest-bitflip` 72-hour arm has not been reported as run.
- [ ] After each long arm, report exact candidate admission and run the agent
  stage only for verified runtime-eligible pairs. Do not count the separate
  one-bit feasibility candidate in the long-arm denominator.
- [ ] Measure runtime admission and paired replay success across multiple
  real AFL queue mutants, retaining exact and prepared hashes separately.
- [ ] Verify multi-candidate queue processing and repeated reproduction on
  real candidate pairs without disrupting AFL++.
- [ ] Run the repeated multi-app evaluation and report denominators, runtime,
  UI/activity observations, replay success, false positives, and ELM usage.

## Parked design idea

- [ ] Consider an unattended, eventually 24/7 candidate pipeline after a
  bounded pilot shows useful new Android-ready or behaviorally distinct
  candidates. Use AFL as one input generator; retain stage counts and run
  identities for every batch, full artifacts for novel outcomes and failures,
  and bounded samples of routine invalid attempts. Keep exact mutants and
  signed derivatives distinct. Add disk/CPU limits, control checks, and stop
  conditions. This is an idea to evaluate, not an authorized continuous run.

## Confirmed constraints

- None of 34 exact mutants in the bounded feasibility sample installed.
- A fixed-seed 10-second AFL++ rehearsal on 2026-11-03 preserved one exact
  candidate, but ZIP and signature preflight blocked runtime analysis. A fresh
  ELM control run made one model call and recorded three of twelve requested
  actions before a teardown/state-collection error; its smoke report's
  `completed` status is not a complete 12-action result.
- The onboarding `SKIP` action was absent during paired replay of a corpus
  app; recent software-emulator retries also encountered log and watchdog
  failures. These are inconclusive infrastructure/synchronization outcomes.
- The user asked to defer the Amazon proposal work until this project work is
  finished.

## Last verified checkpoint

- The repository regression suite passed locally on 2026-11-15 after the
  structure-check variant and gate changes (`bash scripts/run-tests.sh`,
  20 variants). Generation-two mutants from the new variant passed the device
  gate (28 of 40 probed) and one pair completed eight-action replay. The suite
  passed again after the enumeration-step probe fixes. Behavioral testing of
  enumerated mutants, later generations, AFL app feedback, and VM raw artifact
  review are pending. Nothing from 2026-11-15 is committed.
- Local evidence and detailed stage status are linked from
  [LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md).
- This file is a task index; verify current Git status and results before a
  new experiment.
