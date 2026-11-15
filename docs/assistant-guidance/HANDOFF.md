# APKVulFuzz handoff checkpoint — 2026-11-15

## Latest checkpoint: oracle and paper evidence boundary

Gate-v3 oracle code and [definition](../ORACLE.md) separate package fatal
events, suspected manifest rejection, ANR logs, and infrastructure timeouts.
The [real local control check](../../results/oracle-controls-2026-11-15/REVIEW.md)
passed baseline/inert/crasher/baseline on a clean Android 10 emulator; the
known crasher logged 15 fatal blocks with one fingerprint in one install and
was flagged as manifest rejection. The emulator was shut down. Synthetic
tests cover ANR and unavailable-log cases; no real ANR was induced.

The [three-seed 120-second check](../../results/paper-afl-seeds-2026-11-15/REVIEW.md)
finished with identical source/input snapshots and one provenance-verified
exact ZIP/manifest-valid mutant per seed. Every exact signature failed; no
Android app was tested in that batch. An initial seed 10441 attempt had
source drift, was preserved and excluded, then rerun successfully. The later
oracle-only addition of distinct-fingerprint arrays has synthetic tests but
was not in the earlier control/AFL source snapshots. Final full suite passed;
nothing is committed. [Paper framing](../PAPER_FRAMING.md) treats 1,123
raw-value-only flips as a candidate class, not proven three-reader
disagreements.
The [curated paper evidence package](../../results/paper-artifact-2026-11-15/README.md)
contains 81 hash-verified files; it excludes APK binaries and large UI logs.

**Next action:** run the direct `aapt`/Androguard/Android reader study on a
predeclared sample of the 1,123 raw-value-only flips, with the named controls
and the current oracle, then decide if a broader behavioral batch is useful.
The 12-hour app-behavior run is still not cleared by these checks.
A possible unattended candidate pipeline, with stage counts and retention of
novel failures, is parked in [TASKS.md](TASKS.md); no continuous run was started.

## Latest result, 2026-11-15: Android admission blocker addressed; long-run purpose open

Two bounded local checks were authorized and completed; nothing is committed.

1. [Generation-one device check](../../results/gen1-device-admission-2026-11-15/REVIEW.md):
   the 2026-11-12 diagnostic's single queue parent fails Android installation
   by itself, and all its sampled children inherited that string-pool defect.
   Of 38 generation-one offline-ready mutants, 22 launched healthily.
2. [Gate and variant check](../../results/axml-admission-gate-2026-11-15/REVIEW.md):
   new opt-in `manifest-axml-onebit` variant, stricter offline gates, a device
   launch gate (process, no fatal exception, baseline activity) required
   before LLMDroid admission. `bash scripts/run-tests.sh` passes (20 variants);
   the 19 earlier mutator binaries are unchanged. A 120-second run (seed
   10435) gave 28 of 40 probed generation-two mutants passing the device gate
   and two eight-action replays with no divergence. The emulator is shut down.

Confirmed facts: the code diff is `results/axml-admission-gate-2026-11-15/code-changes.patch`
against snapshots in that folder's `prework/`. Assumptions not yet tested:
admission past generation two, from more than one parent, or on another app.
AFL's Python harness reported no new coverage for structurally valid mutants,
so its queue stayed at the seed plus the first mutant.

3. [Enumeration](../../results/gen1-enumeration-2026-11-15/REVIEW.md): all
   71,368 first-generation flips classified offline; 16,024 accepted; 93 of a
   uniform sample of 120 passed the device gate. The probe now tolerates
   undecodable tool output and classifies launch-command timeouts by crash
   evidence; the suite passes.

4. [Semantic classification](../../results/gen1-flip-semantics-2026-11-15/REVIEW.md):
   each accepted flip labeled by what it changes (`classification.tsv`);
   3,339 inert, 1,123 raw-value-only, 3,247 single-difference. Offline only.

**First action next session:** with the user's go-ahead, run either the
stratified paired-replay batch or the raw-value reader-disagreement study
described at the end of the semantics review. Do not repeat the 10434 parent
analysis, the generation-one cohort probe, the enumeration, or the
classification; read `enumeration.tsv` and `classification.tsv` instead.

## Earlier checkpoint — 2026-11-12

## Latest 12-hour readiness result: no-go

The user authorized the three local pre-run checks. An eight-action
original/original control and eight-action real first-generation AFL queue
mutant pair completed with every step `ok` and no divergence observed. A
ten-minute `manifest-valid-onebit` AFL pilot (seed `10433`) exited cleanly,
performed 22,165 Python-harness executions, logged no fallback, preserved two
new exact queue entries with verified patches, and captured 31/31 selected
live samples without hitting its 4 GB budget. Both queue entries failed
manifest preflight; all seven selected descendants failed `aapt`.

A separate 120-second diagnostic (seed `10434`, denser 1/50 descendant
sampling) captured 90/90 live descendants and verified ZIP/patch lineage.
Thirty of 55 generation-two outputs passed offline signed-pair checks. The
actual offline Android 29 device admitted only 2/30 installs, with no F-Droid
process running after the launcher check. LLMDroid's pinned Androguard parser
accepted 0/30 with the expected package. One failed paired replay is
inconclusive because parsing stopped before Android installation; it is not
an app defect. All 30 device checks cleaned up and the emulator is shut down.
The full [readiness review](../../results/manifest-valid-onebit-readiness-2026-11-12/REVIEW.md)
contains commands, hashes, cohorts, and raw-artifact links. **Do not start a
12-hour run intended for Android behavior from this state.** The next
engineering gate is Android binary XML/launcher preservation or early
rejection for later-generation mutants, then a fresh live descendant and
device replay check. AFL still measures the Python harness.

## Latest local fix and device acceptance

The user asked to fix the candidate-generation failure before another long
run. A separate locked `manifest-valid-onebit` mode now accepts one compressed
manifest bit change only when full deflate decoding and ZIP CRC fields remain
consistent. The Python AFL harness reads the complete bounded manifest, and
the live sampler deliberately retains a labeled first-generation prefix. The
queue preparer and offline analyzer keep exact mutants separate from signed
derivatives. Existing long-arm modes and historical artifacts were preserved.

A 30-second local AFL++ run (seed `10432`) completed 1,171 harness executions,
one new queue entry, one captured and patch-verified exact APK with valid ZIP
and manifest, and zero saved harness crashes/hangs. Of 25 selected live
mutations (24 targeted generation one, one sampled generation two), all 25
had verified lineage and valid ZIP; 20 passed offline signed-pair checks.
The real queue mutant's separate test-signed artifact and matched signed
baseline both installed and launched with a running F-Droid process on a
fresh offline Android 29 emulator; both were uninstalled and the emulator
was shut down. `bash scripts/run-tests.sh` and `git diff --check` pass. Exact
commands, hashes, denominators, and caveats are in the
[acceptance report](../../results/manifest-valid-onebit-local-30s-2026-11-12-10432/REVIEW.md).

The local install/launch feasibility gate is cleared for one real queue
mutant. AFL still measures the Python harness, not F-Droid app behavior. Next:
bounded paired Android UI replay on a real prepared queue mutant with
original/original controls, then a runtime-feedback/throughput plan before a
long campaign aimed at application behavior. The prior VM fallback count
requires its raw logs. Do not infer vulnerabilities from the zero harness
crash count.

## Latest two-hour local run and next gate

The user authorized a local two-hour AFL++ run before any further VM work.
The fixed-seed `manifest-onebit` arm (`10420`) completed 7,200 seconds with
275,810 harness executions, three new AFL queue entries, 3/3 exact queue
captures and verified patch lineages, and zero saved harness crashes/hangs.
Runner, watcher, source, and input integrity checks passed. All three queue
APKs failed ZIP/signature preflight. A separate deterministic live mutation
sample preserved 144/144 selected descendants with verified lineage; all
failed raw ZIP and manifest CRC-repair screening. It selected zero generation
one outputs, so it does not estimate first-generation live candidate yield.
The mutator logged 275,713 one-bit operations with no fallback. No Android
install, application run, model call, network, or VM operation was performed.

An offline, reconstructed-only screen of all 848 first-generation patches
found 271 transient signed derivatives that passed local ZIP, `aapt`, and
signature gates (270 distinct signed hashes). They were not live captured,
paired, or installed. The separate 10-second sampler rehearsal captured
20/20 exact APKs and produced four signed baseline/mutant pairs passing its
offline gate; it is outside the two-hour denominator. Full report, exact
commands, counts, caveats, and hashes:
[two-hour local review](../../results/fdroid-local-2h-2026-11-12-onebit-10420/REVIEW.md).
`bash scripts/run-tests.sh` passed after adding the live-sampler tests.

The next engineering gate is a bounded live-capture design that guarantees a
small first-generation cohort while preserving a separately labeled random
descendant sample. Apply strict repair, signing, and matched-baseline checks
to preserved exact bytes, then obtain an authorized bounded local Android
install/launch result before any 72-hour VM arm intended to test application
behavior. The current AFL harness does not provide F-Droid application
feedback. The prior VM `fallback_to_origin` cause still needs raw VM evidence.

## Latest local pilot and next action

The user authorized a 600-second local AFL++ check before any VM transfer. The
locked `manifest-onebit` F-Droid arm completed with 23,133 Python-harness
executions, two new queue entries, 2/2 exact captures and patch matches, no
saved harness crash/hang, and no source/input drift. Both exact APKs failed
ZIP/signature preflight; neither was eligible for an install attempt. The
mutator log had 23,059 one-edit entries and no fallbacks. One CRC-repaired
copy passed ZIP CRC but had malformed Android XML; signing stopped. The other
exact mutant had a decompression error. No emulator, device, model, network,
installation, or VM operation was performed. Full details and hashes are in
the [local pilot report](../../results/fdroid-pilot-2026-11-12-local-manifest-onebit-10415/REVIEW.md).

An SDK `aapt` warning for malformed XML came with exit code 0. Preflight,
preparation, and the Android metadata gate now reject this warning; focused
tests and `bash scripts/run-tests.sh` pass. The original pilot reports remain
untouched; a corrected offline preflight reached the same 0/2 eligibility.
After the pilot, a fixed-seed offline screen reconstructed all 48 saved
generation-one mutations and 200 of 23,011 generation-two mutations. All 248
raw APKs failed exact-APK ZIP/signature preflight. CRC repair and test signing
passed local ZIP, `aapt`, `apksigner`, and manifest-preservation checks for
12/48 and 6/200 respectively. These 18 signed artifacts were transient; no
live exact capture, matched baseline, install, or launch was established for
them. The 200 descendants share just two parents. This screen does not
estimate AFL queue or Android admission yield; see the pilot report for
selection, counts, command, and hashes.
Do not infer F-Droid behavior from AFL harness counts. Before a VM long arm
aimed at runtime candidates, review the raw prior VM arm and establish a
locally validated path from preserved live mutation bytes to a parseable,
signed derived candidate with exact mutant lineage, a matched signed baseline,
and a bounded device check. The 72-hour runtime-candidate gate is not met.

## Earlier pre-pilot review and VM limits

The user reports completion of the first, locked `random-range` 72-hour arm on
the separate university VM at
`/mnt/hdd/ApkVulFuzz/results/fdroid-72h-2026-11-09a-random-range/`:
7,190,955 AFL executions; 35 final corpus entries, 34 new; zero saved AFL
crashes/hangs; and 12 selected exact captures, all ZIP-blocked. These are
user-supplied observations; raw VM artifacts were not available locally.
The second `manifest-bitflip` 72-hour arm has not been reported as run.

On the local checkout, the 2026-11-12 review fixed reporting denominators,
fallback source reasons, future run hashes and configuration capture, and
Python AFL dependency checks. A separate locked `manifest-onebit` pilot
variant was built and passed the full suite. Eight offline, fixed-seed exact
mutants matched their patches, but none passed full ZIP or signature checks;
the SDK `aapt` parsed two of eight manifests. No AFL, emulator, device, network, or VM command
was run in this review. See
[the full review and pre-work diff](../../results/local-readiness-review-2026-11-12/REVIEW_REPORT.md).

The bounded pilot proposed in this earlier review has since completed, as
documented above. Its result does not clear the 72-hour runtime-candidate
gate. Do not start another 72-hour arm from this handoff alone.

## Historical 2026-11-04 checkpoint

## Bounded 20-minute F-Droid test, 2026-11-04

The user authorized a 20-minute local test. Two locked AFL++ arms ran
sequentially for 600 seconds each: `random-range` made 22,880 executions and
captured 12 exact candidates; `manifest-bitflip` made 22,219 and captured two.
Both returned 0 with no saved AFL crash/hang or watchdog error. All captures
matched patch lineage and stored APK hashes, but all 14 failed ZIP/signature
runtime preflight. The agent stage recorded zero ready pairs and made no API
calls on these invalid candidates. Raw evidence and exact commands are in
[the 20-minute report](../evidence/fdroid-20min-2026-11-04/README.md).
This does not start or change either planned 72-hour arm. The previously
verified separate one-bit prepared F-Droid agent control remains the only
F-Droid mutant pair in this checkpoint with completed guided and paired runs.

## F-Droid agent integration checkpoint, 2026-11-04

The ELM key and model passed a live probe. On a fresh offline Android 29
emulator, both original and test-signed F-Droid guided traces completed eight
actions with two model requests each; both passed original/original replay.
A separate 30-second one-bit manifest AFL feasibility run yielded one exact
candidate that could be prepared as a distinct signed artifact. Its fresh
control and two prepared-pair replays reported no divergence; guided runs of
both prepared roles completed with two model requests each. No defect claim.
Raw artifacts, hashes, and exact post-long-arm commands are in
[agent readiness evidence](../evidence/fdroid-agent-readiness-2026-11-04/README.md).
The emulator was shut down after testing. The main two 72-hour arms have not
started and still use locked default mutator settings. They now select at
most 12 exact queue candidates per arm with seeded sampling after AFL stops.
The new agent stage checks pair identity and a matching trace; if none is
runtime-eligible, it reports that gate explicitly without calling the model
on invalid APKs. Next action: launch the long sequence when desired, then
inspect each arm's preflight/admission report and run the agent stage on any
verified pairs. The one-bit control is a separate denominator.

## 72-hour readiness, 2026-11-04

The two-arm sequential launch is prepared but has **not** started. Use
`scripts/run-fdroid-72h-sequence.sh --check RUN_ID` immediately before launch;
`--start RUN_ID` runs locked `random-range` for 259,200 seconds, then locked
`manifest-bitflip` for another 259,200 seconds only if the first succeeds.
The current wrapper and new inode watchdog passed separate 30-second runs,
the full suite passed, corpus validation passed, and both 72-hour preflights
passed without starting AFL. Exact launch, checks, hashes, capacity estimate,
stop conditions, and results are in the
[readiness runbook](../evidence/fdroid-72h-readiness-2026-11-04/README.md).
The project tree remains substantially uncommitted; preserve it and the
ignored raw results. Recheck power and resources at launch. Do not claim
long-run completion or Android defect discovery from these bounded runs.

## Latest checkpoint, 2026-11-04

Added `scripts/run-fdroid-locked-arm.sh` for an isolated single-APK,
single-locked-mutator AFL run. Sequential ten-second F-Droid arms completed:
`random-range` seed 10407 made 433 executions and captured three exact
candidates; `manifest-bitflip` seed 10408 made 423 executions and captured
one. Both had zero AFL crashes/hangs. All four capture hashes and patch
lineages matched, but ZIP/signature preflight blocked runtime analysis.
The repository regression suite, including the APK-tool classification tests,
and corpus validation passed. Commands,
hashes, and raw artifact locations are in
[the acceptance evidence](../evidence/fdroid-locked-arms-2026-11-04/README.md).
The 72-hour arms have not started. Next: review these bounded results, then
run the two planned long arms in sequence. The LLMDroid runner now detects the
observed upstream event-generation exception in its runtime log, records
`inconclusive` regardless of action count, and preserves a separate budget
status. Focused and full tests pass; a fresh device run remains pending.
Stabilize clean-state replay next.

## New-chat handoff, 2026-11-04

The user is moving to a new Daybreak-enabled Codex chat after this session
displayed an account-security message requiring sign-in with an approved
hardware security key. A complete current handoff is in
`NEW_CHAT_HANDOFF_2026-11-04.md`; the user's original 2,397-line brief is
preserved verbatim in `ORIGINAL_PROJECT_BRIEF_2397_LINES.md` beside it.
The user selected local F-Droid for two separate planned 72-hour AFL++ arms:
locked `random-range` first, then locked `manifest-bitflip`. Bounded
single-APK acceptance for both is recorded above; neither 72-hour arm has
started. The `scripts/test-apk-tools.py` false signal classification was fixed
and its two focused tests and full suite passed. Preserve the current
modified/untracked checkout and existing results.

## Last completed outcome

- The guided smoke runner now reports `partial` and returns nonzero when it
  records fewer actions than the configured limit. Focused tests and the
  repository regression suite passed on 2026-11-04. The 2026-11-03 raw report
  remains unchanged and should still be interpreted as partial.
- A 10-second AFL++ rehearsal with seed `10406` completed 420 executions,
  preserved one exact candidate with matching patch lineage, and had no saved
  AFL crash or hang. ZIP and signature preflight blocked that candidate from
  Android runtime analysis. A fresh Android 29/ELM control run made one model
  call and wrote three actions, but did not complete its 12-action budget;
  upstream logged a teardown/state-collection error despite the smoke report's
  `completed` status. Detailed commands and hashes are in
  [meeting rehearsal evidence](../evidence/meeting-rehearsal-2026-11-03/README.md).
- The local ELM credential and pinned LLMDroid model were verified in a live
  probe. Guided exploration, trace export, paired replay, and a deliberate
  crash control have recorded evidence.
- Replay now avoids an extra launch before kill/start traces, waits for a
  completed APK install, and retries transient Android log resets.

## Unfinished work

- Verify the new upstream event-generation error classification on a fresh
  device run and investigate other state-collection failures.
- Reproduce the same UI flow from a clean emulator state. The corpus trace's
  onboarding `SKIP` action is absent in existing sequential replay.
- Complete Stage 9 real-mutant validation and Stage 10 repeated evaluation.
  The exact-mutant installability result is 0/34 in the bounded sample.

## Important current facts

- Repository root: `/home/sahar/Projects/ApkVulFuzz`.
- The existing project checkout contains substantial uncommitted and untracked
  integration work; inspect `git status` before editing or cleaning.
- The fresh Android 29 emulator for the 2026-11-03 meeting rehearsal was
  shut down after evidence collection. Do not treat its state-collection error
  as an app defect.
- Current status and raw evidence locations:
  [LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md) and its linked pages.
- The ELM key is stored locally in an ignored owner-only file. Never print it.

## First action next session

Check the current stage ledger and Git status, then design a fresh-device
original/original replay control that preserves the recorded first-run state.
Run a bounded control before changing action-matching rules; surface upstream
state-collection errors independently of action count.

## Do not repeat without a reason

The 34-mutant feasibility sample and the earlier guided known-defect controls
are already recorded under `docs/evidence/`. Reuse their evidence when planning
the next experiment.
