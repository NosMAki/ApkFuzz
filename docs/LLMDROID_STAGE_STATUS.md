# LLMDroid differential extension: stage checklist

This ledger follows the approved Stage 0–10 list in the project context.
"Implemented" means code exists; "verified" requires a recorded test. The
extension is not complete until the required device experiments and evaluation
are verified.

## Current checkpoint, 2026-11-15

The [outcome oracle](ORACLE.md) now separates package fatal exceptions,
suspected manifest/permission/class-resolution rejection, launch ANRs, and
transport timeouts for **future** probes (launch gate v3). Earlier reports
remain historical v2 observations and are not retrospectively recounted.
AFL coverage and saved crashes measure the Python ZIP/path-file harness;
AFL is an input generator for this study, not evidence of F-Droid code
coverage or vulnerability discovery. The exhaustive `enumeration.tsv` covers
the fixed origin's **first-generation compressed-manifest one-bit space**,
not later generations or other APKs.
An [isolated gate-v3 control check](../results/oracle-controls-2026-11-15/REVIEW.md)
then passed baseline/inert/known-crasher/baseline on the local Android 10
emulator. The crasher's 15 fatal log blocks had one fingerprint and were
flagged as suspected manifest rejection; this was one install, not 15
independent defects. A [three-seed 120-second AFL check](../results/paper-afl-seeds-2026-11-15/REVIEW.md)
preserved one exact ZIP/manifest-valid queue mutant per seed, but all three
failed the original signature check. Neither check cleared a 12-hour run
for app-behavior discovery; no new paired UI experiment was performed.
The [paper evidence package](../results/paper-artifact-2026-11-15/README.md)
pins the tables, protocols, reviews, tool versions, and emulator fingerprint.

A [generation-one device check](../results/gen1-device-admission-2026-11-15/REVIEW.md)
showed that the 2026-11-12 generation-two result below was dominated by one
defect: the diagnostic's single queue parent fails Android installation by
itself, and all 55 sampled generation-two outputs descend from it. The offline
gate also overstated generation one: of 38 offline-ready mutants, 22 launched
healthily, 13 failed to install, and 3 crashed at start.

A [gate and variant check](../results/axml-admission-gate-2026-11-15/REVIEW.md)
then added an opt-in `manifest-axml-onebit` variant that keeps the decoded
manifest structurally sound, offline rejection of `aapt` resource warnings, a
device launch gate that requires a running process, an empty crash record, and
the baseline's activity, and that gate as a precondition for LLMDroid
admission. In a 120-second run (seed 10435) 94 of 95 live generation-two
outputs were offline-ready; 28 of the 40 probed passed the device gate. An
original/original control and one generation-two pair each replayed eight
actions with no divergence observed. The full suite passes with 20 variants;
the 19 earlier mutator binaries are unchanged.

Limits: every sample descends from one queue parent and is generation two; the
comparison with seed 10434 differs in both mode and queued parent; AFL's
harness produced no new coverage for these valid mutants, so its queue did not
grow. The 12-hour decision is therefore **open, not cleared**: the Android
admission blocker is addressed, but what a long run would add is not
established. No model call, VM run, or long run was made.

An [exhaustive first-generation enumeration](../results/gen1-enumeration-2026-11-15/REVIEW.md)
then classified all 71,368 one-bit flips of the compressed manifest offline:
16,024 are accepted by `manifest-axml-onebit`, confirmed against saved
C-mutator patches. A uniform sample of 120 accepted flips, reconstructed
offline rather than AFL-captured, gave 93 healthy launches under the device
gate (77.5%, Wilson 95% 69.2–84.1%), with 37 of 37 repeated probes agreeing.
Generating Android-usable first-generation mutants no longer depends on AFL's
queue; choosing which to test behaviorally is the open work. No paired replay
was run on the enumerated sample.

A [semantic classification](../results/gen1-flip-semantics-2026-11-15/REVIEW.md)
of those 16,024 flips (offline) found 4,528 that change no tag, attribute
identity, or typed value, 3,247 that change exactly one thing, and 8,249 that
change several. The operator mostly renames strings (class names, actions,
permission names) and never cleanly toggles `android:exported`. A stated
prediction missed by one case and showed that 1,123 flips alter only an
attribute's raw value, which different readers resolve differently; Androguard
disagreed with the typed value in all 10 sampled cases. Behavioral testing of
these classes has not been run. The 1,123 are a candidate raw/typed-value
disagreement population; three-reader agreement among `aapt`, Androguard,
and Android has not been measured for the full class.

## Earlier checkpoint, 2026-11-12

Latest [12-hour readiness checks](../results/manifest-valid-onebit-readiness-2026-11-12/REVIEW.md):
the real first-generation queue mutant and its signed baseline completed an
eight-action paired UI replay; an original/original control also completed all
eight actions, with no divergence observed. A ten-minute locked new-mode run
was process-stable (22,165 harness executions, no fallback, two new queue
entries), but both queue entries failed manifest preflight. Its seven selected
live descendants all failed `aapt`. A separate 120-second, denser descendant
capture preserved 90 live outputs; 30 generation-two outputs passed offline
signed-pair checks. On a fresh offline Android 29 emulator, only 2/30 installed
and 0/30 had a F-Droid process running after the launcher check. Androguard
accepted 0/30 with the expected package. The 12-hour Android-candidate run is
**not ready**; no 12-hour or VM run was started. The offline gate must not be
read as device or LLMDroid eligibility.

Latest local fix checkpoint: a new opt-in `manifest-valid-onebit` locked mutator
produced one real AFL queue mutant during a 30-second run. Its exact bytes and
patch lineage verified; its full ZIP and manifest were valid before signing.
The raw signature was invalid after mutation, so a separate test-signed mutant
and matched test-signed baseline were prepared. Both installed, launched, and
showed a running F-Droid process on a fresh offline Android 29 emulator, with
cleanup complete. The deliberately selected live sample contained 25 exact
outputs (24 first-generation prefix, one descendant), all ZIP-valid; 20
passed offline signed-pair checks. The full regression suite passes. See the
[local acceptance report](../results/manifest-valid-onebit-local-30s-2026-11-12-10432/REVIEW.md).
This clears the local install/launch feasibility gate for one real queue
mutant. AFL feedback is still from the Python harness, and no UI differential
or application vulnerability was measured. The original two VM long-arm
definitions and historical evidence are unchanged.

The authorized [two-hour local one-bit run](../results/fdroid-local-2h-2026-11-12-onebit-10420/REVIEW.md)
completed 275,810 harness executions and three new, provenance-verified exact
queue APKs. All three failed ZIP/signature preflight. A separate deterministic
sample preserved 144 exact live descendants, all of which failed raw ZIP and
CRC-repair screening; the sample contained no first-generation outputs. An
offline reconstruction of all 848 generation-one patches yielded 271
transient signed derivatives passing local ZIP, `aapt`, and signature checks,
but these were neither live captured nor device tested. No Android or VM run
followed. At that two-hour checkpoint, the local runtime-candidate gate was
unmet and the full regression suite passed. The newer local fix is above.

The user reports that the VM `random-range` 72-hour arm completed with
7,190,955 AFL executions, 35 final corpus entries (34 new), zero saved AFL
crashes/hangs, and 12 selected exact captures that all failed ZIP preflight.
The VM's raw run artifacts are not available locally, so these are
**user-supplied observations**, not an independent review of that run. The
`manifest-bitflip` 72-hour arm has not been reported as run. The dated
2026-11-04 readiness records below describe the state before this VM arm.

Local fixes now separate queue, capture, offline preflight, device, pair, and
manual-confirmation denominators; log distinct source fallback reasons; record
run-critical hashes at both ends of a future arm; and add an optional locked
`manifest-onebit` pilot variant. The variant is separate from the two original
72-hour arm definitions. An eight-mutant offline sample from it had 8/8 patch
lineage matches and 0/8 full ZIP-valid or signature-valid exact APKs. The SDK
`aapt` parsed 2/8 manifests, but this does not override ZIP/signature failure.
No Android install or launch was attempted. See the
[local readiness review](../results/local-readiness-review-2026-11-12/REVIEW_REPORT.md).

A subsequent [600-second local one-bit pilot](../results/fdroid-pilot-2026-11-12-local-manifest-onebit-10415/REVIEW.md)
completed 23,133 harness executions with two new queue entries. Both exact
APKs were captured with verified lineage, but neither passed ZIP/signature
preflight. One CRC-repaired derivative had malformed Android XML and signing
failed; no runtime-ready artifact was produced. The pilot exposed an `aapt`
exit-zero malformed-XML warning, now rejected by preflight, preparation, and
the Android metadata gate. Focused tests and the full local suite pass. This
pilot does not justify another 72-hour run for application-runtime candidates.
An offline follow-up reconstructed a fixed-seed sample of 248 saved mutation
patches (all 48 generation-one, 200 sampled generation-two). All raw APKs
failed ZIP/signature preflight; CRC repair and test signing passed local tool
gates for 12/48 and 6/200 respectively. Those successful derivatives were
transient and neither live captured nor device tested. The second-generation
population descends from only two parents. This does not measure live queue or
Android admission yield; see the pilot report for protocol and raw counts.

| Stage | Current state | Evidence or remaining acceptance work |
| --- | --- | --- |
| 0. Repository inspection | Verified earlier | Existing AFL++ path-file harness, V2 mutator, DroidBot workflow, tests, and integration points were mapped before edits. |
| 1. Mutation feasibility | Bounded corpus sample verified | Exact captured one-bit manifest mutant, reconstruction, CRC/signature failure, separate prepared pair, and paired install/process-start checks are documented in [artifact evidence](evidence/manifest-runtime-preparation-2026-10-21/README.md). A [34-mutant sample](evidence/mutation-feasibility-2026-10-28/README.md) across all 17 operators and two corpus APKs measured ZIP, manifest, signature, and install outcomes; 0/34 exact mutants installed while both originals did. The sample is one seed per operator/app, not a broad rate estimate. |
| 2. LLMDroid setup and smoke | ELM-guided control smoke verified | Official commit pinned; isolated Python environment, credential guard, and ELM runner verified. The API model-list/chat probe succeeded. A 12-action control-app run made one ELM request. The prepared app-lister produced five actions but no model request; it is not counted as a guided success. [Evidence](evidence/llmdroid-elm-2026-10-28/README.md). |
| 3. Action recording | Guided trace verified | `scripts/export-llmdroid-trace.py` exported the 12-action ELM-guided control trace with source hashes. Earlier non-LLM launch and two-action fixtures remain available. |
| 4. Deterministic replay | Guided 12-action control replay verified; onboarding replay unresolved | `scripts/replay-llmdroid-trace.py` completed the ELM-guided trace twice on the identical control APK. A recorded `kill_app` is safely normalized to a package-scoped force-stop intent because upstream cannot deserialize it. Replay now avoids an extra launch before kill/start traces and waits for completed installation. The flashlight trace still stops at an absent onboarding `SKIP` target; [follow-up evidence](evidence/llmdroid-flashlight-pilot-2026-10-28/README.md). |
| 5. Dual environment | Sequential paired execution verified on a control pair | `scripts/run-llmdroid-pair.py` runs both APKs on the same temporary Android 29 emulator with fresh installation and independent reports. It completed a 12-action guided-trace original/original control and repeated baseline/known-defect pairs. The original/prepared-mutant launch action was also run sequentially. |
| 6. Differential analysis | Guided-trace known crash detected | Comparator reported no divergence for the 12-action identical APK control and marked the deliberate Save-action crash at action 2 in two guided-trace pairs, with AndroidRuntime evidence. The prepared manifest mutant had no divergence on a one-action launch trace. More defect classes remain unverified. |
| 7. Controlled validation | Guided negative control and repeated positive control verified; unstable-app control exposed | Both earlier 12-action identical-control roles completed with no divergence. Two earlier baseline/known-defect pairs found the crash at action 2 with the same fingerprint. A flashlight-corpus identical-APK replay stopped at a missing `SKIP` target; a later software-emulator retry and control regression were inconclusive because of Android log and watchdog failures. [Pilot evidence](evidence/llmdroid-flashlight-pilot-2026-10-28/README.md). Broader false-positive measurement remains pending. |
| 8. LLM-assisted follower | Optional, concrete need observed; unimplemented | The flashlight trace's recorded `SKIP` button disappeared before replay could match it. A semantic follower or a stabilized trace needs explicit action-equivalence rules and original/original controls before use. |
| 9. AFL++ integration | First- and second-generation pair replay verified from one parent each; device gate required for admission (2026-11-15, see checkpoint above); broader lineage and yield unmeasured. Earlier state follows. | Candidate capture enqueues preserved exact artifacts only after AFL stops. The `manifest-valid-onebit` first-generation queue pair completed eight-action original/original and baseline/mutant replays without observed divergence. The ten-minute new-mode run was stable but its two queue entries failed manifest preflight. In a separate denser live-descendant sample, 30 generation-two signed pairs passed offline checks; Android installed 2 and showed no persistent F-Droid process after launcher checks. Androguard accepted none of 30. Exact and prepared hashes remain separate. The user reports completion of the `random-range` 72-hour VM arm, with all 12 selected exact captures ZIP-blocked. Raw VM artifacts and automated reproduction of an AFL-mutant defect remain unverified. |
| 10. Scientific evaluation | One matched-action pilot done; comparative study pending | [Evaluation protocol](LLMDROID_EVALUATION_PROTOCOL.md) fixes arms, budgets, denominators, and cautious conclusions. The ELM key works. A 12-action flashlight pilot recorded 7 state files and one app activity in each arm; LLMDroid made 6 model calls. Its identical-APK replay failed synchronization, so it supplies no differential result. Five-run multi-app comparison, code coverage, resource dispersion, and cross-arm conclusions remain pending. |

## Current dependencies

- ELM Hosted model access and a live guided control trace are verified. The
  locally saved key must remain owner-only and ignored by Git; it must not be
  pasted into the chat or stored in source control.
- The prepared app-lister produced no model call in its short run. A usable
  guided trace for a runtime-eligible AFL mutant remains a research gate.
- The prepared APKs and test results are under ignored `results/`. Those local
  files are needed to rerun the bounded device checks; the committed evidence
  records hashes and classifications without bundling the APK binaries.

## Latest bounded rehearsal

The [2026-11-04 20-minute F-Droid acceptance](evidence/fdroid-20min-2026-11-04/README.md)
ran the two selected locked modes for 600 seconds each. Both completed with
zero saved AFL crashes/hangs and 14 total exact captures with verified
lineage. All 14 failed runtime preflight; the agent stage therefore recorded
zero ready pairs and no model calls for these candidates. The distinct
one-bit prepared-agent control remains valid, but it is not part of these
20-minute arms or the planned 72-hour denominator.

The [F-Droid agent readiness check](evidence/fdroid-agent-readiness-2026-11-04/README.md)
verified a model-guided trace and identical-APK replay for both the original
and a separately test-signed baseline. One preserved exact one-bit manifest
mutant from a separate bounded AFL run was prepared as a distinct signed
artifact; two paired replays showed no divergence and both guided roles made
model requests. This verified the F-Droid control path as of 2026-11-04,
before the user reported completion of the VM `random-range` arm. It does not
establish runtime eligibility of candidates from either 72-hour arm.

The [2026-11-03 meeting rehearsal](evidence/meeting-rehearsal-2026-11-03/README.md)
used AFL++ seed `10406`: one exact candidate was preserved with matching patch
lineage, but ZIP and signature preflight blocked Android runtime analysis. A
fresh ELM-guided control run made one model call and recorded three of twelve
requested actions. Upstream then hit a state-collection error during teardown;
its historical `completed` smoke status must be interpreted as a partial run.
The runner was corrected on 2026-11-04 to label below-limit guided runs
`partial` and exit nonzero. It also now reports `inconclusive` when its runtime
log contains the observed upstream event-generation exception, regardless of
action count, and records the budget outcome separately. The prior raw report
is unchanged and a fresh device verification remains pending. This does not
change the Stage 7–10 acceptance status above.

The [2026-11-04 locked-arm acceptance](evidence/fdroid-locked-arms-2026-11-04/README.md)
ran separate ten-second F-Droid `random-range` and `manifest-bitflip` arms
through the existing AFL path-file harness. Both completed with no saved AFL
crash or hang; all four preserved exact candidates matched their patch
lineage but failed Android runtime preflight. The planned 72-hour arms had not
started as of this 2026-11-04 rehearsal. This does not change Stage 9 or 10
acceptance.

## Preservation rules

The AFL++ mutation loop and the existing modified DroidBot checkout must keep
working when LLMDroid is absent. Exact mutants and every prepared variant must
retain distinct hashes. Infrastructure failures, setup timeouts, and unverified
replays must never be counted as application defects. A divergence is a defect
candidate until reproduced and validated; it is not automatically a security
vulnerability.
