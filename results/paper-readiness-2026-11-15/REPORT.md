# APKVulFuzz: oracle, AFL semantics, and paper-readiness review

**Date:** 2026-11-15. **Repository:** `/home/sahar/Projects/ApkVulFuzz` at
Git HEAD `96f82a05f0376d4f79b897b72f6a6d17d907143d` plus pre-existing
and current uncommitted work. This report concerns the authorized local
F-Droid APK and dedicated Android 10 emulator. It does not reinterpret the
user-supplied university-VM 72-hour run.

## Decision

The oracle and AFL crash semantics are substantially clearer and pass both
synthetic and bounded real controls. A three-seed short AFL check generated
structurally valid exact inputs, but none retained the original APK signature;
no application behavior was tested in that AFL batch. The finite
first-generation binary-XML mutation result is well supported. The proposed
claim that **all 1,123 raw-value-only flips are proven disagreements among
`aapt`, Androguard, and Android is not supported** by the current evidence.
The direct three-reader study, a full manuscript revision, and a behavioral
batch remain open. A 12-hour run intended to find F-Droid application defects
is therefore **not cleared** by this work.

## Changes and verification by priority

| Requested item | State | Evidence and limit |
| --- | --- | --- |
| 1. Manifest-rejection separate from app logic | **Implemented and controlled** | `scripts/probe-android-runtime.py` records package-owned fatal events, exception/stack, fingerprint, and separate `SecurityException`, `ClassNotFoundException`, `Unable to instantiate`, and required-permission flags. The [gate-v3 control](../oracle-controls-2026-11-15/REVIEW.md) flagged the known crasher as suspected manifest rejection with no app-logic candidate. Flags are triage aids, not proof of root cause. |
| 2. ANR separate from infrastructure timeout | **Implemented, synthetic verification** | On launch timeout, the probe queries main/system logcat for a package-matched `ANR in` and `Reason: Input dispatching timed out`. It distinguishes `launched_anr`, `launch_timeout_infrastructure`, `launch_timeout_unverified`, and `runtime_evidence_unavailable`. Tests cover package and other-package ANRs and failed log queries. No real ANR was induced. |
| 3. One documented crash oracle | **Done** | [ORACLE.md](../../docs/ORACLE.md) specifies stack-bearing package fatal, fingerprint deduplication, three clean-install reproductions, triage, and manifest-rejection exclusion. A crash loop's 15 log records in one install count as one fingerprint/trial, not 15 independent reproductions. |
| 4. Explicit AFL-level crash semantics | **Done locally** | `scripts/run-corpus-smoke.sh` sets `PYTHON_AFL_SIGNAL=SIGUSR1`; the locked arm records it in `config.txt`. A controlled unhandled Python exception made AFL++ `afl-showmap` exit 2 with signal 10 and six tuples ([raw check](../oracle-controls-2026-11-15/REVIEW.md)). Saved AFL crashes concern the Python harness only. The old VM environment was not verified. |
| 5. Harness boundary | **Done** | `afl/apk_pathfile_harness.py` and the [paper framing](../../docs/PAPER_FRAMING.md) state that the harness exercises Python `zipfile`/path-file handling and does not run F-Droid or measure its coverage. |
| 6–8. Claim and AFL framing | **Drafted; manuscript pending** | [PAPER_FRAMING.md](../../docs/PAPER_FRAMING.md) removes unsupported F-Droid-crash language, leads with structure-preserving binary-XML mutation and measured raw/typed-value observations, and treats AFL as optional input generation. No actual paper manuscript was identified in this repository; the existing `.docx` files are proposal drafts, which were left untouched. |
| 9. Three seeds and repeats | **Done for a short AFL check; historical repeat reported** | [Three-seed review](../paper-afl-seeds-2026-11-15/REVIEW.md): seeds 10441, 10442, 10443, each 120 seconds, with identical input/source snapshots. The earlier [enumeration review](../gen1-enumeration-2026-11-15/REVIEW.md) reports 37/37 repeat classification agreement after applying the same crash rule. Neither is three independent app-crash reproductions. |
| 10. Named controls | **Done for the gate-v3 rehearsal** | Signed baseline, inert enumerated flip 9157, known start-up crasher 10433/iter15, then baseline all matched expected classes and cleaned up. Exact and prepared hashes are in the [control protocol](../oracle-controls-2026-11-15/PROTOCOL.md). The crasher is an invalid-input control, not a discovered defect. |
| 11. Evidence package | **Done as a curated package** | [Package README](../paper-artifact-2026-11-15/README.md) and `paper-evidence.tar.gz` contain 81 SHA-256-verified files: both full tables, the four original protocol/review pairs, added check reports, selected run records, pinned versions, fingerprint, oracle, and paper framing. Independent device replay still needs the pinned APK, emulator image, signing setup, and full raw APK artifacts. |

## Short experimental results

The prior exhaustive offline enumeration classified **71,368** first-generation
compressed-manifest one-bit positions; **16,024** met the structural mutator's
acceptance rule. A uniform 120-member sample gave **93** healthy gate-v2
launches on one Android 10 emulator; **37/37** repeat classifications agreed
after a common crash-rule derivation. Static refinement found **3,339** inert
and **1,123** raw-value-only flips. Ten sampled raw-only cases differed between
Androguard and the typed-value model; one `<category>` flip changed Android
launcher resolution. Android's resolved value for the other raw-only
attributes was not directly measured. See the [enumeration](../gen1-enumeration-2026-11-15/REVIEW.md)
and [semantic](../gen1-flip-semantics-2026-11-15/REVIEW.md) reviews for methods
and denominators.

The new 120-second AFL arms recorded **4,514**, **4,482**, and **4,401**
Python-harness executions. Each had one new queue entry and one
provenance-verified exact capture, with valid ZIP and parseable manifest but
invalid original signature; each had zero saved **harness** crashes or hangs.
The first 10441 attempt had source drift and was preserved but excluded, then
rerun. No signed derivative was made from these three exact captures in this
batch. These results do not estimate Android eligibility or vulnerability
yield. The [three-seed review](../paper-afl-seeds-2026-11-15/REVIEW.md) links
all per-seed raw files.

## Verification and next decision

`bash scripts/run-tests.sh` passed after the final oracle change;
`git diff --check` found no whitespace errors. The bounded real gate-v3
control check passed and the emulator was shut down. The evidence archive
was extracted to a fresh directory and all **81** included files passed
`sha256sum -c`. Archive SHA-256:
`395ad499ae2b7b9b0145057f5fabfcf9ec0af8807529d795ec2e2f759bfdc2b8`.

Next, predeclare and run a direct `aapt`/Androguard/Android package-manager
comparison on a sample of the 1,123 raw-value-only flips. Record exact
attribute values or parser failures for each reader, with the named gate-v3
controls. Then revise the actual manuscript to match those measured results.
Only after a controlled paired UI batch shows useful behavioral variation
should a longer AFL input-generation arm be considered. None of the current
zero harness-crash counts supports an absence-of-vulnerabilities claim.
