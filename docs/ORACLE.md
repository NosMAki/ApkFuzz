# APKVulFuzz outcome oracle

This definition applies to new Android probes (`launch_gate_version: 3`). Keep
the exact AFL mutant, any signed derivative, and its matched baseline under
separate SHA-256 identities. The device probe's classifications are screening
outcomes; they are not confirmed defects.

## Android outcomes

| Observation | Screening class | Defect count |
| --- | --- | --- |
| Package-owned `AndroidRuntime` `FATAL EXCEPTION` block | `launched_crashed` | Candidate only, after the exclusions and reproduction below. |
| Package-owned `ANR in` record during a launch timeout | `launched_anr` | Separate ANR candidate, never an AFL crash. Record `Reason: Input dispatching timed out` when present. |
| `adb` launch command itself timed out without package ANR evidence | `launch_timeout_infrastructure` | None; investigate device/transport. |
| Android launch returned `Status: timeout` without package ANR evidence | `launch_timeout_unverified` | None until reproduced with app evidence. |
| Crash or ANR log query failed | `runtime_evidence_unavailable` | None; restore logging before interpreting the launch. |
| Installation or launcher resolution failed | `install_failed` / `launch_failed` | Input admission failure, not an app defect. |

A **confirmed app crash** requires a package-owned fatal exception with an
exception class and stack frame, deduplicated by exception class plus first
relevant stack frame after removing line numbers. The probe stores a
provisional SHA-256 fingerprint for this pair. Reproduce the same fingerprint
at least **three times** on clean installs of the same hashed signed APK with
the matched baseline and a working original/original control. Inspect the
logs and stack to classify the cause as harness, emulator, mutated manifest,
or application logic. Confirmed security impact requires separate causal
validation; a crash alone is not a vulnerability.
The JSON report retains a bounded fatal/ANR log block and records truncation;
obtain the full device log separately if a block is truncated. A truncated
empty log check is `runtime_evidence_unavailable`, not a healthy launch.

The probe separately flags fatal blocks containing `SecurityException`,
`ClassNotFoundException`, `Unable to instantiate`, or `Permission … is
required` as **suspected manifest/permission/class-resolution rejection**.
Exclude these from app-logic defect counts unless manual triage proves the
exception arises from app logic. The flag is intentionally conservative:
`SecurityException` by itself does not prove that the manifest is invalid.
Fatal blocks without a usable stack remain incomplete evidence even if the
probe screens them as `launched_crashed`. Report the number of such incomplete
blocks, suspected rejections, other crash candidates, and confirmed app
crashes as separate denominators.
The probe records **raw fatal log events** and distinct fingerprints
separately. A crash loop with repeated copies of one fingerprint during one
installation is one trial, not multiple independent reproductions. The
three-run rule requires three clean installs.

An ANR candidate likewise requires package-matched log evidence and repeated
reproduction; an `adb` or emulator stall is infrastructure. Preserve the raw
log and artifact before deduplication or minimization. The current probe only
looks for an ANR when a launch command times out, so it is **not** a general
long-running UI hang monitor.

## AFL-level outcomes

The AFL target is `afl/apk_pathfile_harness.py`, a Python `zipfile`/path-file
check. New runs through `scripts/run-corpus-smoke.sh` set
`PYTHON_AFL_SIGNAL=SIGUSR1`, making unhandled Python exceptions signal
crashes for AFL. `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` suppresses the
host's piped-core-pattern warning; it does not turn Android failures into AFL
crashes. Saved AFL crashes and coverage-map occupancy describe the **harness**
only. This configuration was not retroactively present or verified in the
earlier university-VM 72-hour arm.

## Methodology text for the paper

> We distinguish AFL harness outcomes, APK admission failures, Android ANRs,
> and application-logic crash candidates. Android crashes require a
> package-owned fatal exception with a stack, are grouped by exception class
> and first relevant frame, and must recur at least three times on clean
> matched baseline/mutant runs. Manifest, permission, and class-resolution
> failures are reported as input rejections unless manual triage establishes
> an application-logic cause. A package-matched ANR log is required to call a
> launch timeout an app outcome; adb and emulator timeouts are infrastructure.

Implementation: [`probe-android-runtime.py`](../scripts/probe-android-runtime.py).
The evaluation protocol is [`LLMDROID_EVALUATION_PROTOCOL.md`](LLMDROID_EVALUATION_PROTOCOL.md).
