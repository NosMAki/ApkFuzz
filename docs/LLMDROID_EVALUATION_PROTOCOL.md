# LLMDroid differential extension: evaluation protocol

This protocol defines the Stage 10 comparison before seeing guided results.
Current one- and two-action controls are engineering checks, not a scientific
comparison between exploration methods.
Use the [outcome oracle](ORACLE.md) for crash fingerprints, three clean
reproductions, manifest-rejection exclusions, and the separate ANR and
infrastructure-timeout denominators. `launch_gate_version: 3` applies only to
new probes; historical device reports retain their original classifications.

The [bounded feasibility sample](evidence/mutation-feasibility-2026-10-28/README.md)
found zero installs among 34 exact mutants from two corpus APKs. Any runtime
arm using repaired or re-signed variants must report that transformed-artifact
denominator separately from exact-mutant eligibility.

## Study inputs and conditions

Use the same recorded APK source, prepared mutation pair, Android API level,
emulator image, screen size, locale, permission policy, time budget, and maximum
action count for each arm. Start each run from a clean app install and record
the APK SHA-256, emulator build fingerprint, LLMDroid commit, model ID, prompt
configuration, AFL++ seed, and trace SHA-256. Run arms in a balanced order to
reduce drift from software emulation. Use at least five independent runs per
app and arm initially; increase the count if the observed outcome varies.

Compare: (A) the existing DroidBot exploration, (B) LLMDroid-guided
exploration, and (C) LLMDroid-guided exploration followed by deterministic
paired replay. Add (D) the optional semantic follower only if a documented
matching failure justifies it. Do not treat A, B, and C as equivalent
coverage measurements unless each uses the same app instrumentation and
coverage collection. The current `time` mode supplies no code-coverage data.

## Measurements

| Metric | Definition and source |
| --- | --- |
| Mutation retention | Exact captured mutant APKs divided by selected AFL++ queue mutants; capture manifest. |
| Runtime eligibility | ZIP, manifest, signature, install, and launch rates reported separately; preflight and bounded device probe. |
| UI exploration | Distinct content-free UI states and foreground activities per equal budget; LLMDroid/DroidBot state files. |
| Replay synchronization | Actions with uniquely matched targets divided by attempted recorded actions; replay reports. |
| Divergence stability | Candidates reproduced at the same first action and class across runs, with log/screenshot evidence; pair and queue reports. |
| False positives | Divergences in original/original controls divided by completed original/original comparisons. Do not mix infrastructure failures into this denominator. |
| Crash diversity | Distinct verified exception signatures after manual inspection; AndroidRuntime logs. |
| Runtime and resources | Wall-clock time, peak RSS, CPU time, disk bytes, and emulator configuration; runner and host measurements. |
| LLM use | Requests, prompt/completion tokens, latency from `LLM-Usage.jsonl`; report null usage as unavailable. Price tokens using the provider's published price on the run date. |
| Confirmed defects | Manual reproduction on the same pair and a causal explanation. Security impact requires separate validation. |

Report per-run values, medians, dispersion, and denominators. Keep timeout,
setup, synchronization, and app-outcome failures separate. A missing API key,
failed provider call, or stalled accessibility helper is an infrastructure
outcome and does not count as an app defect. The manifest mutant's single
launch action showed no divergence; that observation cannot establish absence
of defects or a coverage improvement.

## Current evidence and gates

The [replay controls](evidence/llmdroid-replay-2026-10-21/README.md) verify
one original/original launch comparison, one healthy/healthy launch-and-Save
comparison, and a deliberate crash at the Save action in two paired runs. The
[ELM guided control](evidence/llmdroid-elm-2026-10-28/README.md) adds a real
12-action model-assisted trace, a complete identical-app replay, and two
same-signature known-defect reproductions. This is an integration result, not
a cross-arm study. The [flashlight corpus pilot](evidence/llmdroid-flashlight-pilot-2026-10-28/README.md)
matched a 12-action budget in the two exploration arms but gave no state-count
advantage in one run. Its same-APK replay exposed a transient-screen false
positive and stopped on a missing recorded target; it is excluded from defect
counts. Multi-run APK-mutant evaluation, comparable coverage, cost, and broader
resource measurements remain pending.
