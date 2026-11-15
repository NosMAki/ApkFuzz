# ELM-guided LLMDroid control run, 2026-10-28

This is a bounded integration check on local APKVulFuzz test applications.
The ELM API key is not stored here. The ignored device outputs remain under
`results/`; this document records their identities and observed outcomes.

## Provider and exploration

- Provider: University of Edinburgh ELM, `https://elm.edina.ac.uk/api/v1/`.
- Model: `mistralai/Mistral-Small-4-119B-2603`. The separate model-list and
  chat probe succeeded with the locally saved key.
- LLMDroid commit: `5b5485cf195583370d49e353601985850210277e`.
- Android: isolated API 29 software emulator, `emulator-5562`.
- `results/llmdroid-offline-elm-api29-2026-10-28/smoke-report.json` completed
  the device-only check. It made no model request and recorded no actions.
- `results/llmdroid-guided-elm-api29-2026-10-28/smoke-report.json` completed
  five startup/navigation actions on the prepared app-lister, but made no model
  request. It is not evidence of LLM-guided exploration of that app.
- `results/llmdroid-guided-control-elm-2026-10-28/smoke-report.json` completed
  a 12-action exploration of the local control app in 62.287 seconds. LLMDroid
  made one successful ELM chat request, and its usage record reported 935 total
  tokens. The exported trace has SHA-256
  `f33813750fb4af64ff531d2ee5a21a458c90e2d5997a04fabd96e6056d8d172c`.

The control APKs share a package and certificate. Baseline SHA-256:
`ae5fbc5ef61cf9e2300a52cbd6502a56d3f14bbbda4854ca8c96a8e7cc860181`.
Deliberate-crash variant SHA-256:
`7cec1ca06cf9f8f676595188b4effbe853cd5c84c0ed4806a5f1e355794a6f5f`.
The variant was built as a known-defect test fixture, not produced by AFL++.

## Guided-trace replay controls

The first replay attempt was inconclusive at the trace's initial `kill_app`
action. Upstream records that action but does not deserialize it with
`InputEvent.from_dict`. The replay adapter now maps only a package-matching
`kill_app` to a package-scoped force-stop intent, and rejects foreign commands.

- Identical APK versus itself: both roles completed all 12 trace actions;
  the comparison reported `no_divergence_observed` in
  `results/llmdroid-guided-control-negative-pair-retry-2026-10-28/`.
- Baseline versus deliberate-crash variant: both comparisons reported
  `crash_candidate` at action 2. The baseline step was `ok`, and the variant
  crashed when Save was tapped. The two captured AndroidRuntime logs yield the
  same process/exception/first-app-frame fingerprint. Reports are under
  `results/llmdroid-guided-control-positive-pair-2026-10-28/` and
  `results/llmdroid-guided-control-positive-repeat-2026-10-28/`.

The result demonstrates the guided trace, deterministic follower, identical
app control, first-divergence detection, and repeated known-defect detection on
one small test app. The LLMDroid runner used `time` mode, which has no code
coverage measurement. This is not evidence of improved coverage or of a new
security vulnerability. Multi-app and AFL-mutant evaluation remain separate
study work.

The preserved AFL manifest candidate was also admitted through the independent
analysis queue with a five-action trace from the prepared app-lister. Two
paired runs completed and reported `no_divergence_observed`. That trace made
no model request and mainly exercised startup/navigation, so it does not
establish equivalent application behavior beyond those actions. The result is
under `results/llmdroid-stage1-2026-10-21/analysis-elm-trace-repeat2-2026-10-28/`.
