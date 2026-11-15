# LLMDroid replay controls, 21 October 2026

The temporary Android 29 emulator (`emulator-5562`, software emulation) ran
LLMDroid-Droidbot at commit `5b5485cf195583370d49e353601985850210277e`.
The local checkout and APK binaries remain outside source control. All actions
were recorded with upstream `EventLog` and exported by
`scripts/export-llmdroid-trace.py`. The replay used upstream `Device`, `App`,
and `InputEvent`, with the project's deterministic target matcher.

| Control | Actions | Result |
| --- | ---: | --- |
| Prepared original versus itself | 1 launch | [No divergence](original-control-finding.json) |
| Prepared original versus one-byte manifest mutant | 1 launch | [No divergence](prepared-mutant-finding.json) |
| Healthy control app versus itself | Launch, Save | [No divergence](two-action-negative-finding.json) |
| Healthy control app versus deliberately crashing variant | Launch, Save | [Crash candidate at action 1](positive-control-finding.json) |
| Same known crash, repeated paired run | Launch, Save | [Crash candidate again at action 1](positive-control-repeat-finding.json) |

The combined runner's [positive repeat](positive-repeat-pair-report.json) and
[two-action negative control](two-action-negative-pair-report.json) reports
record the emulator fingerprint, APK hashes, trace hash, and independent run
paths.

The [independent queue check](queue-summary.json) admitted the one prepared
manifest mutant after hash and trace checks. Its paired launch run completed
with no divergence; the worker labeled it `unconfirmed`. This is a one-item
end-to-end queue check, not a throughput or discovery result.

The launch trace SHA-256 is
`3bb27f43042335731eb34be277b9a4a5e4684dcd6c28071544fa8e76f1664052`.
The two-action trace SHA-256 is
`a70f1d87a1144649158aa201da348136bec3c0d136b31541b2d51ed9e17491ea`.
The prepared original and manifest mutant SHA-256 values are
`88cd8dbb7fd80f7aa083af35d1f85f39aaed297f2ee8155d879b6ca8640153ec`
and `f56c17cadfdfe1d6da9f2d41423a29e65dc14576e794a224e5745d1de645290c`.
The control APKs were built with
`scripts/build-llmdroid-control-apks.sh`; their SHA-256 values are
`ae5fbc5ef61cf9e2300a52cbd6502a56d3f14bbbda4854ca8c96a8e7cc860181`
and `7cec1ca06cf9f8f676595188b4effbe853cd5c84c0ed4806a5f1e355794a6f5f`.

The mutated control app deliberately throws
`java.lang.IllegalStateException: CONTROLLED_SAVE_DEFECT` when Save is pressed.
The AndroidRuntime log recorded `FATAL EXCEPTION: main`, the control app's
process name, and that exception together. This verifies detection of one
known crash, not general crash sensitivity. The manifest mutant's observed
equivalence applies only to the launch action. Neither result is evidence of
a confirmed security vulnerability. Guided exploration, longer trace replay,
broader controls, and scientific comparisons still require separate runs.

An earlier two-action healthy/healthy attempt was inconclusive because the
accessibility helper returned no device state. A first retry exposed a runner
precheck error when `pm path` returned exit code 1 for an absent package; that
error was fixed. The completed healthy/healthy result above is the subsequent
retry. Inconclusive attempts were excluded from the no-divergence result.
