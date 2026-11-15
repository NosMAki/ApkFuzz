# RESEARCH_PROTOCOL.md — Reproducible Security Experiments

## Before the experiment
- State the precise question and falsifiable hypothesis.
- Record authorized targets and boundaries (lab VM, emulator, owned app, local test service, or permission reference).
- Choose an inert or controlled environment; avoid uncontrolled scanning, credential capture, live infrastructure impact, and unintended egress.
- Identify baseline/control, independent variable, and measurable outcomes.
- Freeze relevant tool versions, configuration, RNG seed where possible, and input samples.
- Define stop conditions, duration, resource limits, and expected artifact locations.

## During the experiment
- Capture exact commands, environment, version, timestamps, inputs, and outputs.
- Keep raw logs separate from interpreted findings; cap log ingestion and summarize relevant ranges.
- Prefer one-variable-at-a-time comparisons. Record failed and null experiments too.
- For fuzzing: record engine + version, target build, instrumentation, corpus size, dictionary, strategy, timeout, exec rate, coverage where available, crashes, hangs, and sanitizers.
- Track any mutations to baselines and mark experimental changes clearly.

## Crash and finding triage
1. Preserve and hash the sample; protect sensitive data.
2. Reproduce in the same environment and record the exact invocation and exit signal.
3. Minimize the input while preserving the failure; keep the original.
4. Check for duplicates using stack trace, fault site, and root cause; avoid counting every crashing input as a distinct bug.
5. Assess whether the failure is in the harness, emulator, target, or instrumentation.
6. Record evidence and confidence separately from impact/severity. Do not claim exploitability without validation.

## Reporting format
- Title / date / objective / authorization and environment
- Hypothesis and controlled variables
- Tool and source versions / exact command / test duration
- Observed results (with artifact paths and reproducible steps)
- Interpretation, uncertainty, confounders, and limitations
- Next experiment / regression test
