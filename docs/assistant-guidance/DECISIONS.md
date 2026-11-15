# APKVulFuzz durable design decisions

This is an index of decisions already reflected in implementation and the
approved Stage 0–10 plan. Recheck the linked evidence before changing one.

## ADR-001 — Keep LLMDroid separate from the fuzzing loop

- Status: accepted.
- Decision: use a pinned, isolated LLMDroid-Droidbot checkout for downstream
  Android exploration. Preserve the existing AFL++ mutators, path-file
  workflow, and modified DroidBot checkout.
- Consequence: candidate capture and the analysis queue run after fuzzing;
  no LLM or emulator call blocks AFL++ executions.
- Evidence: [LLMDROID_INTEGRATION.md](../LLMDROID_INTEGRATION.md).

## ADR-002 — Start with deterministic, sequential paired replay

- Status: accepted.
- Decision: record the baseline's actions, then replay them on baseline and
  variant in separate clean installs on one controlled emulator. Require a
  unique UI target; do not use coordinates alone or independent follower goals.
- Consequence: unmatched actions stop as synchronization failures. An optional
  semantic follower needs separate validation before use.
- Evidence: [LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md).

## ADR-003 — Preserve exact and prepared mutant identities

- Status: accepted.
- Decision: keep captured AFL outputs byte-for-byte. Any re-signed or repaired
  runtime APK is a different artifact with its own hash and denominator.
- Rationale: the bounded sample found 0 installs among 34 exact mutants;
  preparation must not be presented as exact-mutant runtime feasibility.
- Evidence: [mutation feasibility](../evidence/mutation-feasibility-2026-10-28/README.md).

## ADR-004 — Use ELM for guided local experiments

- Status: accepted for current integration experiments.
- Decision: use University of Edinburgh ELM Hosted with
  `mistralai/Mistral-Small-4-119B-2603`, keeping the key out of source and
  reports. The model and endpoint must be verified for the account in use.
- Evidence: [ELM-guided control](../evidence/llmdroid-elm-2026-10-28/README.md).

## ADR-005 — Android admission is decided on a device, not offline

- Status: accepted, 2026-11-15.
- Decision: a mutant reaches LLMDroid only after a device probe shows a
  running process, no fatal exception for the package, and the baseline's
  resolved activity. Offline checks (ZIP, binary-XML structure, `aapt` with
  warnings treated as failures, signature) only decide what is worth probing.
- Rationale: 16 of 38 generation-one and 12 of 40 generation-two mutants that
  passed the offline checks did not launch healthily; Androguard and Android
  disagreed in both directions; a crash-report process satisfied the older
  process-only check.
- Consequence: admission needs an emulator session and a baseline probe on
  the same device. The opt-in `manifest-axml-onebit` variant keeps manifests
  structurally sound; older variants and their binaries are unchanged.
- Evidence: [generation-one check](../../results/gen1-device-admission-2026-11-15/REVIEW.md),
  [gate and variant check](../../results/axml-admission-gate-2026-11-15/REVIEW.md).
