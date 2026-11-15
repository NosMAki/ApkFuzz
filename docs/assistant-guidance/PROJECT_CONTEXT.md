# APKVulFuzz project context

This is a short index of verified repository facts. Recheck code and evidence
before relying on a status claim; the research extension is still in progress.

## Identity and scope

- Project: APKVulFuzz, an AFL++ based APK fuzzing research project.
- Current extension: LLMDroid-guided Android UI exploration and synchronized
  replay of original and mutated APKs. The approved design preserves the
  existing AFL++ custom mutators, path-file workflow, and modified DroidBot.
- Local experimental scope: repository APK corpus, controlled test APKs, and
  temporary Android emulators. Do not infer authorization for unrelated apps,
  services, networks, or devices.
- Languages and tools present: C custom mutators, Python and shell scripts,
  AFL++, Android SDK/ADB, DroidBot, and an isolated LLMDroid Python environment.

## Where to start

- [README.md](../../README.md) documents the existing APKVulFuzz setup.
- [LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md) is the current Stage
  0–10 checklist; follow its evidence links for experiment details.
- [LLMDROID_INTEGRATION.md](../LLMDROID_INTEGRATION.md) records the integration
  boundary, pinned upstream revision, ELM provider setup, and runner paths.
- [LLMDROID_EVALUATION_PROTOCOL.md](../LLMDROID_EVALUATION_PROTOCOL.md) defines
  comparison conditions and metrics.
- The main regression command is `bash scripts/run-tests.sh`; use focused
  tests first when changing one component.

## Current verified limits

- A bounded sample of 34 exact mutants across two corpus APKs yielded zero
  installs. Prepared runtime variants have distinct identities and must be
  reported separately from exact mutants.
- Guided LLMDroid and deterministic paired replay worked on a small control
  app. A known deliberate crash was reproduced twice in earlier controls.
- A corpus app trace containing an onboarding `SKIP` action did not replay
  reliably. Recent software-emulator follow-ups were inconclusive because of
  changing first-run state and Android log/watchdog failures.
- Full repeated multi-app evaluation and a verified real AFL-mutant defect
  remain open. See the stage checklist for the latest status.

## Data handling

The ELM credential is in an ignored, owner-only local file under `results/`.
Do not copy its value into source, reports, or chat. Raw APKs and device outputs
under ignored `results/` are local evidence, not tracked project documentation.
