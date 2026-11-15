# Bounded seed and LLMDroid meeting rehearsal, 2026-11-03

## Scope and setup

This rehearsal used only the local F-Droid corpus APK, the local APKVulFuzz
control APK, and a fresh temporary Android 29 emulator. It was not a campaign
or an unknown-app security test. AFL++ was version `++4.09c`; the pinned
LLMDroid commit was `5b5485cf195583370d49e353601985850210277e`.
The emulator build fingerprint was
`Android/sdk_phone_x86_64/generic_x86_64:10/QSR1.210820.001/7663313:userdebug/test-keys`.
The ELM key remained in its ignored owner-only file and is not included here.

## Fixed-seed AFL++ run

The isolated path-file seed pointed only to
`Evaluation-SSBSE-2026/apk/F-Droid.apk`. The locked
`cm-ApkVulFuzz2-manifest-bitflip.so` had SHA-256
`b0df959e80771f92ff380f6d5ef9fb77ef3b666a9247bd0b1f76457fc433204e`.
The command was:

```bash
APKFUZZ_INPUT_DIR="$PWD/results/meeting-rehearsal-2026-11-03/seed-input" \
APKFUZZ_SAVE_DIR="$PWD/results/meeting-rehearsal-2026-11-03/patches" \
APKFUZZ_CAPTURE_LIMIT=3 APKFUZZ_AFL_SEED=10406 \
bash scripts/run-corpus-smoke.sh 10 \
  build/mutators/cm-ApkVulFuzz2-manifest-bitflip.so manifest-bitflip \
  results/meeting-rehearsal-2026-11-03/afl
```

The run exited successfully after 10 seconds: 420 executions (41.79/s),
two queue items including the original seed, zero saved crashes, and zero
saved hangs. One new queue candidate was selected and its exact APK bytes
were preserved. The preserved APK SHA-256 is
`94a293c8a90c17ff34f63a5ba304dd274137dd54130edfedd00843ac11dba030`;
its source SHA-256 is
`1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`.
The copied patch chain reconstructed to the exact captured hash.
The `research_ready` capture flag describes preservation and provenance,
not Android runtime eligibility.

`scripts/inspect-runtime-candidates.py` then blocked this candidate:
ZIP validation failed, manifest validation was not reached, and the APK
signature was invalid. It was not installed or sent to paired replay. Raw
stats, candidate bytes, capture manifest, queue, patches, and preflight JSON
are under ignored `results/meeting-rehearsal-2026-11-03/`.

## ELM-guided control run

After restoring and locally guarding the pinned LLMDroid checkout, the
existing healthy control APK (SHA-256
`ae5fbc5ef61cf9e2300a52cbd6502a56d3f14bbbda4854ca8c96a8e7cc860181`)
was run with `mistralai/Mistral-Small-4-119B-2603` on the fresh emulator:

```bash
.venv-llmdroid/bin/python -B scripts/run-llmdroid-smoke.py \
  --checkout .deps/LLMDroid \
  --apk results/llmdroid-positive-control-2026-10-21/baseline.apk \
  --serial emulator-5562 \
  --output-dir results/meeting-rehearsal-2026-11-03/agent-control \
  --mode guided --event-count 12 --interval 2 --timeout 180 \
  --app-name 'APKVulFuzz Control' \
  --description 'A local test app with a Save button; explore its screens and actions.'
```

The run used 193.524 wall-clock seconds. It wrote three action events and
three state files, and made one ELM request: 887 prompt tokens, 44 completion
tokens, 931 total reported tokens, and 1.57449 seconds of reported request
latency. The three exported actions are app force-stop, app launch, and a
`SAVE` tap. The trace SHA-256 is
`2b9a39de432960be85650e62d3db6f70bad0ff821b418f33f758b14c14146dc7`.

The smoke report says `completed`, but this is **partial for the requested
12-action budget**. At the end of the bounded run, the DroidBot adapters
disconnected; a subsequent screenshot pull failed because the local
`droidbot-output/temp` destination no longer existed, and upstream logged a
state-collection exception before stopping event generation. This is an
infrastructure/runner outcome, not an application defect. No paired replay
or new defect confirmation was performed with this partial trace. The key
was absent from the smoke report and runner log in a direct local scan.

On 2026-11-04, `scripts/run-llmdroid-smoke.py` was changed to report `partial`
and exit nonzero when a guided run records fewer actions than its configured
limit. The raw 2026-11-03 report is preserved unchanged as historical evidence.

## Interpretation and next checks

`bash scripts/run-tests.sh` passed on this date, including deterministic
same-seed/different-seed mutator checks and all 17 locked variant checks.
The seed is an AFL++ mutator seed; it does not seed ELM's response generation.
This rehearsal verifies a bounded seeded AFL run, exact candidate retention,
runtime preflight rejection, and one real model-assisted control action
sequence. It supplies no Android code coverage, no runtime result for the
new AFL candidate, and no measure of agent effectiveness or false-positive
rate. The next device experiment should distinguish partial guided runs from
complete ones, then re-establish reliable original/original paired replay.
