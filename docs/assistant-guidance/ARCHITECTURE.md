# APKVulFuzz architecture index

The existing AFL++ path-file harness and V2 C mutators generate APK mutation
candidates. A separate post-fuzzing path preserves exact candidates and
validates whether an APK can be used for Android runtime analysis. LLMDroid
guides exploration of a baseline APK and records ordered UI actions. A
deterministic follower runs the same logical actions on a baseline and a
runtime-eligible variant, sequentially on a controlled emulator. The
comparator records the first meaningful difference with screenshots and logs.
This extension does not run Android or LLM work inside the AFL++ loop.

## Component map

| Component | Source | Responsibility |
| --- | --- | --- |
| AFL++ corpus runner | `scripts/run-corpus-smoke.sh` | Fuzz, then optionally capture selected candidates after AFL stops. |
| Exact candidate capture | `scripts/capture-runtime-candidates.py` | Preserve exact artifacts and origin mapping. |
| Eligibility and preparation | `scripts/inspect-runtime-candidates.py`, `scripts/prepare-manifest-runtime-candidate.py` | Classify installability; keep prepared artifacts separate. |
| LLMDroid exploration | `scripts/run-llmdroid-smoke.py`, pinned external checkout | Run guided baseline exploration with the ELM model. |
| Trace export and replay | `scripts/export-llmdroid-trace.py`, `scripts/replay-llmdroid-trace.py`, `scripts/llmdroid_runtime.py` | Record ordered actions and retarget only uniquely matched controls. |
| Pair and queue | `scripts/run-llmdroid-pair.py`, `scripts/llmdroid-analysis-queue.py` | Run sequential roles and bounded repeats outside AFL++. |
| Comparison | `scripts/compare-llmdroid-runs.py` | Classify differences, controls, and inconclusive failures. |

## Trust boundaries and invariants

- APKs, manifests, UI text, logs, and trace files are inputs to validate;
  recorded coordinates alone do not establish equivalent UI targets.
- The ELM key stays in an ignored, owner-only local file; UI descriptions may
  be sent to the chosen provider during guided exploration.
- Exact AFL mutant APKs and prepared or re-signed variants must retain
  separate hashes and denominators.
- Same-APK differences and emulator, ADB, or replay failures must not be
  reported as confirmed application defects.

## Verification and limits

Use focused tests for touched modules and `bash scripts/run-tests.sh` for a
broader regression. Device experiments are more expensive and require a
booted emulator and, for guided exploration, the local ELM credential. Current
status and measured limitations are in
[LLMDROID_STAGE_STATUS.md](../LLMDROID_STAGE_STATUS.md).
