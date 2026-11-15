# LLMDroid integration: pinned environment and current status

## Integration boundary

LLMDroid-Droidbot is an external, optional dependency. APKVulFuzz's AFL++
loop, custom mutators, path-file harness, and existing modified DroidBot
checkout remain independent. The selected upstream commit is
`5b5485cf195583370d49e353601985850210277e` from
`https://github.com/security-pride/LLMDroid`. The upstream tree has no
top-level LICENSE file at this commit; its DroidBot `setup.py` declares MIT.
We use a separate local checkout and do not vendor upstream source into this
repository.

The checked source contains the expected `UtgBasedInputPolicy.generate_event`,
`__switch_mode`, and `__resolve_new_action` methods. `InputManager.add_event`
uses `EventLog`, which writes one JSON record for each action under `events/`.
`scripts/export-llmdroid-trace.py` collects those records into an ordered
trace with source hashes. A 12-action ELM-guided control-app trace is now
recorded in ignored local results; see the
[guided evidence](evidence/llmdroid-elm-2026-10-28/README.md).

## Reproduce the isolated setup

From the APKVulFuzz root:

```bash
git clone --filter=blob:none --sparse --no-checkout \
  https://github.com/security-pride/LLMDroid.git .deps/LLMDroid
git -C .deps/LLMDroid checkout 5b5485cf195583370d49e353601985850210277e
git -C .deps/LLMDroid sparse-checkout set LLMDroid-Droidbot documents
python3 -m venv .venv-llmdroid
.venv-llmdroid/bin/python -m pip install -r requirements-llmdroid.txt
python3 -B scripts/patch-llmdroid-local.py .deps/LLMDroid
```

The local patch blanks the credential in upstream's tracked example config,
requires `APKVULFUZZ_LLM_API_KEY` from the process environment for guided
exploration, redacts `ApiKey` from upstream's configuration log, and writes
per-request token usage and elapsed time to `LLM-Usage.jsonl` when the provider
returns usage counts. The patch also handles Android's `null` accessibility
setting as an empty service list on a fresh emulator. The patch
refuses a different upstream commit or source layout. The Python environment
is independent of `.venv-droidbot`; its installed package versions from this
machine are in
[`evidence/llmdroid-environment-2026-10-21/requirements-freeze.txt`](evidence/llmdroid-environment-2026-10-21/requirements-freeze.txt).
The upstream entry point imported and displayed `-h` successfully after adding
`JPype1` and `setuptools<81`, both needed at import time but absent from
upstream `setup.py` dependencies.

## ELM test credential

Run `bash scripts/save-llmdroid-elm-key.sh` in a local terminal and enter
the ELM API key at the hidden prompt. It creates an owner-only file under
ignored `results/llmdroid-credentials/`; no key is put in source control or in
LLMDroid's config. `scripts/run-llmdroid-smoke.py` reads the file only in
guided mode and uses ELM's OpenAI compatible endpoint. The current default
model is `mistralai/Mistral-Small-4-119B-2603`, as listed in the
[ELM model guide](https://information-services.ed.ac.uk/computing/elm/elm_competence_centre/elm-models-available-through-the-api).
The guide says API availability depends on the account and key, so the live
model must be verified before guided testing. The assumed API root is
`https://elm.edina.ac.uk/api/v1/`; pass `--base-url` if ELM's API page for this
key specifies a different root. Check the credential and model first with
`.venv-llmdroid/bin/python scripts/probe-llmdroid-elm.py`. This makes one small
chat request after checking ELM's model list. UI descriptions and any text the agent reads may be sent to
the selected provider, so use only an authorized test app without sensitive
data. The generated `LLM_QA.txt` may contain app text and remains in ignored
local results.

The smoke runner uses LLMDroid's built-in `time` coverage mode to test an
uninstrumented APK. This mode provides no code-coverage measurement; it is a
compatibility test, not a substitute for the instrumented scientific run.
The runner uses a separate output directory, a bounded event count and timeout,
and a process watchdog. Example after the emulator is ready:

```bash
.venv-llmdroid/bin/python scripts/run-llmdroid-smoke.py \
  --checkout .deps/LLMDroid \
  --apk results/llmdroid-stage1-2026-10-21/prepared-pair-verified/prepared-baseline.apk \
  --serial emulator-5562 \
  --output-dir results/llmdroid-guided-smoke \
  --mode guided --event-count 5 --timeout 180
```

## Device evidence and limits

The first offline framework attempt on the existing software API 34 emulator
encountered a package service that had not finished starting. A later attempt
reached the LLMDroid accessibility helper but waited for it to stay bound. The
API 34 image also produced many unrelated system ANRs under software
emulation. That run was stopped and classified as infrastructure failure, not
an app defect. Its ignored local report is
`results/llmdroid-offline-smoke-2026-10-21/smoke-report.json`.

A separate temporary Android 29 AVD using the default system image completed
the offline LLMDroid framework check: the helper connected, the prepared
baseline installed and started, and the run cleaned up. Its ignored local
report is `results/llmdroid-offline-api29-retry-2026-10-21/smoke-report.json`.
The run used `policy=none` and wrote zero action events, so it verifies device
integration only. The exact APK and prepared pair from the feasibility
experiment are kept under ignored local `results/llmdroid-stage1-2026-10-21/`.
LLMDroid-guided control-app exploration succeeded with the locally stored ELM
credential. The prepared app-lister's short run produced no model call, and
scientific evaluation still requires additional experiments;
see the [guided evidence](evidence/llmdroid-elm-2026-10-28/README.md).

## Non-LLM replay controls

`scripts/record-llmdroid-launch-fixture.py` uses upstream `EventLog` to record
a launch action, or a launch followed by one uniquely matched Button tap. The
fixture and `scripts/export-llmdroid-trace.py` can validate the trace/replay
pipeline without an API credential. `scripts/replay-llmdroid-trace.py` uses the
same pinned LLMDroid `Device`, `App`, and `InputEvent` stack. It reinstalls the
app for each role, rejects coordinate-only and ambiguous UI actions, keeps
per-step screenshots and logcat, and has a process watchdog. Intent replay is
restricted to launch and force-stop commands for the test package.

`scripts/run-llmdroid-pair.py` runs the baseline and mutant sequentially on
one booted emulator, then writes structured and human-readable comparison
reports. A completed original/original launch control produced no divergence.
The prepared one-byte manifest mutant also produced no divergence on that
single launch action; this does not establish that all behavior is equal.

To test a known runtime defect, `scripts/build-llmdroid-control-apks.sh`
creates two small APKs with the same package and certificate. Both show a Save
button; the altered variant deliberately throws `CONTROLLED_SAVE_DEFECT` when
it is pressed. A two-action trace recorded from the healthy variant replayed
successfully on it and triggered the expected AndroidRuntime crash on the
altered variant. The comparator reported `crash_candidate` at action 1. The
build script keeps its temporary signing key under ignored local results.
The control artifacts and reports are summarized in
[`evidence/llmdroid-replay-2026-10-21/README.md`](evidence/llmdroid-replay-2026-10-21/README.md).

## Independent candidate queue

With `APKFUZZ_CAPTURE_LIMIT` enabled, `scripts/run-corpus-smoke.sh` creates
`candidates/analysis-queue.json` after AFL++ exits. No Android or LLM work runs
inside the fuzzing loop. Identical exact-mutant/original pairs from multiple
AFL queue entries share one analysis item, while retaining all queue entry names.
The queue planner requires a matching preflight and
trace and verifies all exact and prepared artifact hashes before admission.
Prepared pairs must also match the original APK hash recorded at capture.
For a prepared pair and exported trace:

```bash
python3 -B scripts/llmdroid-analysis-queue.py plan \
  --queue /path/to/candidates/analysis-queue.json \
  --preflight /path/to/preflight.json --trace /path/to/trace.json \
  --prepared-report /path/to/preparation.json \
  --device-report /path/to/mutant-device-probe.json \
  --output /path/to/analysis-plan.json
```

A pair is `ready` only when a `probe-android-runtime.py` report shows that
exact prepared mutant passing the device launch gate against its baseline;
without one the item is blocked with `device_launch_gate_missing` or
`device_launch_gate_failed`. `run-fdroid-agent-stage.py` takes the same
`--device-report` option.

Then, on an already booted emulator, run `llmdroid-analysis-queue.py run` with
the plan, LLMDroid checkout, serial, and a new output directory. It calls the
paired runner outside AFL++, repeats candidates twice by default, and retains
each report. Crash grouping now requires the same app process, exception type,
and first app stack frame in the captured log; a missing stack prevents an
automated crash reproduction claim. Other divergences have no automatic
cross-candidate deduplication. Repeated runs with no divergence are reported
as `no_divergence_observed`, while incomplete runs remain inconclusive. A
repeated automated divergence is still a candidate until
manually validated; it is never labeled a confirmed security vulnerability.
