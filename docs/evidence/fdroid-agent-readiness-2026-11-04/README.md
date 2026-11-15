# F-Droid agent readiness, 2026-11-04

## Verified controls

The planned two 72-hour AFL++ arms have **not** started. Their locked
`random-range` and `manifest-bitflip` settings remain separate from the
bounded one-bit feasibility run below. The app under test was the local
F-Droid APK (SHA-256
`1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`).
Its emulator was a fresh, offline Android 29 instance with fingerprint
`Android/sdk_phone_x86_64/generic_x86_64:10/QSR1.210820.001/7663313:userdebug/test-keys`.
The host's local ELM key passed a live probe for
`mistralai/Mistral-Small-4-119B-2603`; the key remained owner-only and was
not found in checked agent output files.

Original F-Droid guided exploration completed 8/8 actions with two model
requests (2,333 prompt and 188 completion tokens). Trace SHA-256:
`ef5752d1119c5759509e4d085efeab2559c78dc43765d1d2959360212248f3a1`.
An original/original replay completed both roles with no divergence. Reports
and trace are under ignored `results/fdroid-guided-2026-11-04/`.

A separately test-signed copy of the original has SHA-256
`f14653a6e7025f7176a75b5f5c3aff3e4b4472138818ce92588ca5be2419625c`.
Re-signing the original twice produced the same hash. Its own guided run
completed 8/8 actions with two model requests (2,329 prompt and 192
completion tokens). Trace SHA-256:
`3d3edc9f1115edf61aa2c3196a1b59be632295602aa1385d44e8216988c643e9`.
Its identical-baseline replay also showed no divergence. These original and
signed-baseline traces have different source hashes and cannot be swapped.
Signed reports are under `results/fdroid-signed-guided-2026-11-04/`.

## One prepared AFL candidate

A **separate 30-second feasibility run** used locked `manifest-bitflip` with
`APKFUZZ_MAX_FLIPS=1` and AFL seed `10414`. This is not either planned 72-hour
arm. Its exact generation-one mutant SHA-256 was
`0476a34fd491a77c3b89891d57f5a48f93dd1b8d9554cc1642062aa90d5205b5`.
The exact APK failed ZIP CRC/signature checks and remains preserved. The
narrow preparation tool verified its patch and manifest lineage, repaired
the CRC in a separate copy, and signed both roles with the same local test
certificate. Prepared mutant SHA-256:
`690b2fe9ec1f32f265fa971f7c3811f033d8a49e9e5b5729f362c33daaab2f25`.
The prepared baseline matched the signed control hash above.

The agent stage admitted one prepared pair and blocked a second candidate.
It ran a fresh identical-baseline control, two paired replays, and independent
8-action model-guided runs of both prepared roles. Control and both replays
reported `no_divergence_observed`; both guided roles completed with two model
requests each (baseline: 2,326 prompt/185 completion tokens; mutant: 2,327
prompt/190 completion tokens). Raw artifacts are under ignored
`results/fdroid-agent-onebit-10414-2026-11-04/`. This verifies one F-Droid
post-mutation agent path. It is not evidence of a defect, vulnerability, or
long-arm candidate result.

## Post-72-hour procedure

The main sequence captures up to 12 exact queue candidates per arm with a
deterministic sample seeded by its AFL seed. Capture, hash/patch verification,
ZIP/manifest/signature preflight, and queue creation happen **after AFL
stops**. No ELM request occurs in the mutation loop. After a successful arm,
start a fresh, offline API 29 emulator using the prepared local AVD, then
check the agent plan:

```bash
cd /home/sahar/Projects/ApkVulFuzz
ANDROID_AVD_HOME="$PWD/results/llmdroid-fdroid-avd-home" \
  emulator -avd apkfuzz_fdroid29 -port 5562 -no-window -no-audio \
  -no-boot-anim -gpu swiftshader_indirect -no-snapshot -wipe-data
# In a second terminal, after `adb -s emulator-5562 shell getprop sys.boot_completed` returns 1:
adb -s emulator-5562 shell svc wifi disable
adb -s emulator-5562 shell svc data disable
.venv-llmdroid/bin/python -B scripts/probe-llmdroid-elm.py
```

The emulator command stays running until the agent stage finishes; shut it
down with `adb -s emulator-5562 emu kill`. Use a fresh output directory and
recheck the key/model before each post-run agent stage. For an exact
install-eligible candidate:

```bash
python3 -B scripts/run-fdroid-agent-stage.py check \
  --arm-dir results/fdroid-72h-2026-11-04a-random-range
python3 -B scripts/run-fdroid-agent-stage.py run \
  --arm-dir results/fdroid-72h-2026-11-04a-random-range \
  --serial emulator-5562 \
  --output-dir results/fdroid-72h-2026-11-04a-random-range/agent-stage-exact
```

For a separately prepared candidate, first use
`scripts/prepare-manifest-runtime-candidate.py` with that arm's capture
manifest, preflight report, exact queue entry, local test key/certificate,
and a fresh output directory. It accepts only verified generation-one,
one-bit manifest changes that remain parseable; it must not be applied
blindly to the planned 16-flip arm. Then use:

```bash
python3 -B scripts/run-fdroid-agent-stage.py check \
  --arm-dir results/fdroid-72h-2026-11-04a-manifest-bitflip \
  --signed-baseline --prepared-report /path/to/preparation.json
python3 -B scripts/run-fdroid-agent-stage.py run \
  --arm-dir results/fdroid-72h-2026-11-04a-manifest-bitflip \
  --signed-baseline --prepared-report /path/to/preparation.json \
  --serial emulator-5562 \
  --output-dir results/fdroid-72h-2026-11-04a-manifest-bitflip/agent-stage-prepared
```

`check` is read-only and reports `ready`/`blocked` counts. `run` first
replays the identical baseline, then repeats deterministic paired replay
twice per admitted candidate and makes bounded ELM-guided runs of each
verified baseline and mutant. If no pair is runtime-eligible, it records
`blocked_no_runtime_eligible_pair`, returns nonzero, and makes no model call
on invalid APKs. Partial and infrastructure outcomes stay separate from app
divergence. Pair and queue replay timeouts produce explicit inconclusive
reports. The key remains in its ignored file and is never passed on the
command line.

The main 72-hour arms do **not** guarantee a runtime-eligible mutant. The
one-bit control is a separate denominator; do not combine it with exact
mutants from the main arms. Report admission counts, blocked reasons, and
any paired outcomes as observed.
