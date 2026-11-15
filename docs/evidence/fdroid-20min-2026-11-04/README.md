# Bounded F-Droid 20-minute test, 2026-11-04

## Question and scope

Can the selected locked AFL++ arms run for ten minutes each on the authorized
local F-Droid APK, preserve exact queue candidates, and hand any eligible
pair to the LLMDroid agent stage? This is a 20-minute **AFL time** acceptance
test, not either planned 72-hour campaign. The arms ran sequentially with
fresh output directories, fixed seeds, a 12-candidate capture limit, and
seeded queue sampling. The app was not installed on Android during these
two arms. The host used `systemd-inhibit` to avoid sleep; the runner's
scratch reaper and resource watchdog remained active.

```bash
systemd-inhibit --what=sleep:idle --mode=block --why='APKVulFuzz bounded F-Droid run' \
  env APKFUZZ_CAPTURE_LIMIT_OVERRIDE=12 bash scripts/run-fdroid-locked-arm.sh \
  random-range 600 10407 results/fdroid-20min-2026-11-04-random-range
systemd-inhibit --what=sleep:idle --mode=block --why='APKVulFuzz bounded F-Droid run' \
  env APKFUZZ_CAPTURE_LIMIT_OVERRIDE=12 bash scripts/run-fdroid-locked-arm.sh \
  manifest-bitflip 600 10408 results/fdroid-20min-2026-11-04-manifest-bitflip
```

The F-Droid APK SHA-256 was
`1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`.
Mutator SHA-256 values were `random-range`
`473051b51f5b2316480bbfa841d1bc7ea78f816939dbad0e190d4f3736600ef8`
and `manifest-bitflip`
`b0df959e80771f92ff380f6d5ef9fb77ef3b666a9247bd0b1f76457fc433204e`.
AFL++ was `4.09c`. Both logs showed the requested effective mode with
`locked=1`. No flip-count or generation-cap override was set. UTC start
times were `20:44:35` and `20:55:07` respectively. The precise commands,
Git HEAD/worktree status, source hashes, and resource headroom are in each
ignored `results/` output directory's `config.txt` and `source-sha256.txt`.

## Observations

| Arm | AFL duration | Executions | Mean exec/s | Final corpus | AFL crashes / hangs | Preserved exact candidates | Android preflight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| random-range | 600 s | 22,880 | 38.13 | 30 | 0 / 0 | 12/12 selected | 12 blocked |
| manifest-bitflip | 600 s | 22,219 | 37.03 | 3 | 0 / 0 | 2/2 selected | 2 blocked |

Both runners returned exit code 0. No resource watchdog error was written.
The random arm saved 22,496 patch files; the manifest arm saved 22,139.
Both patch stores occupied about 90 MiB on disk. The scratch directories were
removed at completion. The last resource check found about 7.6 GiB free in
`/dev/shm`, 266 GiB free on the project filesystem, and 26.6 million free
inodes. System-wide physical write estimates printed by the runner were
596.9 MB and 456.4 MB, respectively; those include other host activity.

Every captured candidate had matching patch integrity and preserved APK hash.
All 14 failed ZIP and signature preflight, so manifest validation could not
proceed. The manifest arm's two candidates both had 16 edits; neither meets
the narrow one-bit runtime-preparation rule. The agent stage was invoked for
both arms and recorded `blocked_no_runtime_eligible_pair` with `ready=0`.
It made no API calls on these invalid candidates. This is a runtime admission
result, not a failure of the ELM credential or the previously verified agent
control path.

Raw evidence: `results/fdroid-20min-2026-11-04-random-range/` and
`results/fdroid-20min-2026-11-04-manifest-bitflip/`. Capture manifest SHA-256
values are `dc5f6f8b8d0d806a4eb08a09ba14e6c258cd3f4f8065d7e9dc349d028ce6f7e3`
and `91f524449dc9acabadb44cd0e902b8ab28cde1d1ee8f1a25c6bf2486eb4112e9`.
Preflight report SHA-256 values are
`3df412b88e2157b9cd4ef3ddc2d0496819b294798bb55139b9d19cd986d0e54a`
and `f502f2518cad6557180f1e597f893dfd88e40e255cca1d58aacd6355a14e6dd3`.

## Interpretation and next step

The test supports bounded campaign stability and exact-candidate retention
for both selected modes. It does not measure 72-hour stability, Android
runtime behavior of these mutants, a target-app defect, or a vulnerability.
The separately documented one-bit F-Droid feasibility candidate remains a
distinct denominator and is not counted among these 14 candidates. Recheck
resources before a long run. To obtain agent comparisons from the long arms,
a candidate must pass exact install eligibility or a separately validated
preparation method with a matching signed baseline trace.
