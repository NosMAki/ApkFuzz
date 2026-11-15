# Flashlight corpus APK exploration pilot, 2026-10-28

This is a 12-action engineering comparison on the corpus file
`Evaluation-SSBSE-2026/apk/flashlight.apk` (package `cm.aptoide.pt`, APK SHA-256
`188bbdb899be2da401ac0471ba4d10693612fa1067f2ea0987cc6e1afcfd4374`).
Both arms ran on the same isolated Android API 29 emulator with clean installs.
The original DroidBot used `dfs_greedy`; LLMDroid used ELM-hosted
`mistralai/Mistral-Small-4-119B-2603`. Both were capped at 12 actions. The
LLMDroid runner used time mode, so this pilot has no code coverage measure.

| Arm | Recorded actions | State files | App foreground activities | LLM use |
| --- | ---: | ---: | ---: | ---: |
| Original DroidBot | 12 | 7 | 1 (`MainActivity`) | None |
| LLMDroid guided | 12 | 7 | 1 (`MainActivity`) | 6 calls, 11,368 reported tokens |

LLMDroid finished in 58.053 seconds according to its smoke report. Its trace
SHA-256 is `9ac1bda1a9c4970111fef91702804560e338f644a6f65c64b8c948388640804a`.
Raw outputs are under ignored `results/llmdroid-flashlight-pilot-elm-2026-10-28/`
and `results/droidbot-flashlight-pilot-2026-10-28/`. State hash values cannot
be compared across the two explorers because their state serialization differs.
This one run per arm gives no basis for a coverage or effectiveness advantage.

## Identical-APK replay control

The guided trace was replayed as the same APK in both roles. Both replays
reached `MainActivity`, but their screens differed after the launch action,
and both stopped at action 2 because the recorded `SKIP` button was absent.
Each role therefore completed only 2 of 12 actions. The raw comparison
initially labeled the earlier screen difference as a defect candidate. The
comparator now marks any divergence between identical APK hashes as
`inconclusive` / `identical_apk_divergence`; the corrected finding and
reclassified pair report are under
`results/llmdroid-flashlight-negative-pair-retry3-2026-10-28/`.

The screenshots show the same app page at different loading/animation states.
This is a replay synchronization failure and a false positive caught by the
identical-app control. It must not enter a mutant-defect count. The failure
also illustrates why a future semantic follower or a stabilized trace may be
needed for changing screens; it does not justify silently skipping recorded
actions in the current deterministic follower.

## Follow-up on replay setup

The trace begins with `kill_app` and then an explicit launch. Replay had been
launching the app once before that prefix, which could alter first-run state.
It now avoids that extra launch. Replay also now waits for a completed Android
installation before clearing app data; the upstream adapter may return while
its background install is still running. Focused tests cover the lifecycle
decision.

The first device retry after these changes never reached an action because
Android's package-manager data reset timed out in both roles. A direct reset
later succeeded. In the next retry, the baseline executed the stop and launch
actions, but the recorded onboarding `SKIP` target was still absent at action
2. The other role hit an Android log-collection error at action 0. The final
classification of that retry is `inconclusive`; it is not a valid same-APK
false-positive rate sample. Reports are under
`results/llmdroid-flashlight-negative-pair-install-fix-2026-10-28/`.

The source screenshot shows an onboarding page with `SKIP`, while the retry
shows the app home page. No app-specific external data directory was present
after uninstall. Device-wide or app-service first-run state remains a possible
cause, but is not established. A fresh emulator state per run or a trace that
starts after onboarding is needed before this app can be used for a reliable
paired replay control.

The emulator also intermittently failed `adb logcat -c`. Replay now retries
that reset up to three times; unit tests cover transient and persistent
failure. A follow-up known-defect control recorded the deliberate crash in
the defective app. Its healthy counterpart reached four correct actions but
hit the replay watchdog in the software emulator, so that new pair remains
inconclusive. The earlier completed known-defect pairs remain the verified
device results. The follow-up reports are under
`results/llmdroid-control-positive-install-fix-2026-10-28/` and
`results/llmdroid-control-baseline-log-retry-2026-10-28/`.
