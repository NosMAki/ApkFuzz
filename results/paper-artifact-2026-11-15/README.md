# APKVulFuzz paper evidence package — 2026-11-15

`paper-evidence.tar.gz` is a curated, hashed **evidence package** for the
first-generation compressed-manifest study, not a new experimental result.
`MANIFEST.sha256` identifies every included source file. Archive paths are
relative to the repository root. The four dated experiment folders each
contribute their `PROTOCOL.md` and `REVIEW.md`; the enumeration and semantic
folders also contribute their full tables, scripts, summaries, and device
outcome records. The new oracle and paper-framing drafts are included.
The later three-seed AFL protocol/review and gate-v3 control protocol/review,
run summaries, and control JSON are included as separate evidence layers.
The controlled AFL Python exception check is included with its log and map.

## Identity and environment recorded in the source reviews

- Git HEAD: `96f82a05f0376d4f79b897b72f6a6d17d907143d`, with uncommitted
  changes. Source file hashes in `MANIFEST.sha256` are the identity for this
  package; HEAD alone does not reproduce it.
- Origin F-Droid APK SHA-256:
  `1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`.
- `manifest-axml-onebit` binary SHA-256:
  `ba42388c6fb50d7ce6917dc863b79b2047c14547b631f852fd5bd5093bb56496`.
- Historical host: Linux 7.0.0-43-generic x86_64; Python 3.12.3;
  clang 18.1.3; AFL++ 4.09c; `aapt` Build Tools 34.0.0;
  `apksigner` 0.9; adb 1.0.41; emulator 36.5.11.0; Androguard 4.1.4.
- Android 10 emulator fingerprint:
  `Android/sdk_phone_x86_64/generic_x86_64:10/QSR1.210820.001/7663313:userdebug/test-keys`.
- Enumeration covers 71,368 bit positions; 16,024 accepted. Device sample:
  120 accepted flips using seed 10436, 93 healthy gate-v2 launches, 37/37
  repeat classes agreeing after the common crash-rule derivation. The AFL
  feasibility arm used one seed, 10435, and is not a multi-seed yield study.
- A separate three-seed 120-second check used seeds 10441–10443 and recorded
  one exact ZIP/manifest-valid but signature-invalid mutant per seed. The
  excluded first 10441 attempt is documented in its review. A fresh gate-v3
  baseline/inert/crasher/baseline control check passed on the same emulator
  fingerprint; its crasher's 15 fatal blocks had one fingerprint during one
  install.

The origin APK, signed derivatives, large UI run logs, and full per-mutant
APKs are not redistributed in this curated package. Their hashes and source
locations are recorded in the reviews. This package is suitable for auditing
the reported tables and methods; independent Android replay requires the
pinned APK, emulator image, signing setup, and full raw run artifacts.

Check the package after extraction from its repository root with
`sha256sum -c results/paper-artifact-2026-11-15/MANIFEST.sha256`.
