# One captured manifest mutant: preparation and paired launch probe

This bounded feasibility experiment used the `app-lister.apk` test application
from the existing DroidBot checkout. The V2 `manifest-bitflip` mutator produced
an exact generation-one mutant with one bit changed at APK offset 2304470
(`3d` to `1d`). Its SHA-256 is
`48bf546df91dd3b9f75d31181c213a8686da4c96769904d43064a0f8b2581420`.
The original SHA-256 is
`6f6155c520750d7a12debfdf38483c25333b7053fd397830cdcb02df48a18b4f`.
The saved [patch](mutator-output.apk.patch),
[capture manifest](capture-manifest.json), and
[exact preflight](exact-preflight.json) document its provenance. The exact
mutant fails manifest ZIP CRC and APK signature validation, as expected.

The optional preparation script changed only the local and central manifest
CRC fields in a separate copy, then signed separate mutant and baseline APKs
with one ephemeral test certificate. The decompressed manifest changed by one
byte; the Android XML element `provider` became `promider`. The
[manifest diff](manifest-xmltree.diff) and [preparation report](preparation.json)
record the result. Both signed APKs passed ZIP, `aapt`, and `apksigner` checks.
An additional payload comparison after tightening the metadata check confirmed
that all 889 non-signature, non-manifest ZIP entries match between the prepared
pair. The historical `preparation.json` reports 834 because it excluded every
`META-INF` entry; the newer check includes non-signature `META-INF` payload.
The prepared mutant SHA-256 is
`f56c17cadfdfe1d6da9f2d41423a29e65dc14576e794a224e5745d1de645290c`;
the prepared baseline SHA-256 is
`88cd8dbb7fd80f7aa083af35d1f85f39aaed297f2ee8155d879b6ca8640153ec`.
The exact mutant and original were not changed. The signing key is outside the
repository; neither it nor the APK binaries are committed.

Both prepared APKs were tried separately on the same read-only API 34 software
emulator. Each installed, launched its app process, and was uninstalled. In
both cases Android's `am start -W` returned `Status: timeout` while `pidof`
confirmed the process was running. The [mutant](mutant-device-report.json) and
[baseline](baseline-device-report.json) reports therefore classify the result
as `launch_timeout_process_running`. This shows a possible runtime-compatible
mutation; it does not establish completed UI exploration or a behavior
divergence. Software emulation was slow and unrelated Google service ANRs
appeared, so the timeout cannot be attributed to either APK.

The selected exact APK, prepared pair, original test APK, and reports were also
copied to ignored local storage at `results/llmdroid-stage1-2026-10-21/` so the
full binaries remain available without entering source control. The evidence
JSON retains paths from the original `/tmp` run; verify SHA-256 values when
using the local copies. The read-only emulator was shut down after the probe.
