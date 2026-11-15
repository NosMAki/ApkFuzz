# Bounded Android runtime feasibility check, 2026-10-21

This check used the existing `test34` Android API 34 AVD. It was started with
`-read-only -no-snapshot -no-window -no-audio -no-boot-anim -gpu
swiftshader_indirect -accel off` because `/dev/kvm` was unavailable. The AVD
was stopped after the check. No APK or emulator configuration was changed.

The test APKs below were **unmodified controls**. Temporary zero-edit V2
patches and queue indexes exercised the capture, preflight, and device probe
gates. They do not measure the runtime success rate of AFL++ mutants.

| APK and SHA-256 | Device result |
| --- | --- |
| DroidBoxTests.apk `ee093aa086a1638edd22823ec3c806828caf40ee41f1f48367c172b516c9e070` | Signed and preflight eligible. Android rejected installation with `INSTALL_FAILED_DEPRECATED_SDK_VERSION` (target SDK 0). Package absent afterward. [Raw report](legacy-control.json). |
| droidbotApp.apk `5062e239fb82ee412fd1d7d34f4c65e595496e956932dec0d50d165b139aeb33` | Signed and preflight eligible. The package was already installed on the AVD, so the probe did not install, launch, or remove it. [Raw report](preinstalled-control.json). |
| app-lister.apk `6f6155c520750d7a12debfdf38483c25333b7053fd397830cdcb02df48a18b4f` | Signed and preflight eligible. `adb install` completed with `Success`. The package-wide launcher intent did not resolve; explicit launch of the APK's declared `MainActivity` returned `Status: ok`. `pidof` found no process two seconds later, so the result is `process_not_running`, not a sustained launch. Uninstall succeeded and a later `pm path` check confirmed absence. [Raw report](bench-control.json). |

The repository's F-Droid control
(`1dfce4269081693f10350dbabd26991a59d7c2bb81f870de54e5b113f4785b7a`)
did not complete `adb install` within 120 seconds on this software-emulated
AVD. A transient `pm path` entry appeared, but Android later logged that the
package was removed before post-install completed. Those attempts are
**inconclusive** for installation and launch. The probe now requires the
install command itself to complete successfully before attempting launch.

This establishes that the device probe can distinguish SDK rejection, an
existing installation, completed installation, launch command outcome, process
state, and cleanup. It does not establish that any saved AFL++ mutant is
installable. The next feasibility step is a traceable runtime candidate with
the exact AFL++ mutant hash and, if preparation is needed, a separate prepared
APK hash and recorded transformation. Test the original and candidate under
equivalent device conditions before attributing a difference to the mutation.

The JSON reports retain their original `/tmp` paths as provenance from this
session. Those temporary APK copies are not part of this repository; the
control APK hashes above identify the source bytes without redistributing them.
