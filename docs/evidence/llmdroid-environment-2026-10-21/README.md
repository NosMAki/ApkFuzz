# Pinned LLMDroid local environment check

The official LLMDroid repository was inspected at commit
`5b5485cf195583370d49e353601985850210277e`. The isolated Python 3.12.3
environment's package versions are in [requirements-freeze.txt](requirements-freeze.txt).
The upstream `start.py -h` entry point imported successfully after adding
`JPype1` and `setuptools<81` to the environment.

The first software API 34 device attempts were inconclusive because Android
system services were still starting and the accessibility helper did not stay
bound. Inspection found upstream interpreted an unset Android setting as the
literal service name `null`; the local patch corrects that parser and also
keeps API credentials out of configuration logs. The existing AVD was used in
read-only mode and shut down.

A temporary API 29 AVD using the default system image completed an offline
LLMDroid-Droidbot check with the signed baseline test APK. The helper connected,
the app installed and started, and cleanup completed. The
[smoke report](offline-api29-smoke-report.json) records 31.959 seconds of
runner time and zero action files. The policy was `none`, so this check does
not establish LLM-guided exploration or action recording. Those require the
locally entered Gemini API key and a separate guided run.
