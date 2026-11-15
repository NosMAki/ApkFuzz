"""The device probe gates installs and always records cleanup."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-android-runtime.py"
ENTRY = "id:000001,src:000000,+cov"


class RuntimeProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkfuzz-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.capture_dir = self.base / "capture"
        (self.capture_dir / "apks").mkdir(parents=True)
        self.apk = self.capture_dir / "apks" / "candidate.apk"
        self.apk.write_bytes(b"signed test artifact")
        self.digest = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.manifest = self.capture_dir / "manifest.json"
        self.manifest.write_text(json.dumps({
            "candidates": [{"queue_entry": ENTRY, "stored_apk": "apks/candidate.apk",
                            "mutant_sha256": self.digest, "research_ready": True}]
        }))
        self.preflight = self.base / "preflight.json"
        self.write_preflight("eligible_for_install_attempt")
        self.aapt = self.base / "aapt"
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n"
                             "print('x' * 900)\n"
                             "print(\"launchable-activity: name='org.example.test.MainActivity'\")\n")
        self.aapt.chmod(0o755)
        self.adb = self.base / "adb"
        self.adb.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys, time\n"
            "args = sys.argv[1:]\n"
            "state = pathlib.Path(os.environ['FAKE_ADB_STATE'])\n"
            "with open(os.environ['FAKE_ADB_LOG'], 'a') as log: log.write(' '.join(args) + '\\n')\n"
            "if args == ['devices', '-l']: print('List of devices attached\\nemulator-5554\\tdevice product:test')\n"
            "elif args[-2:] == ['getprop', 'sys.boot_completed']: print('1')\n"
            "elif 'date' in args: print('1700000000')\n"
            "elif 'logcat' in args:\n"
            "    if 'system' in args and os.environ.get('FAKE_ANR_LOG_TIMEOUT'): time.sleep(3)\n"
            "    log_text = (os.environ.get('FAKE_ANR_LOG', '') if 'system' in args\n"
            "                else os.environ.get('FAKE_CRASH_LOG', ''))\n"
            "    sys.stdout.buffer.write((b'\\xc0\\xff ' if os.environ.get('FAKE_BAD_BYTES') else b'')\n"
            "                            + log_text.encode() + b'\\n')\n"
            "elif 'pm' in args and 'path' in args:\n"
            "    if os.environ.get('FAKE_PREINSTALLED') or state.exists(): print('package:/data/app/existing.apk')\n"
            "    else: sys.exit(1)\n"
            "elif 'install' in args:\n"
            "    if os.environ.get('FAKE_INSTALL_TIMEOUT_BEFORE_STATE'): time.sleep(2)\n"
            "    state.write_text('installed')\n"
            "    if os.environ.get('FAKE_INSTALL_TIMEOUT'): time.sleep(2)\n"
            "    print('Success')\n"
            "elif 'am' in args and 'start' in args:\n"
            "    if os.environ.get('FAKE_PACKAGE_LAUNCH_HANG') and '-n' not in args: time.sleep(3)\n"
            "    if os.environ.get('FAKE_PACKAGE_LAUNCH_FAIL') and '-n' not in args:\n"
            "        print('Error: Activity not started, unable to resolve Intent')\n"
            "    elif os.environ.get('FAKE_EXPLICIT_LAUNCH_TIMEOUT') and '-n' in args:\n"
            "        print('Status: timeout')\n"
            "    else: print('Status: ok\\nActivity: ' + os.environ.get(\n"
            "        'FAKE_ACTIVITY', 'org.example.test/.MainActivity'))\n"
            "elif 'pidof' in args: print('1234')\n"
            "elif 'uninstall' in args:\n"
            "    if os.environ.get('FAKE_UNINSTALL_FAIL'): print('Failure'); sys.exit(1)\n"
            "    state.unlink(missing_ok=True)\n"
            "    print('Success')\n"
        )
        self.adb.chmod(0o755)
        self.log = self.base / "adb.log"
        self.state = self.base / "adb.state"

    def write_preflight(self, status):
        self.preflight.write_text(json.dumps({"candidates": [{
            "capture_refs": [{"manifest": str(self.manifest), "entry": ENTRY}],
            "preflight": status, "capture_integrity": "match",
            "live_apk_match": "match", "mutant_sha256": self.digest,
        }]}))

    def invoke(self, execute=False, extra_env=None, serial="emulator-5554", timeout=30):
        report = self.base / (f"report-{len(list(self.base.glob('report-*.json')))}.json")
        cmd = [sys.executable, "-B", str(SCRIPT), "--capture-manifest", str(self.manifest),
               "--preflight-report", str(self.preflight), "--queue-entry", ENTRY,
               "--output", str(report), "--aapt", str(self.aapt), "--adb", str(self.adb),
               "--settle", "0", "--timeout", str(timeout)]
        if execute:
            cmd += ["--execute", "--serial", serial]
        env = os.environ.copy()
        env["FAKE_ADB_LOG"] = str(self.log)
        env["FAKE_ADB_STATE"] = str(self.state)
        env.update(extra_env or {})
        run = subprocess.run(cmd, capture_output=True, text=True, env=env)
        return run, json.loads(report.read_text()) if report.exists() else None

    def invoke_prepared(self, changed=False, baseline_run=False, extra_env=None,
                        with_baseline_report=True):
        original = self.base / "original.apk"
        baseline = self.base / "prepared-baseline.apk"
        prepared_apk = self.base / "prepared.apk"
        with zipfile.ZipFile(original, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"original")
        with zipfile.ZipFile(baseline, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"original")
        with zipfile.ZipFile(prepared_apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"mutated")
        exact = self.base / "exact-mutant.apk"
        exact.write_bytes(prepared_apk.read_bytes() + b"exact-mutant")
        repaired = self.base / "crc-repaired.apk"
        repaired.write_bytes(prepared_apk.read_bytes() + b"crc-repair")
        patch = self.base / "mutation.patch"
        patch.write_text("one verified mutation")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_hash = lambda content: hashlib.sha256(content).hexdigest()
        evidence = self.base / "preparation.json"
        evidence.write_text(json.dumps({
            "status": "ready_for_install_attempt", "queue_entry": ENTRY,
            "manifest_content_retained": True,
            "original_manifest_sha256": manifest_hash(b"original"),
            "mutated_manifest_sha256": manifest_hash(b"mutated"),
            "prepared_manifest_sha256": manifest_hash(b"mutated"),
            "origin_path": str(original), "origin_sha256": digest(original),
            "exact_mutant_path": str(exact),
            "exact_mutant_sha256": digest(exact),
            "crc_repair_path": str(repaired),
            "crc_repair_sha256": digest(repaired),
            "patch_path": str(patch), "patch_sha256": digest(patch),
            "prepared_apk_path": str(prepared_apk),
            "prepared_apk_sha256": digest(prepared_apk),
            "prepared_baseline_path": str(baseline),
            "prepared_baseline_sha256": digest(baseline),
        }))
        signer = self.base / "apksigner"
        signer.write_text("#!/bin/sh\nexit 0\n")
        signer.chmod(0o755)
        env = os.environ.copy()
        env["FAKE_ADB_LOG"] = str(self.log)
        env["FAKE_ADB_STATE"] = str(self.state)

        def probe(name, *extra, **overrides):
            report_path = self.base / name
            cmd = [sys.executable, "-B", str(SCRIPT), "--prepared-report", str(evidence),
                   "--output", str(report_path), "--aapt", str(self.aapt),
                   "--adb", str(self.adb), "--apksigner", str(signer), "--execute",
                   "--serial", "emulator-5554", "--settle", "0", *extra]
            run = subprocess.run(cmd, capture_output=True, text=True,
                                 env=dict(env, **overrides))
            return run, json.loads(report_path.read_text()) if report_path.exists() else None

        if baseline_run:
            return probe("prepared-device-report.json", "--use-prepared-baseline",
                         **(extra_env or {}))
        extra = []
        if with_baseline_report:
            # A prepared mutant is compared with a healthy baseline on the same device.
            run, _ = probe("baseline-device-report.json", "--use-prepared-baseline")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.log.unlink()
            extra = ["--baseline-probe-report", str(self.base / "baseline-device-report.json")]
        if changed:
            prepared_apk.write_bytes(prepared_apk.read_bytes() + b"changed")
        return probe("prepared-device-report.json", *extra, **(extra_env or {}))

    def test_default_plan_reads_metadata_without_adb(self):
        run, report = self.invoke()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "ready_for_device_probe")
        self.assertEqual(report["package"], "org.example.test")
        self.assertEqual(report["launch_activity"], "org.example.test.MainActivity")
        self.assertFalse(self.log.exists())

    def test_aapt_bad_xml_warning_blocks_device_probe(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "import sys\n"
                             "print(\"package: name='org.example.test'\")\n"
                             "print('Bad XML block: malformed attributes', file=sys.stderr)\n")
        run, report = self.invoke()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "metadata_unavailable")
        self.assertEqual(report["metadata"]["reason"], "malformed_xml_warning")
        self.assertIsNone(report["device_probe"])
        self.assertFalse(self.log.exists())

    def test_aapt_resource_warning_blocks_device_probe_on_exit_zero(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "import sys\n"
                             "print(\"package: name='org.example.test'\")\n"
                             "print('ResourceType W 11-15 10:52:46 1 1] Bad string block: '\n"
                             "      'string #247 entry is at 2301952, past end at 17516',\n"
                             "      file=sys.stderr)\n")
        run, report = self.invoke()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "metadata_unavailable")
        self.assertFalse(self.log.exists())

    def test_fatal_exception_for_package_is_not_a_healthy_launch(self):
        crash = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                 "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                 "E AndroidRuntime: java.lang.IllegalStateException: failed\n"
                 "E AndroidRuntime: at org.example.test.MainActivity.onCreate(MainActivity.java:21)")
        run, report = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": crash})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_crashed")
        self.assertEqual(report["device_probe"]["crash"]["package_fatal_exceptions"], 1)
        self.assertEqual(report["device_probe"]["crash"]["app_logic_candidates"], 1)
        self.assertEqual(report["device_probe"]["crash"]["suspected_manifest_rejections"], 0)
        self.assertIsNotNone(report["device_probe"]["crash"]["events"][0]["fingerprint"])
        self.assertIn("FATAL EXCEPTION", report["device_probe"]["crash"]["events"][0]["log_block"])
        self.assertEqual(report["device_probe"]["crash"]["incomplete_fatal_blocks"], 0)
        self.assertEqual(len(report["device_probe"]["crash"]["distinct_fingerprints"]), 1)
        self.assertEqual(report["device_probe"]["process"]["stdout"], "1234")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_manifest_rejection_is_separate_from_app_logic_candidate(self):
        for detail, reason in (
            ("java.lang.SecurityException: Permission X is required",
             "security_exception"),
            ("java.lang.ClassNotFoundException: MissingActivity",
             "class_not_found"),
            ("java.lang.RuntimeException: Unable to instantiate activity MissingActivity",
             "unable_to_instantiate"),
        ):
            with self.subTest(detail=detail):
                crash = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                         "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                         f"E AndroidRuntime: {detail}\n"
                         "E AndroidRuntime: at org.example.test.MainActivity.run(MainActivity.java:21)")
                run, report = self.invoke(execute=True,
                                          extra_env={"FAKE_CRASH_LOG": crash})
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(report["classification"], "launched_crashed")
                evidence = report["device_probe"]["crash"]
                self.assertEqual(evidence["suspected_manifest_rejections"], 1)
                self.assertEqual(evidence["app_logic_candidates"], 0)
                self.assertEqual(len(evidence["suspected_manifest_rejection_fingerprints"]), 1)
                self.assertIn(reason, evidence["events"][0]["manifest_rejection_reasons"])

    def test_process_line_without_fatal_header_is_not_a_crash(self):
        run, report = self.invoke(execute=True, extra_env={
            "FAKE_CRASH_LOG": "E AndroidRuntime: Process: org.example.test, PID: 77"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertEqual(report["device_probe"]["crash"]["package_fatal_exceptions"], 0)

    def test_fingerprint_ignores_stack_line_numbers(self):
        def crash(line):
            return ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                    "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                    "E AndroidRuntime: java.lang.IllegalStateException: failed\n"
                    f"E AndroidRuntime: at org.example.test.MainActivity.run(MainActivity.java:{line})")
        _, first = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": crash(21)})
        _, second = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": crash(94)})
        self.assertEqual(first["device_probe"]["crash"]["events"][0]["fingerprint"],
                         second["device_probe"]["crash"]["events"][0]["fingerprint"])

    def test_crash_loop_has_one_distinct_fingerprint(self):
        block = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                 "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                 "E AndroidRuntime: java.lang.SecurityException: denied\n"
                 "E AndroidRuntime: at org.example.test.MainActivity.run(MainActivity.java:21)\n")
        _, report = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": block * 2})
        evidence = report["device_probe"]["crash"]
        self.assertEqual(evidence["package_fatal_exceptions"], 2)
        self.assertEqual(len(evidence["distinct_fingerprints"]), 1)
        self.assertEqual(len(evidence["suspected_manifest_rejection_fingerprints"]), 1)

    def test_truncated_crash_log_is_not_a_healthy_launch(self):
        run, report = self.invoke(execute=True,
                                  extra_env={"FAKE_CRASH_LOG": "x" * 100100})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "runtime_evidence_unavailable")
        self.assertTrue(report["device_probe"]["crash"]["log_output_truncated"])

    def test_undecodable_bytes_in_crash_log_do_not_abort_the_probe(self):
        crash = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                 "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                 "E AndroidRuntime: java.lang.IllegalStateException: failed\n"
                 "E AndroidRuntime: at org.example.test.MainActivity.run(MainActivity.java:21)")
        run, report = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": crash,
                                                           "FAKE_BAD_BYTES": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_crashed")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_crash_evidence_outranks_a_launch_command_timeout(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n")
        crash = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                 "E AndroidRuntime: Process: org.example.test, PID: 77\n"
                 "E AndroidRuntime: java.lang.IllegalStateException: failed\n"
                 "E AndroidRuntime: at org.example.test.MainActivity.run(MainActivity.java:21)")
        run, report = self.invoke(execute=True, timeout=2, extra_env={
            "FAKE_PACKAGE_LAUNCH_HANG": "1", "FAKE_CRASH_LOG": crash})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["device_probe"]["launch"]["status"], "timeout")
        self.assertEqual(report["classification"], "launched_crashed")

    def test_other_package_crash_does_not_fail_the_launch(self):
        crash = ("E AndroidRuntime: FATAL EXCEPTION: main\n"
                 "E AndroidRuntime: Process: org.example.testing, PID: 77\n"
                 "E AndroidRuntime: java.lang.IllegalStateException: failed\n"
                 "E AndroidRuntime: at org.example.testing.MainActivity.run(MainActivity.java:21)")
        run, report = self.invoke(execute=True, extra_env={"FAKE_CRASH_LOG": crash})
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertEqual(report["device_probe"]["crash"]["package_fatal_exceptions"], 0)
        self.assertIn("-T 1700000001.000", self.log.read_text())

    def test_prepared_mutant_requires_baseline_probe_report(self):
        run, report = self.invoke_prepared(with_baseline_report=False)
        self.assertEqual(run.returncode, 2)
        self.assertIn("--baseline-probe-report", run.stderr)
        self.assertIsNone(report)
        self.assertFalse(self.log.exists())

    def test_prepared_mutant_must_resolve_the_baseline_activity(self):
        run, report = self.invoke_prepared(
            extra_env={"FAKE_ACTIVITY": "org.example.test/org.acra.dialog.CrashReportDialog"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_unexpected_activity")
        self.assertEqual(report["expected_activity"], "org.example.test/.MainActivity")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_execute_installs_launches_and_uninstalls(self):
        run, report = self.invoke(execute=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])
        calls = self.log.read_text()
        self.assertIn(" install ", calls)
        self.assertIn(" uninstall org.example.test", calls)
        self.assertLess(calls.index(" install "), calls.index(" uninstall "))
        self.assertFalse(self.state.exists())

    def test_declared_activity_is_used_when_launcher_intent_cannot_resolve(self):
        run, report = self.invoke(execute=True,
                                  extra_env={"FAKE_PACKAGE_LAUNCH_FAIL": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertIn("unable to resolve Intent", report["device_probe"]["launch"]["stdout"])
        self.assertEqual(report["device_probe"]["launch_fallback"]["status"], "ok")
        self.assertIn("-n org.example.test/org.example.test.MainActivity",
                      self.log.read_text())
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_android_launch_timeout_still_checks_process(self):
        run, report = self.invoke(execute=True, extra_env={
            "FAKE_PACKAGE_LAUNCH_FAIL": "1", "FAKE_EXPLICIT_LAUNCH_TIMEOUT": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launch_timeout_unverified")
        self.assertEqual(report["device_probe"]["process"]["stdout"], "1234")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_package_anr_on_launch_timeout_is_an_app_outcome(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n")
        anr = ("E ActivityManager: ANR in org.example.test\n"
               "E ActivityManager: Reason: Input dispatching timed out")
        run, report = self.invoke(execute=True, timeout=2, extra_env={
            "FAKE_PACKAGE_LAUNCH_HANG": "1", "FAKE_ANR_LOG": anr})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_anr")
        self.assertEqual(report["device_probe"]["anr"]["package_anrs"], 1)
        self.assertTrue(report["device_probe"]["anr"]["events"][0]["input_dispatch_timeout"])
        self.assertIn("ANR in org.example.test", report["device_probe"]["anr"]["events"][0]["log_block"])

    def test_other_package_anr_does_not_replace_infrastructure_timeout(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n")
        anr = ("E ActivityManager: ANR in org.example.testing\n"
               "E ActivityManager: Reason: Input dispatching timed out")
        run, report = self.invoke(execute=True, timeout=2, extra_env={
            "FAKE_PACKAGE_LAUNCH_HANG": "1", "FAKE_ANR_LOG": anr})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launch_timeout_infrastructure")
        self.assertEqual(report["device_probe"]["anr"]["package_anrs"], 0)

    def test_anr_log_unavailable_does_not_claim_infrastructure_timeout(self):
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n")
        run, report = self.invoke(execute=True, timeout=2, extra_env={
            "FAKE_PACKAGE_LAUNCH_HANG": "1", "FAKE_ANR_LOG_TIMEOUT": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "runtime_evidence_unavailable")
        self.assertEqual(report["device_probe"]["anr"]["status"], "timeout")

    def test_adb_timeout_of_launcher_command_is_inconclusive_not_launch_failed(self):
        # No declared launcher activity, so there is no explicit fallback launch.
        self.aapt.write_text("#!/usr/bin/env python3\n"
                             "print(\"package: name='org.example.test'\")\n")
        run, report = self.invoke(execute=True, timeout=2,
                                  extra_env={"FAKE_PACKAGE_LAUNCH_HANG": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["device_probe"]["launch"]["status"], "timeout")
        self.assertIsNone(report["device_probe"]["launch_fallback"])
        self.assertEqual(report["classification"], "launch_timeout_infrastructure")
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_blocked_preflight_never_contacts_adb(self):
        self.write_preflight("blocked")
        run, report = self.invoke(execute=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "skipped_preflight")
        self.assertFalse(self.log.exists())

    def test_existing_install_is_left_untouched(self):
        run, report = self.invoke(execute=True, extra_env={"FAKE_PREINSTALLED": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "package_already_installed")
        self.assertNotIn(" install ", self.log.read_text())
        self.assertNotIn(" uninstall ", self.log.read_text())

    def test_uninstall_failure_is_reported(self):
        run, report = self.invoke(execute=True, extra_env={"FAKE_UNINSTALL_FAIL": "1"})
        self.assertEqual(run.returncode, 1)
        self.assertIn("cleanup_failed", report["reasons"])
        self.assertFalse(report["device_probe"]["cleanup"]["complete"])
        self.assertTrue(self.state.exists())

    def test_timed_out_install_still_checks_and_removes_package(self):
        run, report = self.invoke(execute=True, timeout=1,
                                  extra_env={"FAKE_INSTALL_TIMEOUT": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "install_timeout")
        self.assertIsNone(report["device_probe"]["launch"])
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])
        self.assertFalse(self.state.exists())

    def test_timed_out_install_with_absent_package_has_uncertain_cleanup(self):
        run, report = self.invoke(execute=True, timeout=1,
                                  extra_env={"FAKE_INSTALL_TIMEOUT_BEFORE_STATE": "1"})
        self.assertEqual(run.returncode, 1)
        self.assertEqual(report["classification"], "install_timeout")
        self.assertIn("cleanup_unverified", report["reasons"])
        self.assertTrue(report["device_probe"]["cleanup"]["uncertain"])
        self.assertIsNone(report["device_probe"]["launch"])

    def test_stored_apk_change_blocks_execution(self):
        self.apk.write_bytes(b"different")
        run, report = self.invoke(execute=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "skipped_preflight")
        self.assertIn("stored_apk_hash_mismatch", report["reasons"])
        self.assertFalse(self.log.exists())

    def test_prepared_candidate_uses_separate_apk_and_tracks_mutant_hash(self):
        run, report = self.invoke_prepared()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertEqual(report["source_kind"], "prepared_mutant")
        self.assertEqual(report["launch_gate_version"], 3)
        self.assertEqual(report["device_probe"]["resolved_activity"],
                         report["expected_activity"])
        self.assertNotEqual(report["mutant_sha256"], report["tested_apk_sha256"])
        self.assertTrue(report["device_probe"]["cleanup"]["complete"])

    def test_equivalently_signed_baseline_is_separately_identified(self):
        run, report = self.invoke_prepared(baseline_run=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "launched_process_running")
        self.assertEqual(report["source_kind"], "prepared_baseline")
        self.assertEqual(report["tested_apk_sha256"], report["baseline_apk_sha256"])
        self.assertNotEqual(report["mutant_sha256"], report["tested_apk_sha256"])

    def test_changed_prepared_apk_never_reaches_device(self):
        run, report = self.invoke_prepared(changed=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report["classification"], "skipped_preparation")
        self.assertIn("prepared_apk_hash_mismatch", report["reasons"])
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
