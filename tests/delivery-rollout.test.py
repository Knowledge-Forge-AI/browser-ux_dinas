import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "delivery"))
import rollout
import observations

SPEC = importlib.util.spec_from_file_location("build_manifest", ROOT / "delivery/build-manifest.py")
build_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_manifest)


class RolloutTests(unittest.TestCase):
    def test_optional_vivaldi_observation_does_not_block_other_lanes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bindings, build = root / "bindings.json", root / "build.json"
            bindings.write_text(json.dumps({"candidateFiles": {}, "requiredPosture": {},
                "extensionIds": {}, "vivaldiVpn": {"sourceId": "synthetic", "route": "standalone"}}))
            build.write_text(json.dumps({"candidateFiles": {}, "requiredPosture": {}}))
            args = type("Args", (), dict(bindings=bindings, build_manifest=build,
                browser_ux=root, core=root, composition=root, browsers=["chrome", "firefox", "floorp"]))()
            def app(browser):
                return {"signingIdentityMatches": browser != "vivaldi", "signatureVerified": browser != "vivaldi"}
            with mock.patch.object(rollout.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="example-current-mac")), \
                 mock.patch.object(rollout, "app_metadata", side_effect=app), \
                 mock.patch.object(rollout, "validate_build", return_value=([], build)), \
                 mock.patch.object(rollout, "vivaldi_vpn_source", return_value={"sourceCapability": "UNVERIFIED"}):
                result = rollout.check(args)
            self.assertTrue(result["browserReadiness"]["chrome"]["canApplyConfiguration"])
            self.assertTrue(result["browserReadiness"]["floorp"]["canApplyConfiguration"])
            self.assertFalse(result["browserReadiness"]["vivaldi"]["canApplyConfiguration"])
            self.assertEqual(result["selectedBrowsers"], args.browsers)
            self.assertEqual(result["vpnRouteReadback"], "ATTENDED_INSTANCE_CONFIRMATION_PENDING")

    def test_helper_probes_user_and_system_roots_with_reader_precedence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, system = root / "home", root / "system"
            user_root = home / "Library/Application Support/Vivaldi/NativeMessagingHosts"
            system_root = system / "Application Support/Vivaldi/NativeMessagingHosts"
            user_root.mkdir(parents=True)
            system_root.mkdir(parents=True)
            executable = root / "synthetic-helper"
            executable.write_text("synthetic-executable-fixture")
            manifest = {"allowed_origins": ["chrome-extension://synthetic/"], "path": str(executable)}
            (system_root / "com.apple.passwordmanager.json").write_text(json.dumps(manifest))
            result = observations.helper("vivaldi", "synthetic", home=home, system_root=system)
            self.assertEqual(result["status"], "NATIVE_HELPER_AVAILABLE")
            self.assertEqual(result["selectedRegistration"], "system")
            self.assertEqual(result["authenticatedUsability"], "UNVERIFIED")
            (user_root / "com.apple.passwordmanager.json").write_text(json.dumps(manifest | {"allowed_origins": []}))
            result = observations.helper("vivaldi", "synthetic", home=home, system_root=system)
            self.assertEqual(result["status"], "NATIVE_HELPER_UNVERIFIED")
            self.assertEqual(result["selectedRegistration"], "per-user")
            self.assertEqual(len(result["registrations"]), 2)

    def test_vivaldi_source_reference_survives_minification_but_is_not_instance_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary)
            bundle = app / "Contents/Frameworks/Vivaldi Framework.framework/Resources/vivaldi/background-common-bundle.js"
            bundle.parent.mkdir(parents=True)
            bundle.write_text('const renamed="jplgfhpmjnbigmhklmmbgecoobifkmpa";Other:()=>renamed;')
            with mock.patch.dict(observations.APPS, {"vivaldi": (str(app), "synthetic", "synthetic")}):
                result = observations.vivaldi_vpn_source()
                self.assertEqual(result["referencedStoreId"], "jplgfhpmjnbigmhklmmbgecoobifkmpa")
                self.assertEqual(result["installedInstance"], "UNVERIFIED")
                self.assertEqual(result["route"], "UNVERIFIED_REQUIRES_ATTENDED_INSTANCE")
                bundle.write_text("const changedResource = true;")
                self.assertEqual(observations.vivaldi_vpn_source()["sourceCapability"], "UNVERIFIED")

    def test_lane_targets_share_mozilla_once_and_exclude_other_browsers(self):
        targets = [{"target": name} for name in sorted(rollout.TARGETS)]
        selected = rollout.selected_targets(targets, ["chrome", "floorp"])
        names = {row["target"] for row in selected}
        self.assertIn("/Library/Application Support/Mozilla/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json", names)
        self.assertIn("/Library/Managed Preferences/com.google.Chrome.plist", names)
        self.assertFalse(any("Vivaldi" in name or "org.mozilla.firefox.plist" in name for name in names))


    def test_execute_healthy_lane_uses_its_core_script_and_exact_backup(self):
        # Target R3 rollout holds execution before any effect, backup write or prerequisite script run.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            chrome, vivaldi, payload = (root / name for name in
                ("com.google.Chrome.plist", "com.vivaldi.Vivaldi.plist", "payload"))
            for file in (chrome, vivaldi, payload):
                file.write_text("synthetic-policy")
            build = root / "build.json"
            build.write_text(json.dumps({"applyScripts": {"chrome": "/nix/store/synthetic-chrome-script"}}))
            targets = [{"target": str(file), "source": str(payload)} for file in (chrome, vivaldi)]
            args = type("Args", (), dict(build_manifest=build, backup=root / "backup", attended=True,
                mail_calendar_feeds_on=True, browsers=["chrome"], vpn_instance_confirmed=False))()
            # 1. Target R3 mechanical hold: execute raises before check, backup, or apply script run
            with mock.patch.object(rollout, "check", return_value={"browserReadiness": {
                    "chrome": {"canApplyConfiguration": True}, "vivaldi": {"canApplyConfiguration": False}}}) as check, \
                 mock.patch.object(rollout, "validate_build", return_value=(targets, payload)), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0), \
                 mock.patch.object(rollout.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "R3_DEPLOYMENT_HELD_SOURCE_RELEASE_REQUIRED"):
                    rollout.execute(args)
                check.assert_not_called()
                run.assert_not_called()
                self.assertFalse((root / "backup").exists())

            # 2. Existing backup guard: if backup directory already exists, backup creation is refused
            existing_backup = root / "existing_backup"
            existing_backup.mkdir()
            with self.assertRaisesRegex(ValueError, "BACKUP_DESTINATION_UNSAFE"):
                rollout.backup(targets, existing_backup)

            # 3. Legacy execute implementation characterized with the hold mocked out (no release authority)
            def unheld_require(cond, msg):
                if msg == "R3_DEPLOYMENT_HELD_SOURCE_RELEASE_REQUIRED":
                    return
                if not cond:
                    raise ValueError(msg)

            with mock.patch.object(rollout, "require", side_effect=unheld_require), \
                 mock.patch.object(rollout, "check", return_value={"browserReadiness": {
                    "chrome": {"canApplyConfiguration": True}, "vivaldi": {"canApplyConfiguration": False}}}), \
                 mock.patch.object(rollout, "validate_build", return_value=(targets, payload)), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0), \
                 mock.patch.object(rollout.subprocess, "run") as run:
                result = rollout.execute(args)
                self.assertEqual(result["status"], "CONFIGURATION_WRITTEN_EFFECTIVE_READBACK_PENDING")
                self.assertEqual(run.call_args.args[0], ["/nix/store/synthetic-chrome-script"])
                self.assertEqual([row["target"] for row in json.loads((args.backup / "BACKUP.json").read_text())], [str(chrome)])

    def test_check_never_invokes_writer_or_creates_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bindings, build = root / "bindings.json", root / "build.json"
            bindings.write_text(json.dumps({"candidateFiles": {}, "requiredPosture": {}, "extensionIds": {}, "vivaldiVpn": {"sourceId": "synthetic", "route": "standalone"}}))
            build.write_text(json.dumps({"candidateFiles": {}, "requiredPosture": {}}))
            args = type("Args", (), dict(bindings=bindings, build_manifest=build,
                                        browser_ux=root, core=root, composition=root))()
            host = subprocess.CompletedProcess([], 0, stdout="example-current-mac\n")
            with mock.patch.object(rollout.subprocess, "run", return_value=host) as run, \
                 mock.patch.object(rollout, "app_metadata", return_value={"signingIdentityMatches": True, "signatureVerified": True}), \
                 mock.patch.object(rollout, "validate_build", return_value=([], build)), \
                 mock.patch.object(rollout, "vivaldi_vpn_source", return_value={"id": "synthetic"}):
                self.assertEqual(rollout.check(args)["status"], "CHECKED_NOT_ACTIVATED")
                self.assertEqual([call.args[0] for call in run.call_args_list], [
                    ["/usr/sbin/scutil", "--get", "LocalHostName"], ["/usr/bin/sw_vers", "-productVersion"]])

    def test_failure_emits_evidence_and_no_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "failure.json"
            args = [sys.executable, str(ROOT / "delivery/rollout.py"), "check", "--report", str(report)]
            result = subprocess.run(args, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(report.read_text())["status"], "FAILED")

    def test_arbitrary_root_target_and_writer_refused(self):
        with self.assertRaises(ValueError):
            rollout.validate_build({"owner": "core/programs.browserBaseline", "targets": [
                {"target": "/etc/synthetic-invalid", "source": "/nix/store/synthetic"}], "primaryHome": "/Users/browser-probe", "applyScript": "/tmp/fake"})
        with self.assertRaises(ValueError):
            rollout.validate_build({"owner": "unrelated", "targets": [], "primaryHome": "/Users/browser-probe", "applyScript": "/tmp/fake"})

    def test_synthetic_extension_is_presence_not_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            target = home / "Library/Application Support/Vivaldi/Default/Extensions/synthetic/1/manifest.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"version": "1", "permissions": ["storage"]}))
            observation = observations.installed("vivaldi", "synthetic", home=home)[0]
            self.assertEqual(observation["signedIn"], "UNVERIFIED")
            self.assertEqual(observation["behavior"], "UNVERIFIED")



    def test_backup_restores_only_fixture_files_links_and_absence(self):
        # Target R3 rollback remains held before reading host backups or performing restoration.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            file, link, absent, referent = (root / name for name in ("file", "link", "absent", "referent"))
            file.write_text("synthetic-policy-before")
            file.chmod(0o640)
            referent.write_text("synthetic-reference")
            link.symlink_to("referent")
            targets = [{"target": str(path)} for path in (file, link, absent)]
            backup = root / "backup"
            rollout.backup(targets, backup)
            file.write_text("synthetic-policy-after")
            link.unlink()
            link.write_text("synthetic-new-manifest")
            absent.write_text("synthetic-installed")
            args = type("Args", (), {"backup": backup, "attended": True})()

            # 1. Target R3 mechanical hold: rollback raises before any host read or restoration
            with mock.patch.object(rollout, "TARGETS", {str(path) for path in (file, link, absent)}), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0), \
                 mock.patch.object(rollout.os, "chown"):
                with self.assertRaisesRegex(ValueError, "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED"):
                    rollout.rollback(args)
            # Verify no restoration occurred under held R3
            self.assertEqual(file.read_text(), "synthetic-policy-after")
            self.assertEqual(link.read_text(), "synthetic-new-manifest")
            self.assertTrue(absent.exists())

            # 2. Legacy rollback implementation characterized with the hold mocked out (no release authority)
            def unheld_require(cond, msg):
                if msg == "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED":
                    return
                if not cond:
                    raise ValueError(msg)

            with mock.patch.object(rollout, "require", side_effect=unheld_require), \
                 mock.patch.object(rollout, "TARGETS", {str(path) for path in (file, link, absent)}), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0), \
                 mock.patch.object(rollout.os, "chown"):
                result = rollout.rollback(args)
                self.assertEqual(result["status"], "AFFECTED_CONFIGURATION_RESTORED")
                self.assertEqual(result["extensionData"], "NOT_BACKED_UP_POLICY_REMOVAL_MAY_UNINSTALL")
            self.assertEqual(file.read_text(), "synthetic-policy-before")
            self.assertEqual(file.stat().st_mode & 0o777, 0o640)
            self.assertEqual(link.readlink(), Path("referent"))
            self.assertFalse(absent.exists())
            self.assertEqual(referent.read_text(), "synthetic-reference")

    def test_invalid_backup_is_validated_before_any_restore(self):
        # Tampered and unsafe backups are refused before any file restoration.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            file = root / "file"
            file.write_text("synthetic-current")
            backup = root / "backup"
            rollout.backup([{"target": str(file)}], backup)
            (backup / "0").write_text("synthetic-tampered")
            args = type("Args", (), {"backup": backup, "attended": True})()

            # 1. Target R3 hold refuses rollback
            with mock.patch.object(rollout, "TARGETS", {str(file)}), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED"):
                    rollout.rollback(args)
            self.assertEqual(file.read_text(), "synthetic-current")

            # 2. Even under mocked hold release, tampered checksum is refused before any restore
            def unheld_require(cond, msg):
                if msg == "R3_LEGACY_ROLLBACK_HELD_SEPARATE_PRESERVING_AUTHORITY_REQUIRED":
                    return
                if not cond:
                    raise ValueError(msg)

            with mock.patch.object(rollout, "require", side_effect=unheld_require), \
                 mock.patch.object(rollout, "TARGETS", {str(file)}), \
                 mock.patch.object(rollout.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "BACKUP_CHECKSUM_MISMATCH"):
                    rollout.rollback(args)
            self.assertEqual(file.read_text(), "synthetic-current")

            # 3. Existing backup destination refusal guard
            with self.assertRaisesRegex(ValueError, "BACKUP_DESTINATION_UNSAFE"):
                rollout.backup([{"target": str(file)}], backup)

    def test_evaluated_posture_mismatch_refuses_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bindings, evaluation = root / "bindings.json", root / "evaluation.json"
            bindings.write_text(json.dumps({"candidateFiles": {}, "requiredPosture": {"appleProton": True}}))
            evaluation.write_text(json.dumps({"sourceRoots": {}, "requiredPosture": {"appleProton": False}}))
            args = type("Args", (), {"bindings": bindings, "evaluation": evaluation, "output": root / "output"})()
            with mock.patch.object(build_manifest.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    build_manifest.prepare(args)
                run.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_payload_builder_failure_emits_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bindings, evaluation, report = (root / name for name in ("bindings", "evaluation", "report"))
            bindings.write_text("{}")
            evaluation.write_text("{}")
            result = subprocess.run([sys.executable, str(ROOT / "delivery/build-manifest.py"),
                "--bindings", str(bindings), "--evaluation", str(evaluation),
                "--output", str(root / "manifest"), "--report", str(report)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(report.read_text())["status"], "FAILED")
            self.assertFalse((root / "manifest").exists())


if __name__ == "__main__":
    unittest.main()
