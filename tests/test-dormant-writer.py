"""Dispatch-time macOS tests. Never runs activation or writes a real home/sudoers.

Fixed macOS utilities make this intentionally unsuitable for a Nix build sandbox.
Only simulated root/foreign ownership probes alter a disposable helper copy.
"""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRATCH = None
BUNDLE = "ai.knowledge-forge.dinas.brave-youtube"


def bundle(path, identity, **extra):
    (path / "Contents").mkdir(parents=True, exist_ok=True)
    with (path / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump(dict(CFBundleIdentifier=identity, **extra), stream)
    return path


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="writer-", dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.user = subprocess.check_output(["/usr/bin/id", "-un"], text=True).strip()
        self.common = REPO / "modules/user-home-writer-common.sh"
        self.log = self.root / "calls"
        self.app = self.home / "Applications/Brave YouTube.app"
        self.support = self.home / "Library/Application Support"
        self.profile = self.support / "Brave YouTube"
        self.source = bundle(self.root / "source.app", "com.brave.Browser",
                             CFBundleVersion="123", CFBundleShortVersionString="1.2.3",
                             KSProductID="remove", CFBundleURLTypes=[{}])
        self.prepare_source()
        self.prepare_stubs()

    def prepare_source(self):
        contents = self.source / "Contents"
        for name in ("MacOS", "Resources", "Library/LaunchServices",
                     "Frameworks/Brave Browser Framework.framework/Versions/1/Helpers/BraveUpdater.app",
                     "Frameworks/Brave Browser Framework.framework/Versions/1/Frameworks/Sparkle.framework"):
            (contents / name).mkdir(parents=True, exist_ok=True)
        (contents / "MacOS/Brave Browser").write_text("synthetic browser\n")
        (contents / "Library/LaunchServices/com.brave.Browser.UpdaterPrivilegedHelper").touch()

    def prepare_stubs(self):
        self.tool = self.root / "tool"
        self.tool.write_text('''#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$BUX_TEST_LOG"
if [ "$1" = -c ]; then
  test -f "$3/icon_16x16.png"
  printf 'synthetic icns' > "$5"
fi
''')
        self.tool.chmod(0o755)
        self.python_stub = self.root / "python"
        self.python_stub.write_text('''#!/bin/bash
set -eu
printf '%s\\n' "$1" >> "$BUX_TEST_LOG"
case "$1" in
  */generate-icon.py) printf 'icon consumed' > "$2/icon_16x16.png" ;;
  */generate-theme-assets.py)
    for name in theme_frame.png theme_toolbar.png theme_ntp_background.png; do
      printf 'theme consumed' > "$2/$name"
    done ;;
  *) exit 1 ;;
esac
''')
        self.python_stub.chmod(0o755)

    def run_writer(self, target=None, success=True):
        args = ["/bin/bash", str(REPO / "modules/brave-youtube-app-writer.sh"),
                str(self.common), target or self.user, str(self.home), str(self.source),
                str(REPO / "config/brave-youtube/launcher.sh.template"),
                str(REPO / "config/brave-youtube/theme-manifest.json"),
                str(REPO / "libexec/brave-youtube/generate-icon.py"),
                str(REPO / "libexec/brave-youtube/generate-theme-assets.py"),
                str(self.python_stub), str(self.tool), "/usr/libexec/PlistBuddy",
                str(self.tool), str(self.tool), str(self.tool), BUNDLE]
        # Production mktemp has a fixed /private/tmp path. Track the exact directory
        # through the iconutil call; production removes it on every successful run.
        result = subprocess.run(args, text=True, capture_output=True,
                                env={**os.environ, "BUX_TEST_LOG": str(self.log)})
        self.assertEqual(result.returncode == 0, success, result.stderr)
        if self.log.exists():
            for line in self.log.read_text().splitlines():
                if line.startswith("-c icns "):
                    iconset = line.split(" -o ")[0].removeprefix("-c icns ")
                    self.assertFalse(Path(iconset).exists(), "production iconset cleanup")
        return result

    def test_complete_bundle_and_tools(self):
        self.run_writer()
        contents = self.app / "Contents"
        with (contents / "Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        self.assertEqual(info["CFBundleIdentifier"], BUNDLE)
        self.assertEqual(info["CFBundleVersion"], "123")
        self.assertEqual(info["CFBundleShortVersionString"], "1.2.3")
        self.assertEqual(info["CFBundleExecutable"], "Brave YouTube")
        self.assertNotIn("KSProductID", info)
        self.assertNotIn("CFBundleURLTypes", info)
        self.assertEqual(list(contents.rglob("BraveUpdater.app")), [])
        self.assertEqual(list(contents.rglob("Sparkle.framework")), [])
        self.assertFalse((contents / "Library/LaunchServices/com.brave.Browser.UpdaterPrivilegedHelper").exists())
        self.assertEqual((contents / "MacOS/Brave YouTube.bin").read_text(), "synthetic browser\n")
        launcher = (contents / "MacOS/Brave YouTube").read_text()
        self.assertNotIn("@USER_NAME@", launcher)
        self.assertIn(f"/Users/{self.user}/", launcher)
        self.assertEqual((contents / "Resources/app.icns").read_bytes(), b"synthetic icns")
        theme = self.profile / "brave-youtube-theme"
        self.assertEqual((theme / "manifest.json").read_bytes(),
                         (REPO / "config/brave-youtube/theme-manifest.json").read_bytes())
        for name in ("theme_frame.png", "theme_toolbar.png", "theme_ntp_background.png"):
            self.assertEqual((theme / name).read_text(), "theme consumed")
        calls = self.log.read_text()
        for call in ("--force --deep --sign -", "-u ", "-f ", "-r cache"):
            self.assertIn(call, calls)

    def test_wrong_identity_preserved_and_same_identity_replaced(self):
        bundle(self.app, "org.example.unmanaged")
        (self.app / "sentinel").write_text("unmanaged")
        self.run_writer()
        backup = self.app.with_name(self.app.name + ".before-nix-darwin")
        self.assertEqual((backup / "sentinel").read_text(), "unmanaged")
        (self.app / "managed-sentinel").touch()
        self.run_writer()
        self.assertFalse((self.app / "managed-sentinel").exists())
        self.assertEqual(len(list(self.app.parent.glob("Brave YouTube.app.before-*"))), 1)
        # Non-directory/symlink conflict at app_bundle is preserved without mutating symlink target.
        subprocess.run(["/bin/rm", "-rf", str(self.app)], check=True)
        outside = self.root / "outside-app"
        outside.mkdir()
        (outside / "sentinel").write_text("keep-target")
        self.app.symlink_to(outside)
        self.run_writer()
        link_backups = list(self.app.parent.glob("Brave YouTube.app.before-nix-darwin.*"))
        self.assertEqual(len(link_backups), 1)
        self.assertTrue(link_backups[0].is_symlink())
        self.assertEqual((outside / "sentinel").read_text(), "keep-target")
        self.assertTrue((self.app / "Contents/Info.plist").is_file())

    def test_legacy_identity_cleanup_and_preservation(self):
        applications = self.home / "Applications"
        unmanaged_chrome_app = bundle(applications / "YouTube Chrome.app", "org.example.legacy-chrome")
        unmanaged_brave_app = bundle(applications / "YouTube Brave.app", "org.example.legacy-brave")
        chrome = bundle(applications / "Chrome Apps.localized/YouTube.app", "org.example.shortcut",
                        CrAppModeShortcutID="agimnkijcaahngcdmfeangaknmldooml")
        self.run_writer()
        self.assertFalse(chrome.exists())
        # Public-preview migration boundary: historical private app names are not touched by the writer.
        self.assertTrue(unmanaged_chrome_app.exists())
        self.assertTrue(unmanaged_brave_app.exists())
        self.assertEqual(list(applications.glob("YouTube *.app.before-*")), [])
        bundle(chrome, "org.example.other", CrAppModeShortcutID="unmanaged")
        self.run_writer()
        self.assertTrue(chrome.exists())
        subprocess.run(["/bin/rm", "-rf", str(chrome)], check=True)
        outside_shortcut = self.root / "outside-shortcut"
        outside_shortcut.mkdir()
        (outside_shortcut / "sentinel").write_text("shortcut-target")
        chrome.symlink_to(outside_shortcut)
        self.run_writer()
        self.assertTrue(chrome.with_name(chrome.name + ".before-nix-darwin").is_symlink())
        self.assertEqual((outside_shortcut / "sentinel").read_text(), "shortcut-target")

    def test_guarded_profile_rename_and_existing_profile(self):
        old = self.support / "YouTube Brave"
        old.mkdir(parents=True)
        (old / "sentinel").write_text("profile")
        self.run_writer()
        self.assertFalse(old.exists())
        self.assertEqual((self.profile / "sentinel").read_text(), "profile")
        old.mkdir()
        (old / "preserved").touch()
        self.run_writer()
        self.assertTrue((old / "preserved").exists())
        self.assertEqual((self.profile / "sentinel").read_text(), "profile")

    def test_identity_mismatch_production_bytes(self):
        result = self.run_writer(target=self.user + "-not-effective", success=False)
        self.assertIn("effective user does not match target user", result.stderr)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_profile_symlink_refused_without_target_mutation(self):
        self.support.mkdir(parents=True)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_text("preserve")
        (self.support / "YouTube Brave").symlink_to(outside)
        result = self.run_writer(success=False)
        self.assertIn("not an ordinary directory", result.stderr)
        self.assertEqual([p.name for p in outside.iterdir()], ["sentinel"])
        self.assertEqual((outside / "sentinel").read_text(), "preserve")

    def helper_probe(self, home, helper=None):
        return subprocess.run(["/bin/bash", "-c", 'source "$1"; uh_initialize "$2" "$3"',
                               "probe", str(helper or self.common), self.user, str(home)],
                              text=True, capture_output=True)

    def test_helper_path_and_type_guards(self):
        link = self.root / "link"
        link.symlink_to(self.home)
        regular = self.root / "file"
        regular.touch()
        for home in ("relative", "/", str(self.home) + "/../home", link, regular):
            with self.subTest(home=str(home)):
                self.assertNotEqual(self.helper_probe(home).returncode, 0)
        self.assertEqual(self.helper_probe(self.home).returncode, 0)

    def test_simulated_root_and_foreign_owner_guards(self):
        source = self.common.read_text()
        substitutions = (
            ("$(/usr/bin/id -u)", "0", "refusing to mutate user-home state as root"),
            ('''$(/usr/bin/stat -f '%u' "$uh_required_directory")''', "-1", "not owned by the target user"),
        )
        for old, new, message in substitutions:
            self.assertEqual(source.count(old), 1)
            helper = self.root / "simulated-helper.sh"
            helper.write_text(source.replace(old, new))
            result = self.helper_probe(self.home, helper)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
        self.assertEqual(list(self.home.iterdir()), [])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", required=True, type=Path)
    arguments = parser.parse_args()
    SCRATCH = arguments.scratch.resolve(strict=True)
    if os.geteuid() == 0 or os.uname().sysname != "Darwin":
        parser.error("requires an unprivileged macOS user")
    unittest.main(argv=[__file__], verbosity=2)
