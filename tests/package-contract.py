"""Installed package contracts; safe entrypoints only, no browser/network calls."""
import json
import os
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

package, source = map(Path, sys.argv[1:3])
python, gallery_python, bash, rclone = sys.argv[3:]
names = {
    "brave-youtube-cdp", "brave-youtube-session", "clear-new-tab-sync",
    "cnt-wallpaper-gallery", "shared-images-db-audit", "shared-images-promote-original",
    "shared-images-rclone-sync", "shared-images-refresh-artist-links",
    "shared-images-rehash", "shared-images-workflow-layout",
}
assert {p.name for p in (package / "bin").iterdir()} == names
manifest = json.loads((source / "tests/fixtures/command-source-manifest.json").read_text())
assert {str(p.relative_to(package)) for p in package.rglob("*") if p.is_file()} == set(manifest)
assert len(names) == 10 and not any(p.startswith("bin/") and p[4:] not in names for p in manifest)
# BUX5B0C/BUX5B1 library helpers: installed beside their siblings, not commands, importable by Nix Python.
library = package / "libexec/clear-new-tab/durable_state.py"
recovery = package / "libexec/clear-new-tab/guarded_recovery.py"
for path in (library, recovery):
    assert path.is_file() and path.stat().st_mode & 0o111 == 0
    assert not path.read_text().startswith("#!")
probe = ("import importlib.util, sys\n"
         "spec = importlib.util.spec_from_file_location('durable_state', sys.argv[1])\n"
         "module = importlib.util.module_from_spec(spec)\n"
         "spec.loader.exec_module(module)\n"
         "sys.exit(0 if module.MANIFEST_SCHEMA == 'browser-ux-cnt-manifest-v1' and not hasattr(module, 'main') else 3)\n")
subprocess.run([python, "-I", "-B", "-c", probe, str(library)], check=True)
# guarded_recovery resolves its foundation only as the installed sibling file.
probe = ("import importlib.util, sys\n"
         "spec = importlib.util.spec_from_file_location('guarded_recovery', sys.argv[1])\n"
         "module = importlib.util.module_from_spec(spec)\n"
         "spec.loader.exec_module(module)\n"
         "ok = module.ds.__file__ == sys.argv[2] and module.ACCEPTED_RESET_POLICY.entries == ()\n"
         "sys.exit(0 if ok and not hasattr(module, 'main') and 'browser_ux_cnt_durable_state' not in sys.modules else 3)\n")
subprocess.run([python, "-I", "-B", "-c", probe, str(recovery), str(library)], check=True)
# BUX5B1 CONSUMER-ADAPT1 consumer helper: non-executable, not a command, loads both siblings privately.
consumer = package / "libexec/clear-new-tab/brave-youtube-consumer.py"
assert consumer.is_file() and consumer.stat().st_mode & 0o111 == 0
assert not consumer.read_text().startswith("#!")
probe = ("import importlib.util, sys\n"
         "spec = importlib.util.spec_from_file_location('consumer', sys.argv[1])\n"
         "module = importlib.util.module_from_spec(spec)\n"
         "spec.loader.exec_module(module)\n"
         "ok = module.gr.__file__ == sys.argv[2] and module.ds.__file__ == sys.argv[3]\n"
         "sys.exit(0 if ok and 'browser_ux_cnt_guarded_recovery' not in sys.modules else 3)\n")
subprocess.run([python, "-I", "-B", "-c", probe, str(consumer), str(recovery), str(library)], check=True)
shells ={"brave-youtube-session", "clear-new-tab-sync", "shared-images-rclone-sync"}
for name in names:
    path = package / "bin" / name
    text = path.read_text()
    runtime = bash if name in shells else gallery_python if name == "cnt-wallpaper-gallery" else python
    assert text.splitlines()[0] == "#!" + runtime, name
    assert runtime.startswith("/nix/store/") and os.access(path, os.X_OK)
for rel in manifest:
    text = (package / rel).read_text()
    assert "/run/current-system" not in text, rel
    assert "/usr/bin/env python" not in text, rel
    assert "/usr/bin/python3" not in text, rel
    assert "darwin-is-not-a-snowflake" not in text, rel
    assert "/Users/" not in text, rel
    assert "/home/" not in text, rel
session = (package / "bin/brave-youtube-session").read_text()
assert session.count(python + ' "$(script_dir)/../libexec/brave-youtube/') == 3
assert '"$self"' in session  # self-reexecution stays at the installed bin entry
sync = (package / "bin/clear-new-tab-sync").read_text()
assert "exec " + python + ' -I -B "$(clear_new_tab_libexec_dir)/brave-youtube-consumer.py" "$@"' in sync
assert "latest-source-extension-dir" not in sync and not (package / "libexec/clear-new-tab/latest-source-extension-dir.py").exists()
assert '${RCLONE:-' + rclone + '}' in (package / "bin/shared-images-rclone-sync").read_text()
subprocess.run([gallery_python, "-c", "import playwright.sync_api"], check=True)
with tempfile.TemporaryDirectory() as temporary:
    home = Path(temporary)
    env = {"HOME": str(home), "XDG_STATE_HOME": str(home / "state"), "PATH": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"}
    for name in sorted(names):
        args = ["bogus", "9222"] if name == "brave-youtube-cdp" else ["--help"]
        result = subprocess.run([str(package / "bin" / name), *args], env=env, text=True, capture_output=True)
        assert result.returncode == (2 if name == "brave-youtube-cdp" else 0), (name, result.stderr)
    # Existing bounded RCLONE override records arguments only, including mutating
    # verbs. Nothing contacts a real remote or runs the real rclone executable.
    recorder = home / "record"
    recorder.write_text(f"#!{python}\nimport json,sys\nfrom pathlib import Path\nPath({str(home / 'args')!r}).write_text(json.dumps(sys.argv[1:]))\n")
    recorder.chmod(0o700)
    # Execute packaged sibling Python helpers without touching launchd or profiles.
    session_path = str(package / "bin/brave-youtube-session")
    helper_env = env | {"BRAVE_YOUTUBE_SOURCE_ONLY": "1"}
    (home / "state/brave-youtube-session").mkdir(parents=True)
    subprocess.run([bash, "-c", 'source "$1"; write_launch_plist "$(script_path)"',
                    "fixture", session_path], env=helper_env, check=True)
    with (home / "state/brave-youtube-session/local.brave-youtube-session.plist").open("rb") as stream:
        plist = plistlib.load(stream)
    assert plist["ProgramArguments"][0] == session_path
    assert "daemon" in plist["ProgramArguments"]
    # BUX5B1 CONSUMER-ADAPT1: verified durable state is the only authority. A populated legacy
    # Chrome profile and its former override are present but never reported, read or copied.
    profile = home / "Chrome/Default"
    for version in ("1.9.0", "1.10.0"):
        (profile / "Extensions/felphkbfjadmcejnibcmcncimlappdde" / version).mkdir(parents=True)
    legacy = env | {"CLEAR_NEW_TAB_SOURCE_CHROME_PROFILE": str(profile)}
    sync_bin = str(package / "bin/clear-new-tab-sync")
    result = subprocess.run([sync_bin, "status"], env=legacy, check=True, capture_output=True, text=True)
    assert "state_root: REFUSED STATE_ROOT_RELOCATION_UNBOUND" in result.stdout  # this env relocates XDG
    assert "1.10.0" not in result.stdout and "Chrome" not in result.stdout
    default_xdg = legacy | {"XDG_STATE_HOME": str(home / ".local/state")}
    result = subprocess.run([sync_bin, "status"], env=default_xdg, check=True, capture_output=True, text=True)
    assert "authority: browser-ux-durable-state" in result.stdout
    assert "state_root_present: absent" in result.stdout and not (home / ".local").exists()
    brave = home / "brave"
    (brave / "Default").mkdir(parents=True)
    (brave / "Default/Preferences").write_text("{}")
    target_env = default_xdg | {"BRAVE_YOUTUBE_USER_DATA_DIR": str(brave)}

    def tree(path):
        return sorted((str(p), p.read_bytes() if p.is_file() else None) for p in path.rglob("*"))
    before = tree(brave)
    result = subprocess.run([sync_bin, "brave-youtube"], env=target_env, capture_output=True, text=True)
    assert (result.returncode, result.stdout) == (3, "")
    assert result.stderr == "clear-new-tab-sync: refused: MANIFEST_SELECTION_REQUIRED\n"
    # End to end through the installed libraries: capture a fixture state root, then plan and refuse.
    durable = home / "durable"
    durable.mkdir()
    capture = ("import importlib.util, sys\n"
               "spec = importlib.util.spec_from_file_location('gr', sys.argv[1])\n"
               "gr = importlib.util.module_from_spec(spec)\n"
               "spec.loader.exec_module(gr)\n"
               "labels = dict(gr.ds.PROJECTED_LABELS)\n"
               "with open(sys.argv[3], 'rb') as stream:\n"
               "    raw = stream.read()\n"
               "target = gr.bind_target({'labels': labels, 'profile_token': 'a' * 64, 'storage_token': 'b' * 64})\n"
               "export = {'labels': labels, 'part_count': 1, 'parts': [raw]}\n"
               "print(gr.capture_export(sys.argv[2], gr.verify_export(export, target)).manifest_sha256)\n")
    digest = subprocess.run([python, "-I", "-B", "-c", capture, str(recovery), str(durable),
                             str(source / "tests/fixtures/cnt-native/firefox/6.12.1/export.json")],
                            check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([sync_bin, "plan", "--state-root", str(durable), "--manifest", digest],
                            env=target_env, check=True, capture_output=True, text=True)
    plan = json.loads(result.stdout)
    assert (plan["verdict"], plan["refusal"]) == ("REFUSED", "BRAVE_CNT_IMPORT_UNQUALIFIED")
    assert plan["source"]["manifest_sha256"] == digest and plan["native_parts_brave_portable"] is False
    result = subprocess.run([sync_bin, "brave-youtube", "--state-root", str(durable), "--manifest", digest],
                            env=target_env, capture_output=True, text=True)
    assert (result.returncode, result.stdout) == (3, "")
    assert result.stderr == "clear-new-tab-sync: refused: BRAVE_CNT_IMPORT_UNQUALIFIED\n"
    # The dormant session's implicit call passes no selection: a warning, never a target write.
    result = subprocess.run([bash, "-c", 'source "$1"; sync_clear_new_tab', "fixture", session_path],
                            env=helper_env | {"BRAVE_YOUTUBE_USER_DATA_DIR": str(brave)},
                            capture_output=True, text=True)
    assert result.returncode == 0 and "Clear New Tab sync failed" in result.stderr, result.stderr
    assert tree(brave) == before and not (home / ".local").exists()
    env.update(RCLONE=str(recorder), SHARED_IMAGES_LOCAL_DIR=str(home), SHARED_IMAGES_CRYPT_REMOTE="fixture:")
    for verb in ("push", "pull", "dry-run-push", "dry-run-pull", "size"):
        subprocess.run([str(package / "bin/shared-images-rclone-sync"), verb], env=env, check=True)
        args = json.loads((home / "args").read_text())
        if verb == "size":
            assert args == ["size", "fixture:"]
        else:
            assert args[0] == "sync" and "--links" in args and "--exclude" in args
            assert ("--dry-run" in args) == verb.startswith("dry-run-")
            assert args[-2:] == (["fixture:", str(home)] if verb.endswith("pull") else [str(home), "fixture:"])
print("PASS: exact roster/layout, Nix interpreters, Playwright, runtime paths, sibling helpers, ten safe entrypoints, five recorded rclone dispatches, durable_state and guarded_recovery libraries and the durable-state consumer installed non-executable and importable; "
      "sync never consults Chrome and refuses before any Brave target write")
