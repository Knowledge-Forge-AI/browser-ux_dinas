from __future__ import annotations

import json
import plistlib
import runpy
import sys
from pathlib import Path

import pytest


def test_allocate_debug_port_binds_loopback_ephemeral_port(load_module, monkeypatch, capsys):
    module = load_module("libexec/brave-youtube/allocate-debug-port.py")
    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def bind(self, address):
            calls.append(address)

        def getsockname(self):
            return ("127.0.0.1", 43123)

    monkeypatch.setattr(module.socket, "socket", lambda family, kind: FakeSocket())

    module.main()

    assert calls == [("127.0.0.1", 0)]
    assert capsys.readouterr().out == "43123\n"


def test_allocate_debug_port_cli_runs_main(repo_root: Path, monkeypatch, capsys):
    import socket

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def bind(self, address):
            self.address = address

        def getsockname(self):
            return ("127.0.0.1", 43124)

    monkeypatch.setattr(socket, "socket", lambda family, kind: FakeSocket())

    runpy.run_path(str(repo_root / "libexec/brave-youtube/allocate-debug-port.py"), run_name="__main__")

    assert capsys.readouterr().out == "43124\n"


def test_profile_extension_audit_reports_expected_extension_classes(
    load_module,
    monkeypatch,
    capsys,
    tmp_path: Path,
):
    module = load_module("libexec/brave-youtube/profile-extension-audit.py")
    secure_preferences = tmp_path / "Secure Preferences"
    theme_dir = tmp_path / "brave-youtube-theme"
    clear_new_tab_dir = tmp_path / "clear-new-tab-extension"
    extra_extension_dir = tmp_path / "extra-extension"
    policy_extension_dir = tmp_path / "policy-extension"
    for path in (theme_dir, clear_new_tab_dir, extra_extension_dir, policy_extension_dir):
        path.mkdir()

    main_extension_id = sorted(module.MAIN_CHROME_IDS)[0]
    extra_extension_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    clear_new_tab_extension_id = "felphkbfjadmcejnibcmcncimlappdde"
    data = {
        "extensions": {
            "settings": {
                "theme-extension": {"path": str(theme_dir), "location": "4"},
                clear_new_tab_extension_id: {"path": str(clear_new_tab_dir), "location": "4"},
                main_extension_id: {"path": str(tmp_path / "main-extension"), "location": "1"},
                extra_extension_id: {"path": str(extra_extension_dir), "location": "1"},
                "policy-extension": {"path": str(policy_extension_dir), "location": "5"},
            }
        }
    }
    secure_preferences.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "profile-extension-audit.py",
            str(secure_preferences),
            str(theme_dir),
            str(clear_new_tab_dir),
            clear_new_tab_extension_id,
        ],
    )

    module.main()

    assert capsys.readouterr().out == (
        f"theme=present clear_new_tab=present main_chrome_ids={main_extension_id} "
        f"non_theme_extensions={extra_extension_id}\n"
    )


def test_profile_extension_audit_handles_missing_and_invalid_secure_preferences(load_module, capsys, tmp_path: Path):
    module = load_module("libexec/brave-youtube/profile-extension-audit.py")

    with pytest.raises(SystemExit) as missing_error:
        module.load_secure_preferences(tmp_path / "missing.json")
    assert missing_error.value.code == 0
    assert capsys.readouterr().out == "profile_not_created\n"

    invalid_preferences = tmp_path / "Secure Preferences"
    invalid_preferences.write_text("{not json", encoding="utf-8")

    with pytest.raises(SystemExit) as invalid_error:
        module.load_secure_preferences(invalid_preferences)
    assert invalid_error.value.code == 0
    assert capsys.readouterr().out == "unknown reason=JSONDecodeError\n"


def test_profile_extension_audit_cli_runs_main(repo_root: Path, monkeypatch, capsys, tmp_path: Path):
    secure_preferences = tmp_path / "Secure Preferences"
    theme_dir = tmp_path / "brave-youtube-theme"
    clear_new_tab_dir = tmp_path / "clear-new-tab-extension"
    theme_dir.mkdir()
    clear_new_tab_dir.mkdir()
    secure_preferences.write_text(json.dumps({"extensions": {"settings": {}}}), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "profile-extension-audit.py",
            str(secure_preferences),
            str(theme_dir),
            str(clear_new_tab_dir),
            "felphkbfjadmcejnibcmcncimlappdde",
        ],
    )

    runpy.run_path(str(repo_root / "libexec/brave-youtube/profile-extension-audit.py"), run_name="__main__")

    assert capsys.readouterr().out == "theme=missing clear_new_tab=missing main_chrome_ids=none non_theme_extensions=none\n"


def test_write_launch_plist_main_writes_daemon_plist(load_module, monkeypatch, tmp_path: Path):
    module = load_module("libexec/brave-youtube/write-launch-plist.py")
    output_file = tmp_path / "local.test.brave-youtube.plist"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write-launch-plist.py",
            str(output_file),
            "local.test.brave-youtube",
            "/tmp/brave-youtube-session",
            "/tmp/brave-youtube-session.log",
        ],
    )

    module.main()

    with output_file.open("rb") as handle:
        plist = plistlib.load(handle)
    assert plist == {
        "Label": "local.test.brave-youtube",
        "ProgramArguments": ["/tmp/brave-youtube-session", "daemon"],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": "/tmp/brave-youtube-session.log",
        "StandardErrorPath": "/tmp/brave-youtube-session.log",
    }


def test_write_launch_plist_main_rejects_wrong_arity(load_module, monkeypatch):
    module = load_module("libexec/brave-youtube/write-launch-plist.py")
    monkeypatch.setattr(sys, "argv", ["write-launch-plist.py"])

    with pytest.raises(SystemExit) as error:
        module.main()

    assert str(error.value) == "usage: write-launch-plist.py OUTPUT LABEL PROGRAM LOG_FILE"


def test_write_launch_plist_cli_runs_main(repo_root: Path, monkeypatch, tmp_path: Path):
    output_file = tmp_path / "local.test.brave-youtube.plist"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write-launch-plist.py",
            str(output_file),
            "local.test.brave-youtube",
            "/tmp/brave-youtube-session",
            "/tmp/brave-youtube-session.log",
        ],
    )

    runpy.run_path(str(repo_root / "libexec/brave-youtube/write-launch-plist.py"), run_name="__main__")

    with output_file.open("rb") as handle:
        assert plistlib.load(handle)["ProgramArguments"] == ["/tmp/brave-youtube-session", "daemon"]
