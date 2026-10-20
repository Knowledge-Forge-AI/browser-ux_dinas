from __future__ import annotations

import sys
import runpy
from pathlib import Path

import pytest


def test_version_key_sorts_numeric_segments(load_module):
    module = load_module("libexec/clear-new-tab/latest-source-extension-dir.py")

    versions = ["1.9.0", "1.10.0", "1.2.20"]

    assert sorted(versions, key=module.version_key) == ["1.2.20", "1.9.0", "1.10.0"]


def test_latest_source_extension_dir_prints_highest_version(load_module, monkeypatch, capsys, tmp_path: Path):
    module = load_module("libexec/clear-new-tab/latest-source-extension-dir.py")
    for version in ("1.9.0", "1.10.0", "1.2.20"):
        (tmp_path / version).mkdir()
    (tmp_path / "README.txt").write_text("not a directory\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["latest-source-extension-dir.py", str(tmp_path)])

    module.main()

    assert capsys.readouterr().out == f"{tmp_path / '1.10.0'}\n"


def test_latest_source_extension_dir_exits_when_no_versions(load_module, monkeypatch, tmp_path: Path):
    module = load_module("libexec/clear-new-tab/latest-source-extension-dir.py")
    monkeypatch.setattr(sys, "argv", ["latest-source-extension-dir.py", str(tmp_path)])

    with pytest.raises(SystemExit) as error:
        module.main()

    assert error.value.code == 1


def test_latest_source_extension_dir_cli_runs_main(repo_root: Path, monkeypatch, capsys, tmp_path: Path):
    for version in ("1.0.0", "1.0.1"):
        (tmp_path / version).mkdir()
    monkeypatch.setattr(sys, "argv", ["latest-source-extension-dir.py", str(tmp_path)])

    runpy.run_path(str(repo_root / "libexec/clear-new-tab/latest-source-extension-dir.py"), run_name="__main__")

    assert capsys.readouterr().out == f"{tmp_path / '1.0.1'}\n"
