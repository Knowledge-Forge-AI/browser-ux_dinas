from __future__ import annotations


import json


import os


import runpy


import subprocess


import sys


from pathlib import Path


import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_entrypoint(repo_root: Path, relative_path: str, monkeypatch, argv: list[str] | None = None):
    script_path = repo_root / relative_path
    monkeypatch.setattr(sys, "argv", [str(script_path), *(argv or [])])
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as error:
        return error.code
    return 0


def test_brave_youtube_cdp_rejects_unknown_command(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/brave-youtube-cdp", monkeypatch, ["bogus", "9222"]) == 2
    assert "Usage: brave-youtube-cdp" in capsys.readouterr().err


def test_cnt_wallpaper_gallery_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/cnt-wallpaper-gallery", monkeypatch, ["--help"]) == 0
    assert "Clear Clear New Tab DBs or load shared image import files" in capsys.readouterr().out


def test_shared_images_db_audit_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/shared-images-db-audit", monkeypatch, ["--help"]) == 0
    assert "shared-images" in capsys.readouterr().out


def test_shared_images_promote_original_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/shared-images-promote-original", monkeypatch, ["--help"]) == 0
    assert "original" in capsys.readouterr().out.casefold()


def test_shared_images_refresh_artist_links_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/shared-images-refresh-artist-links", monkeypatch, ["--help"]) == 0
    assert "artist" in capsys.readouterr().out.casefold()


def test_shared_images_rehash_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/shared-images-rehash", monkeypatch, ["--help"]) == 0
    assert "sha256" in capsys.readouterr().out


def test_shared_images_workflow_layout_help_is_available(repo_root: Path, monkeypatch, capsys):
    assert run_entrypoint(repo_root, "bin/shared-images-workflow-layout", monkeypatch, ["--help"]) == 0
    assert "workflow" in capsys.readouterr().out.casefold()
