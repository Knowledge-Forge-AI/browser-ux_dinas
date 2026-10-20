"""CNT format characterization and runtime selection without browser execution."""
import argparse
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path

import pytest


@pytest.fixture
def gallery(load_module):
    return load_module("bin/cnt-wallpaper-gallery")


def test_chrome_precedence_and_fail_closed(gallery, tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ("cli", "environment", "packaged")]
    for path in paths:
        path.write_text("fixture only")
        path.chmod(0o700)
    args = argparse.Namespace(chrome_executable=str(paths[0]))
    monkeypatch.setenv("CNT_CHROME_EXECUTABLE", str(paths[1]))
    monkeypatch.setattr(gallery, "PACKAGED_CHROME_EXECUTABLE", str(paths[2]))
    assert gallery.chrome_executable(args) == paths[0]
    args.chrome_executable = str(tmp_path / "missing")
    with pytest.raises(SystemExit, match="not executable"):
        gallery.chrome_executable(args)
    args.chrome_executable = None
    assert gallery.chrome_executable(args) == paths[1]
    monkeypatch.delenv("CNT_CHROME_EXECUTABLE")
    assert gallery.chrome_executable(args) == paths[2]
    monkeypatch.setattr(gallery, "PACKAGED_CHROME_EXECUTABLE", "")
    with pytest.raises(SystemExit, match="matching selected core"):
        gallery.chrome_executable(args)


def test_python_subprocess_uses_current_interpreter(gallery):
    assert gallery.playwright_python() == Path(gallery.sys.executable)


def wallpaper(gallery, path, digest=None):
    # Keep constructor bound to the observed data model.
    return gallery.Wallpaper(path=path, rating="sfw", series="fixture", artist="unknown",
                             image_type="wallpaper", hi_res=True, digest=digest or "")


def test_content_identity_order_and_mapping(gallery, tmp_path, monkeypatch):
    first = tmp_path / "first.png"
    first.write_bytes(b"fixture image")
    second = tmp_path / "renamed.png"
    second.write_bytes(first.read_bytes())
    monkeypatch.setattr(gallery, "image_dimensions", lambda p: (1920, 1080))
    monkeypatch.setattr(gallery, "thumbnail_data_url", lambda p: ("", None, None))
    images = gallery.dedupe_images([wallpaper(gallery, first), wallpaper(gallery, second)])
    assert len(images) == 1
    chunk = gallery.make_chunk(images[0], 3)
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert chunk["data"]["id"] == uuid.uuid5(uuid.NAMESPACE_URL, f"cnt-wallpaper-gallery:{digest}").hex
    assert chunk["data"]["i"] == "3"
    assert set(chunk) == {"data", "thumbnail", "file", "tasks"}
    assert chunk["file"]["name"] == "first.png"
    assert "source" not in chunk and "path" not in chunk["file"]
    moved = gallery.make_chunk(wallpaper(gallery, second, digest), 3)
    assert moved["data"]["id"] == chunk["data"]["id"]
    second.write_bytes(b"edited original")
    edited = gallery.dedupe_images([wallpaper(gallery, second)])[0]
    assert gallery.make_chunk(edited, 3)["data"]["id"] != chunk["data"]["id"]


def test_rank_gaps_and_multipart_preferences(gallery, tmp_path, monkeypatch):
    images = [wallpaper(gallery, tmp_path / name) for name in ("one.png", "skip.txt", "three.png")]
    def chunk(item, index):
        if item.path.suffix == ".txt":
            return None
        return {"data": {"i": str(index)}, "file": {"background": "x" * 600000}}
    monkeypatch.setattr(gallery, "make_chunk", chunk)
    files = gallery.write_backup_files(images, tmp_path / "backups", 1, False)
    parts = [json.loads(p.read_text()) for p in files]
    assert len(parts) == 2
    assert [p["chunks"][0]["data"]["i"] for p in parts] == ["1", "3"]
    assert parts[0]["settings"]["prefs"] == {"mode": "multiple_backgrounds", "id_of_last_installed_theme": ""}
    assert parts[0]["custom_code"] == {"html": "", "css": "", "js": ""}
    assert "settings" not in parts[1] and "custom_code" not in parts[1]


def test_membership_sql_order_and_source_resolution(gallery, tmp_path):
    database = tmp_path / "images.sqlite"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
          CREATE TABLE image_types (id INTEGER, value TEXT);
          CREATE TABLE res_type (id INTEGER, value TEXT);
          CREATE TABLE anime_women_images (path TEXT, relative_path TEXT, safety TEXT,
            series TEXT, artist TEXT, title TEXT, image_type_id INTEGER, res_type_id INTEGER);
          INSERT INTO image_types VALUES (1, 'wallpaper'), (2, 'portrait');
          INSERT INTO res_type VALUES (1, 'high_res'), (2, 'low_res');
        """)
        rows = [
            ("z.png", "Z", 1, 1), ("a.png", "A", 1, 1),
            ("portrait.png", "B", 2, 1), ("low.png", "C", 1, 2),
            ("missing.png", "D", 1, 1), ("unsupported.txt", "E", 1, 1),
        ]
        for filename, title, image_type, resolution in rows:
            if filename != "missing.png":
                (tmp_path / filename).write_bytes(b"fixture")
            connection.execute("INSERT INTO anime_women_images VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                               ("/nonexistent/old/" + filename, filename, "sfw", "Series", "Artist", title, image_type, resolution))
    images = gallery.discover_images(database, "sfw", {"wallpaper"}, {"series"}, {"artist"}, True)
    assert [item.path.name for item in images] == ["a.png", "z.png"]
    assert all(item.path.parent == tmp_path for item in images)


def test_source_parity_manifest(repo_root):
    manifest = json.loads((repo_root / "tests/fixtures/command-source-manifest.json").read_text())
    assert len(manifest) == 29
    assert len([rel for rel in manifest if rel.startswith("bin/")]) == 10
    # BUX5B0C/BUX5B1: destination-origin library and consumer helpers with no core source; still ten commands.
    origin = {rel: item for rel, item in manifest.items() if item["adaptation"] == "destination-origin"}
    assert list(origin) == ["libexec/clear-new-tab/brave-youtube-consumer.py", "libexec/clear-new-tab/durable_state.py",
                            "libexec/clear-new-tab/guarded_recovery.py"]
    # The retired Chrome extension-version selector is no longer packaged.
    assert "libexec/clear-new-tab/latest-source-extension-dir.py" not in manifest
    adapted = {rel: item["adaptation"] for rel, item in manifest.items()
               if item["adaptation"] not in ("byte-identical", "destination-origin")}
    assert adapted == {"bin/clear-new-tab-sync": "durable-authority-consumer",
                       "bin/cnt-wallpaper-gallery": "tracked-runtime-selection"}
    assert all(item["source_sha256"] is None and item["mode"] == "0o644" for item in origin.values())
    assert all(item["source_sha256"] is not None for rel, item in manifest.items() if rel not in origin)
    for rel, item in manifest.items():
        path = repo_root / rel
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["destination_sha256"], rel
        # Store normalization strips write bits; dispatch parity checks exact modes.
        assert path.stat().st_mode & 0o111 == int(item["mode"], 8) & 0o111, rel


def test_local_skills_and_sanitized_sources(repo_root):
    for name in ("browser-hardening-policy", "shared-images-workflow"):
        for client in (".agents", ".claude"):
            link = repo_root / client / "skills" / name
            assert link.is_symlink() and link.resolve().is_relative_to(repo_root)
            assert (link / "agents/openai.yaml").is_file()
            for path in link.rglob("*"):
                if path.is_file():
                    assert "/Users/" not in path.read_text()
