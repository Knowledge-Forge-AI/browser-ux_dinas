from __future__ import annotations

import hashlib
import io
import os
import sqlite3
import struct
import zlib
from pathlib import Path

import pytest


def load_promote_original(load_module, monkeypatch, repo_root: Path, shared_root: Path):
    monkeypatch.syspath_prepend(str(repo_root / "libexec" / "shared-images"))
    import shared_images_lib

    monkeypatch.setattr(shared_images_lib, "ANIME_WOMEN_ROOT", shared_root / "anime" / "women")
    return load_module("libexec/shared-images/promote_original.py")


def png_bytes(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b""))
        + chunk(b"IEND", b"")
    )


def image_file(path: Path, width: int = 32, height: int = 18) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png_bytes(width, height))
    return path


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE anime_women_images (
            id INTEGER PRIMARY KEY,
            image_type_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            dimensions TEXT,
            sha256 TEXT,
            sha256_12 TEXT,
            relative_path TEXT,
            source_note TEXT
        );

        CREATE TABLE anime_women_images_transparency_workflow (
            id INTEGER PRIMARY KEY,
            image_type_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            safety TEXT NOT NULL,
            series TEXT NOT NULL,
            artist TEXT NOT NULL,
            original_path TEXT,
            original_archive_path TEXT,
            transparent_path TEXT NOT NULL,
            transparent_relative_path TEXT,
            final_path TEXT,
            final_relative_path TEXT,
            original_archive_relative_path TEXT,
            production_destination TEXT,
            production_destination_relative_path TEXT,
            accepted_original INTEGER,
            accepted_transparent INTEGER,
            canonical_choice TEXT,
            workflow_status TEXT,
            superseded_path TEXT,
            superseded_relative_path TEXT,
            alternate_path TEXT,
            alternate_relative_path TEXT,
            notes TEXT,
            updated_utc TEXT
        );
        """,
    )
    conn.commit()


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    return conn


def insert_workflow_rows(conn: sqlite3.Connection, original: Path, transparent: Path) -> None:
    conn.execute(
        """
        INSERT INTO anime_women_images
            (
                id,
                image_type_id,
                item_id,
                path,
                dimensions,
                sha256,
                sha256_12,
                relative_path,
                source_note
            )
        VALUES (7, 1, 99, ?, '1x1', 'old-sha', 'old-sha', 'old/path.png', 'seed note')
        """,
        (str(transparent),),
    )
    conn.execute(
        """
        INSERT INTO anime_women_images_transparency_workflow
            (
                id,
                image_type_id,
                item_id,
                safety,
                series,
                artist,
                original_path,
                original_archive_path,
                transparent_path,
                final_path,
                production_destination,
                accepted_original,
                accepted_transparent,
                canonical_choice,
                workflow_status,
                notes
            )
        VALUES (
            3,
            1,
            99,
            'sfw',
            're_zero',
            'atelier',
            ?,
            NULL,
            ?,
            ?,
            ?,
            0,
            1,
            'transparent',
            'ready',
            'workflow note'
        )
        """,
        (str(original), str(transparent), str(transparent), str(transparent)),
    )
    conn.commit()


def test_promoted_filename_removes_original_prefix(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")

    assert module.promoted_filename(Path("original-rem.png")) == "rem.png"
    assert module.promoted_filename(Path("rem.png")) == "rem.png"


def test_parse_args_accepts_cli_options(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")

    args = module.parse_args(
        [
            "--db",
            str(tmp_path / "shared.sqlite"),
            "--shared-root",
            str(tmp_path / "shared-images"),
            "--replace",
            "--dry-run",
            "original-rem.png",
        ],
    )

    assert args.db == tmp_path / "shared.sqlite"
    assert args.shared_root == tmp_path / "shared-images"
    assert args.replace is True
    assert args.dry_run is True
    assert args.originals == [Path("original-rem.png")]


def test_copy_original_to_prod_rejects_different_existing_destination(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    original = image_file(tmp_path / "original.png", 10, 10)
    dest = image_file(tmp_path / "dest.png", 20, 20)

    with pytest.raises(FileExistsError, match="different content"):
        module.copy_original_to_prod(original, dest, replace=False)


def test_copy_original_to_prod_skips_matching_existing_destination(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    original = image_file(tmp_path / "original.png", 10, 10)
    dest = tmp_path / "dest.png"
    dest.write_bytes(original.read_bytes())
    out = io.StringIO()

    module.copy_original_to_prod(original, dest, replace=False, stdout=out)

    assert f"prod already present: {dest}" in out.getvalue()


def test_copy_original_to_prod_replaces_different_existing_destination(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    original = image_file(tmp_path / "original.png", 10, 10)
    dest = image_file(tmp_path / "dest.png", 20, 20)

    module.copy_original_to_prod(original, dest, replace=True)

    assert dest.read_bytes() == original.read_bytes()


def test_move_transparency_handles_missing_and_same_source(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    missing = tmp_path / "missing.png"
    same = image_file(tmp_path / "same.png", 12, 12)

    assert module.move_transparency(missing, tmp_path / "dest.png") == tmp_path / "dest.png"
    assert module.move_transparency(same, same) == same
    assert same.exists()


def test_move_transparency_removes_duplicate_source(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    src = image_file(tmp_path / "src.png", 12, 12)
    dest = tmp_path / "dest.png"
    dest.write_bytes(src.read_bytes())

    assert module.move_transparency(src, dest) == dest
    assert dest.exists()
    assert not src.exists()


def test_move_transparency_reports_duplicate_dry_run_and_rejects_different_destination(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    src = image_file(tmp_path / "src.png", 12, 12)
    duplicate = tmp_path / "duplicate.png"
    duplicate.write_bytes(src.read_bytes())
    out = io.StringIO()

    assert module.move_transparency(src, duplicate, dry_run=True, stdout=out) == duplicate
    assert src.exists()
    assert "remove duplicate transparency source" in out.getvalue()

    different = image_file(tmp_path / "different.png", 13, 13)
    with pytest.raises(FileExistsError, match="different content"):
        module.move_transparency(src, different)


def test_promote_paths_updates_database_files_and_artist_links(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    shared_root = tmp_path / "shared-images"
    module = load_promote_original(load_module, monkeypatch, repo_root, shared_root)
    original = image_file(
        shared_root / "anime/women/wallpapers/originals/sfw/re_zero/original-rem.png",
        64,
        36,
    )
    transparent = image_file(shared_root / "anime/women/wallpapers/prod/sfw/re_zero/rem-transparent.png", 32, 18)
    old_artist_link = (
        shared_root
        / "anime/women/wallpapers/prod/sfw/by-artist/atelier/sfw__re_zero__rem-transparent.png"
    )
    old_artist_link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(transparent), old_artist_link)
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_workflow_rows(conn, original, transparent)
    out = io.StringIO()

    try:
        assert module.promote_paths(conn, [original], shared_root=shared_root, stdout=out) == 0
        image = conn.execute("SELECT * FROM anime_women_images WHERE id = 7").fetchone()
        workflow = conn.execute("SELECT * FROM anime_women_images_transparency_workflow WHERE id = 3").fetchone()
    finally:
        conn.close()

    prod_dest = shared_root / "anime/women/wallpapers/prod/sfw/re_zero/rem.png"
    transparent_dest = shared_root / "anime/women/wallpapers/transparency/sfw/re_zero/rem-transparent.png"
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    artist_link = shared_root / "anime/women/wallpapers/prod/sfw/by-artist/atelier/sfw__re_zero__rem.png"
    original_link = (
        shared_root
        / "anime/women/wallpapers/prod/sfw/by-artist/atelier/originals__sfw__re_zero__original-rem.png"
    )

    assert prod_dest.read_bytes() == original.read_bytes()
    assert transparent_dest.exists()
    assert not transparent.exists()
    assert not old_artist_link.exists()
    assert Path(os.readlink(artist_link)) == prod_dest
    assert Path(os.readlink(original_link)) == original
    assert image["path"] == str(prod_dest)
    assert image["relative_path"] == "anime/women/wallpapers/prod/sfw/re_zero/rem.png"
    assert image["dimensions"] == "64x36"
    assert image["sha256"] == digest
    assert "approved original promoted to production" in image["source_note"]
    assert workflow["accepted_original"] == 1
    assert workflow["accepted_transparent"] == 0
    assert workflow["canonical_choice"] == "original"
    assert workflow["transparent_path"] == str(transparent_dest)
    assert workflow["final_path"] == str(prod_dest)
    assert workflow["original_archive_path"] == str(original)
    assert f"prod={prod_dest}" in out.getvalue()
    assert f"transparency={transparent_dest}" in out.getvalue()


def test_promote_paths_dry_run_rolls_back_database_and_filesystem(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    shared_root = tmp_path / "shared-images"
    module = load_promote_original(load_module, monkeypatch, repo_root, shared_root)
    original = image_file(shared_root / "anime/women/wallpapers/originals/sfw/re_zero/original-rem.png")
    transparent = image_file(shared_root / "anime/women/wallpapers/prod/sfw/re_zero/rem-transparent.png")
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_workflow_rows(conn, original, transparent)
    out = io.StringIO()

    try:
        assert module.promote_paths(conn, [original], dry_run=True, shared_root=shared_root, stdout=out) == 0
        image = conn.execute("SELECT path, sha256 FROM anime_women_images WHERE id = 7").fetchone()
    finally:
        conn.close()

    assert image["path"] == str(transparent)
    assert image["sha256"] == "old-sha"
    assert transparent.exists()
    assert not (shared_root / "anime/women/wallpapers/prod/sfw/re_zero/rem.png").exists()
    assert "copy " in out.getvalue()
    assert "move " in out.getvalue()


def test_promote_paths_handles_missing_transparent_source(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    shared_root = tmp_path / "shared-images"
    module = load_promote_original(load_module, monkeypatch, repo_root, shared_root)
    original = image_file(shared_root / "anime/women/wallpapers/originals/sfw/re_zero/original-rem.png")
    transparent = shared_root / "anime/women/wallpapers/prod/sfw/re_zero/missing-transparent.png"
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_workflow_rows(conn, original, transparent)
    out = io.StringIO()

    try:
        assert module.promote_paths(conn, [original], shared_root=shared_root, stdout=out) == 0
        workflow = conn.execute("SELECT transparent_path, final_path FROM anime_women_images_transparency_workflow").fetchone()
    finally:
        conn.close()

    assert workflow["transparent_path"] == str(
        shared_root / "anime/women/wallpapers/transparency/sfw/re_zero/missing-transparent.png",
    )
    assert workflow["final_path"] == str(shared_root / "anime/women/wallpapers/prod/sfw/re_zero/rem.png")
    assert "transparency=" in out.getvalue()


def test_promote_paths_reports_missing_file(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    conn = open_db(tmp_path / "shared-images.sqlite")
    err = io.StringIO()

    try:
        result = module.promote_paths(conn, [tmp_path / "missing.png"], stderr=err)
    finally:
        conn.close()

    assert result == 1
    assert f"error: {tmp_path / 'missing.png'}" in err.getvalue()


def test_main_accepts_explicit_argv_and_closes_connection(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_promote_original(load_module, monkeypatch, repo_root, tmp_path / "shared-images")
    closed = False
    calls = []

    class TrackingConnection:
        def close(self):
            nonlocal closed
            closed = True

    conn = TrackingConnection()

    def fake_connect_db(path: Path):
        calls.append(("connect", path))
        return conn

    def fake_promote_paths(conn_arg, originals, *, replace, dry_run, shared_root):
        calls.append(("promote", conn_arg, originals, replace, dry_run, shared_root))
        return 0

    monkeypatch.setattr(module, "connect_db", fake_connect_db)
    monkeypatch.setattr(module, "promote_paths", fake_promote_paths)

    assert module.main(
        [
            "--db",
            str(tmp_path / "shared.sqlite"),
            "--shared-root",
            str(tmp_path / "shared-images"),
            "--replace",
            "--dry-run",
            "original-rem.png",
        ],
    ) == 0
    assert calls == [
        ("connect", tmp_path / "shared.sqlite"),
        ("promote", conn, [Path("original-rem.png")], True, True, tmp_path / "shared-images"),
    ]
    assert closed
