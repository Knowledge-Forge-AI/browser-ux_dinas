from __future__ import annotations

import hashlib
import io
import sqlite3
import struct
import zlib
from pathlib import Path


def load_rehash(load_module, monkeypatch, repo_root: Path):
    monkeypatch.syspath_prepend(str(repo_root / "libexec" / "shared-images"))
    return load_module("libexec/shared-images/rehash.py")


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


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE anime_women_images (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            sha256 TEXT,
            sha256_12 TEXT,
            dimensions TEXT,
            relative_path TEXT
        );
        """,
    )
    conn.commit()


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    return conn


def image_file(shared_root: Path, relative_path: str, width: int = 32, height: int = 18) -> Path:
    path = shared_root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png_bytes(width, height))
    return path


def insert_image(conn: sqlite3.Connection, path: Path) -> None:
    conn.execute(
        """
        INSERT INTO anime_women_images
            (id, path, sha256, sha256_12, dimensions, relative_path)
        VALUES (1, ?, 'old-sha', 'old-sha', '1x1', 'old/path.png')
        """,
        (str(path.resolve()),),
    )
    conn.commit()


def test_rehash_paths_updates_hash_dimensions_and_relative_path(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_rehash(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    image = image_file(shared_root, "anime/women/wallpapers/prod/sfw/re_zero/rem.png")
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_image(conn, image)
    out = io.StringIO()
    err = io.StringIO()

    try:
        result = module.rehash_paths(conn, [image], shared_root=shared_root, stdout=out, stderr=err)
        row = conn.execute("SELECT sha256, sha256_12, dimensions, relative_path FROM anime_women_images").fetchone()
    finally:
        conn.close()

    assert result == 0
    assert row["sha256"] == digest
    assert row["sha256_12"] == digest[:12]
    assert row["dimensions"] == "32x18"
    assert row["relative_path"] == "anime/women/wallpapers/prod/sfw/re_zero/rem.png"
    assert f"  sha256: old-sha -> {digest}" in out.getvalue()
    assert "  dimensions: 1x1 -> 32x18" in out.getvalue()
    assert "updated_rows=1" in out.getvalue()
    assert err.getvalue() == ""


def test_rehash_paths_dry_run_reports_without_updating(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_rehash(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    image = image_file(shared_root, "anime/women/wallpapers/prod/sfw/re_zero/rem.png")
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_image(conn, image)
    out = io.StringIO()

    try:
        result = module.rehash_paths(conn, [image], dry_run=True, shared_root=shared_root, stdout=out)
        row = conn.execute("SELECT sha256, dimensions, relative_path FROM anime_women_images").fetchone()
    finally:
        conn.close()

    assert result == 0
    assert row["sha256"] == "old-sha"
    assert row["dimensions"] == "1x1"
    assert row["relative_path"] == "old/path.png"
    assert "updated_rows=0" in out.getvalue()


def test_rehash_paths_reports_missing_file(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_rehash(load_module, monkeypatch, repo_root)
    conn = open_db(tmp_path / "shared-images.sqlite")
    err = io.StringIO()
    missing = tmp_path / "missing.png"

    try:
        result = module.rehash_paths(conn, [missing], stderr=err)
    finally:
        conn.close()

    assert result == 1
    assert f"missing file: {missing.resolve()}" in err.getvalue()


def test_rehash_paths_reports_missing_database_row(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_rehash(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    image = image_file(shared_root, "anime/women/wallpapers/prod/sfw/re_zero/rem.png")
    conn = open_db(tmp_path / "shared-images.sqlite")
    err = io.StringIO()

    try:
        result = module.rehash_paths(conn, [image], stderr=err)
    finally:
        conn.close()

    assert result == 1
    assert f"no anime_women_images row for: {image.resolve()}" in err.getvalue()


def test_main_accepts_explicit_argv_and_closes_connection(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_rehash(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    image = image_file(shared_root, "anime/women/wallpapers/prod/sfw/re_zero/rem.png")
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_image(conn, image)
    conn.close()
    closed = False
    real_connect_db = module.connect_db

    class TrackingConnection:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, *args, **kwargs):
            return self._conn.execute(*args, **kwargs)

        def commit(self):
            return self._conn.commit()

        def rollback(self):
            return self._conn.rollback()

        def close(self):
            nonlocal closed
            closed = True
            self._conn.close()

    def tracking_connect_db(path: Path):
        return TrackingConnection(real_connect_db(path))

    monkeypatch.setattr(module, "connect_db", tracking_connect_db)

    assert module.main(["--db", str(db), "--shared-root", str(shared_root), str(image)]) == 0
    assert closed
