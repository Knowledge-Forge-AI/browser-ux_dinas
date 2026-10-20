from __future__ import annotations

import io
import os
import sqlite3
from pathlib import Path


def load_artist_links(load_module, monkeypatch, repo_root: Path, shared_root: Path):
    monkeypatch.syspath_prepend(str(repo_root / "libexec" / "shared-images"))
    import shared_images_lib

    monkeypatch.setattr(shared_images_lib, "ANIME_WOMEN_ROOT", shared_root / "anime" / "women")
    return load_module("libexec/shared-images/artist_links.py")


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE image_types (
            id INTEGER PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE anime_women_images (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            image_type_id INTEGER NOT NULL,
            safety TEXT NOT NULL,
            artist TEXT NOT NULL,
            series TEXT NOT NULL
        );

        INSERT INTO image_types (id, value)
        VALUES (1, 'wallpaper'), (2, 'portrait');
        """,
    )
    conn.commit()


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    return conn


def image_file(tmp_path: Path, name: str) -> Path:
    path = tmp_path / "images" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("image\n", encoding="utf-8")
    return path


def insert_image(
    conn: sqlite3.Connection,
    image_id: int,
    path: Path,
    *,
    image_type_id: int = 1,
    safety: str = "sfw",
    artist: str = "artist",
    series: str = "re_zero",
) -> None:
    conn.execute(
        """
        INSERT INTO anime_women_images
            (id, path, image_type_id, safety, artist, series)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (image_id, str(path), image_type_id, safety, artist, series),
    )
    conn.commit()


def test_refresh_artist_links_filters_rows_and_skips_missing_files(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_artist_links(load_module, monkeypatch, repo_root, tmp_path / "shared")
    conn = open_db(tmp_path / "shared-images.sqlite")
    keep = image_file(tmp_path, "rem.png")
    missing = tmp_path / "images" / "missing.png"
    insert_image(conn, 1, keep)
    insert_image(conn, 2, missing)
    insert_image(conn, 3, image_file(tmp_path, "nsfw.png"), safety="nsfw")
    insert_image(conn, 4, image_file(tmp_path, "portrait.png"), image_type_id=2)
    out = io.StringIO()

    try:
        linked, pruned = module.refresh_artist_links(
            conn,
            image_type="wallpaper",
            safety="sfw",
            artist="artist",
            stdout=out,
        )
    finally:
        conn.close()

    link = (
        tmp_path
        / "shared"
        / "anime"
        / "women"
        / "wallpapers"
        / "prod"
        / "sfw"
        / "by-artist"
        / "artist"
        / "sfw__re_zero__rem.png"
    )
    assert (linked, pruned) == (1, 0)
    assert link.is_symlink()
    assert Path(os.readlink(link)) == keep
    assert f"skip missing canonical file: {missing}" in out.getvalue()
    assert "linked=1 pruned_broken=0" in out.getvalue()


def test_refresh_artist_links_dry_run_reports_without_writing(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_artist_links(load_module, monkeypatch, repo_root, tmp_path / "shared")
    conn = open_db(tmp_path / "shared-images.sqlite")
    keep = image_file(tmp_path, "rem.png")
    insert_image(conn, 1, keep)
    out = io.StringIO()

    try:
        linked, pruned = module.refresh_artist_links(conn, dry_run=True, stdout=out)
    finally:
        conn.close()

    assert (linked, pruned) == (1, 0)
    assert not (tmp_path / "shared").exists()
    assert "link " in out.getvalue()
    assert "linked=1 pruned_broken=0" in out.getvalue()


def test_refresh_artist_links_prunes_broken_links(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_artist_links(load_module, monkeypatch, repo_root, tmp_path / "shared")
    conn = open_db(tmp_path / "shared-images.sqlite")
    keep = image_file(tmp_path, "rem.png")
    insert_image(conn, 1, keep)
    root = (
        tmp_path
        / "shared"
        / "anime"
        / "women"
        / "wallpapers"
        / "prod"
        / "sfw"
        / "by-artist"
        / "artist"
    )
    root.mkdir(parents=True)
    broken = root / "broken.png"
    healthy = root / "healthy.png"
    os.symlink(str(tmp_path / "missing-target.png"), broken)
    os.symlink(str(keep), healthy)
    out = io.StringIO()

    try:
        linked, pruned = module.refresh_artist_links(conn, prune_broken=True, stdout=out)
    finally:
        conn.close()

    assert (linked, pruned) == (1, 1)
    assert not broken.exists()
    assert healthy.is_symlink()
    assert "linked=1 pruned_broken=1" in out.getvalue()


def test_refresh_artist_links_prune_dry_run_does_not_unlink(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_artist_links(load_module, monkeypatch, repo_root, tmp_path / "shared")
    conn = open_db(tmp_path / "shared-images.sqlite")
    keep = image_file(tmp_path, "rem.png")
    insert_image(conn, 1, keep)
    root = (
        tmp_path
        / "shared"
        / "anime"
        / "women"
        / "wallpapers"
        / "prod"
        / "sfw"
        / "by-artist"
        / "artist"
    )
    root.mkdir(parents=True)
    broken = root / "broken.png"
    os.symlink(str(tmp_path / "missing-target.png"), broken)
    out = io.StringIO()

    try:
        linked, pruned = module.refresh_artist_links(
            conn,
            prune_broken=True,
            dry_run=True,
            stdout=out,
        )
    finally:
        conn.close()

    assert (linked, pruned) == (1, 1)
    assert broken.is_symlink()
    assert f"unlink broken {broken} -> {tmp_path / 'missing-target.png'}" in out.getvalue()
    assert "linked=1 pruned_broken=1" in out.getvalue()


def test_main_accepts_filters_and_closes_connection(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_artist_links(load_module, monkeypatch, repo_root, tmp_path / "shared")
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_image(conn, 1, image_file(tmp_path, "rem.png"))
    conn.close()
    closed = False
    real_connect_db = module.connect_db

    class TrackingConnection:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, *args, **kwargs):
            return self._conn.execute(*args, **kwargs)

        def close(self):
            nonlocal closed
            closed = True
            self._conn.close()

    def tracking_connect_db(path: Path):
        return TrackingConnection(real_connect_db(path))

    monkeypatch.setattr(module, "connect_db", tracking_connect_db)

    assert module.main(["--db", str(db), "--image-type", "wallpaper", "--safety", "sfw"]) == 0
    assert closed
