from __future__ import annotations

import contextlib
import hashlib
import io
import os
import sqlite3
from pathlib import Path


def load_db_audit(load_module, monkeypatch, repo_root: Path):
    monkeypatch.syspath_prepend(str(repo_root / "libexec" / "shared-images"))
    return load_module("libexec/shared-images/db_audit.py")


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE anime_women_images (
            id INTEGER PRIMARY KEY,
            path TEXT,
            sha256 TEXT,
            image_type_id INTEGER,
            res_type_id INTEGER,
            artist TEXT
        );

        CREATE TABLE anime_women_images_high_res_substitutes (
            substitute_path TEXT,
            original_lowres_path TEXT,
            low_res_original_deleted INTEGER
        );

        CREATE TABLE anime_women_images_transparency_workflow (
            production_destination TEXT,
            original_path TEXT,
            transparent_path TEXT,
            superseded_path TEXT,
            alternate_path TEXT,
            final_path TEXT,
            original_archive_path TEXT
        );
        """,
    )
    conn.commit()


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    return conn


def image_file(tmp_path: Path, name: str, content: bytes = b"image\n") -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def insert_clean_rows(conn: sqlite3.Connection, tmp_path: Path) -> Path:
    image = image_file(tmp_path, "prod/rem.png")
    substitute = image_file(tmp_path, "substitutes/rem-large.png")
    original_lowres = image_file(tmp_path, "originals/rem-small.png")
    workflow_paths = [
        image_file(tmp_path, f"workflow/{name}.png")
        for name in (
            "production",
            "original",
            "transparent",
            "superseded",
            "alternate",
            "final",
            "archive",
        )
    ]
    conn.execute(
        """
        INSERT INTO anime_women_images
            (id, path, sha256, image_type_id, res_type_id, artist)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (1, str(image), hashlib.sha256(image.read_bytes()).hexdigest(), 1, 1, "artist"),
    )
    conn.execute(
        """
        INSERT INTO anime_women_images_high_res_substitutes
            (substitute_path, original_lowres_path, low_res_original_deleted)
        VALUES (?, ?, 0)
        """,
        (str(substitute), str(original_lowres)),
    )
    conn.execute(
        """
        INSERT INTO anime_women_images_transparency_workflow
            (
                production_destination,
                original_path,
                transparent_path,
                superseded_path,
                alternate_path,
                final_path,
                original_archive_path
            )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(str(path) for path in workflow_paths),
    )
    conn.commit()
    return image


def test_count_missing_reports_blank_and_missing_paths(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    present = image_file(tmp_path, "present.png")

    assert module.count_missing(["", None, str(present), str(tmp_path / "missing.png")]) == (2, 1)


def test_audit_database_reports_clean_database(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_clean_rows(conn, tmp_path)
    out = io.StringIO()
    err = io.StringIO()

    try:
        result = module.audit_database(conn, stdout=out, stderr=err)
    finally:
        conn.close()

    assert result == 0
    assert "foreign_key_check_rows=0" in out.getvalue()
    assert "anime_women_images.path blanks=0 missing=0" in out.getvalue()
    assert "transparency_workflow.path_fields blanks=0 missing=0" in out.getvalue()
    assert err.getvalue() == ""


def test_audit_database_counts_required_field_and_path_failures(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    conn = open_db(tmp_path / "shared-images.sqlite")
    missing = tmp_path / "missing.png"
    conn.execute(
        """
        INSERT INTO anime_women_images
            (id, path, sha256, image_type_id, res_type_id, artist)
        VALUES (1, '', '', NULL, 1, '')
        """,
    )
    conn.execute(
        """
        INSERT INTO anime_women_images
            (id, path, sha256, image_type_id, res_type_id, artist)
        VALUES (2, ?, '', 1, NULL, NULL)
        """,
        (str(missing),),
    )
    conn.execute(
        """
        INSERT INTO anime_women_images_high_res_substitutes
            (substitute_path, original_lowres_path, low_res_original_deleted)
        VALUES ('', ?, 0)
        """,
        (str(tmp_path / "lowres-missing.png"),),
    )
    conn.execute(
        """
        INSERT INTO anime_women_images_high_res_substitutes
            (substitute_path, original_lowres_path, low_res_original_deleted)
        VALUES (?, ?, 1)
        """,
        (str(image_file(tmp_path, "existing-substitute.png")), str(tmp_path / "deleted-lowres.png")),
    )
    workflow_existing = image_file(tmp_path, "workflow/existing.png")
    conn.execute(
        """
        INSERT INTO anime_women_images_transparency_workflow
            (
                production_destination,
                original_path,
                transparent_path,
                superseded_path,
                alternate_path,
                final_path,
                original_archive_path
            )
        VALUES (?, '', ?, ?, ?, ?, ?)
        """,
        (
            str(workflow_existing),
            str(tmp_path / "workflow/missing-transparent.png"),
            str(workflow_existing),
            str(workflow_existing),
            str(workflow_existing),
            str(workflow_existing),
        ),
    )
    conn.commit()
    out = io.StringIO()

    try:
        result = module.audit_database(conn, stdout=out)
    finally:
        conn.close()

    output = out.getvalue()
    assert result == 1
    assert "anime_women_images.path blanks=1 missing=1" in output
    assert "anime_women_images.required_fk_nulls=2" in output
    assert "anime_women_images.blank_artists=2" in output
    assert "high_res_substitutes.substitute_path blanks=1 missing=0" in output
    assert "high_res_substitutes.active_original_lowres_missing=1" in output
    assert "transparency_workflow.path_fields blanks=1 missing=1" in output


def test_audit_database_optionally_reports_hash_mismatches(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    conn = open_db(tmp_path / "shared-images.sqlite")
    image = insert_clean_rows(conn, tmp_path)
    conn.execute("UPDATE anime_women_images SET sha256 = 'wrong' WHERE path = ?", (str(image),))
    conn.commit()
    out = io.StringIO()
    err = io.StringIO()

    try:
        result = module.audit_database(conn, check_hashes=True, stdout=out, stderr=err)
    finally:
        conn.close()

    assert result == 1
    assert "anime_women_images.hash_mismatches=1" in out.getvalue()
    assert f"hash_mismatch id=1 path={image}" in err.getvalue()


def test_audit_database_optionally_reports_broken_artist_symlinks(
    load_module,
    monkeypatch,
    repo_root: Path,
    tmp_path: Path,
):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    conn = open_db(tmp_path / "shared-images.sqlite")
    insert_clean_rows(conn, tmp_path)
    by_artist = (
        tmp_path
        / "home"
        / "Pictures"
        / "shared-images"
        / "anime"
        / "women"
        / "wallpapers"
        / "prod"
        / "sfw"
        / "by-artist"
    )
    by_artist.mkdir(parents=True)
    broken = by_artist / "sfw__re_zero__rem.png"
    os.symlink(str(tmp_path / "missing-target.png"), broken)
    out = io.StringIO()
    err = io.StringIO()

    try:
        result = module.audit_database(
            conn,
            check_symlinks=True,
            home=tmp_path / "home",
            stdout=out,
            stderr=err,
        )
    finally:
        conn.close()

    assert result == 1
    assert "by_artist_broken_symlinks=1" in out.getvalue()
    assert f"broken_symlink {broken} -> {tmp_path / 'missing-target.png'}" in err.getvalue()


def test_main_accepts_explicit_argv(load_module, monkeypatch, repo_root: Path, tmp_path: Path, capsys):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_clean_rows(conn, tmp_path)
    conn.close()

    result = module.main(["--db", str(db)])

    assert result == 0
    assert "foreign_key_check_rows=0" in capsys.readouterr().out


def test_main_closes_database_connection(load_module, monkeypatch, repo_root: Path, tmp_path: Path):
    module = load_db_audit(load_module, monkeypatch, repo_root)
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_clean_rows(conn, tmp_path)
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

    assert module.main(["--db", str(db)]) == 0
    assert closed
