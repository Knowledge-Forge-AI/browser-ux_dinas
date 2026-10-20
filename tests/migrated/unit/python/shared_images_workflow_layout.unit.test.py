from __future__ import annotations

import sqlite3
from io import StringIO
from pathlib import Path


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE anime_women_images (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            relative_path TEXT NOT NULL
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE anime_women_images_high_res_substitutes (
            id INTEGER PRIMARY KEY,
            original_lowres_path TEXT NOT NULL,
            original_lowres_relative_path TEXT NOT NULL,
            substitute_path TEXT NOT NULL,
            substitute_relative_path TEXT NOT NULL
        )
        """,
    )
    conn.execute(
        """
        CREATE TABLE anime_women_images_transparency_workflow (
            id INTEGER PRIMARY KEY,
            production_destination TEXT NOT NULL,
            production_destination_relative_path TEXT NOT NULL,
            original_path TEXT NOT NULL,
            original_relative_path TEXT NOT NULL,
            transparent_path TEXT NOT NULL,
            transparent_relative_path TEXT NOT NULL,
            superseded_path TEXT NOT NULL,
            superseded_relative_path TEXT NOT NULL,
            alternate_path TEXT NOT NULL,
            alternate_relative_path TEXT NOT NULL,
            final_path TEXT NOT NULL,
            final_relative_path TEXT NOT NULL,
            original_archive_path TEXT NOT NULL,
            original_archive_relative_path TEXT NOT NULL
        )
        """,
    )
    return conn


def insert_legacy_paths(conn: sqlite3.Connection, shared_root: Path) -> None:
    legacy_low_res = shared_root / "anime/women/wallpapers/inbox/low-res/sfw/Re Zero/rem.png"
    legacy_transparency = shared_root / "anime/women/portraits/inbox/transparency/sfw/Re Zero/rem/original.png"
    conn.execute(
        "INSERT INTO anime_women_images VALUES (1, ?, ?)",
        (
            str(legacy_low_res),
            "anime/women/wallpapers/inbox/low-res/sfw/Re Zero/rem.png",
        ),
    )
    conn.execute(
        "INSERT INTO anime_women_images_high_res_substitutes VALUES (1, ?, ?, ?, ?)",
        (
            str(legacy_low_res),
            "anime/women/wallpapers/inbox/low-res/sfw/Re Zero/rem.png",
            str(shared_root / "anime/women/wallpapers/prod/sfw/Re Zero/rem-hires.png"),
            "anime/women/wallpapers/prod/sfw/Re Zero/rem-hires.png",
        ),
    )
    conn.execute(
        "INSERT INTO anime_women_images_transparency_workflow VALUES (1, ?, ?, ?, ?, '', '', '', '', '', '', '', '', '', '')",
        (
            str(shared_root / "anime/women/portraits/prod/sfw/Re Zero/rem.png"),
            "anime/women/portraits/prod/sfw/Re Zero/rem.png",
            str(legacy_transparency),
            "anime/women/portraits/inbox/transparency/sfw/Re Zero/rem/original.png",
        ),
    )
    conn.commit()


def load_workflow_layout(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / "libexec" / "shared-images"))
    return load_module("libexec/shared-images/workflow_layout.py")


def test_check_reports_legacy_layout_and_db_references(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    (shared_root / "anime/women/wallpapers/inbox/low-res/sfw/Re Zero").mkdir(parents=True)
    (shared_root / "anime/women/portraits/inbox/transparency/sfw/Re Zero").mkdir(parents=True)
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_legacy_paths(conn, shared_root)
    out = StringIO()

    assert module.check_layout(shared_root, conn, out) == 1

    output = out.getvalue()
    assert "missing unified inbox" in output
    assert "legacy type-specific inbox still exists" in output
    assert "anime_women_images.path" in output
    conn.close()


def test_migrate_dry_run_reports_without_mutating(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    legacy = shared_root / "anime/women/wallpapers/inbox"
    legacy.mkdir(parents=True)
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_legacy_paths(conn, shared_root)
    out = StringIO()

    assert module.migrate_layout(shared_root, conn, dry_run=True, out=out) == 0

    assert legacy.is_dir()
    assert not (shared_root / "anime/women/inbox").exists()
    assert "dry-run complete" in out.getvalue()
    row = conn.execute("SELECT relative_path FROM anime_women_images").fetchone()
    assert "/inbox/" in row["relative_path"]
    conn.close()


def test_migrate_renames_workflow_dirs_and_updates_db_paths(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    wallpaper_legacy = shared_root / "anime/women/wallpapers/inbox"
    portrait_legacy = shared_root / "anime/women/portraits/inbox"
    (wallpaper_legacy / "low-res/sfw/Re Zero").mkdir(parents=True)
    (portrait_legacy / "transparency/sfw/Re Zero").mkdir(parents=True)
    (wallpaper_legacy / "low-res/sfw/Re Zero/rem.png").write_text("image\n", encoding="utf-8")
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    insert_legacy_paths(conn, shared_root)
    out = StringIO()

    assert module.migrate_layout(shared_root, conn, dry_run=False, out=out) == 0

    assert (shared_root / "anime/women/inbox").is_dir()
    assert not wallpaper_legacy.exists()
    assert not portrait_legacy.exists()
    assert (shared_root / "anime/women/wallpapers/workflow/low-res/sfw/Re Zero/rem.png").is_file()
    assert (shared_root / "anime/women/portraits/workflow/processed-notes").is_dir()
    row = conn.execute("SELECT path, relative_path FROM anime_women_images").fetchone()
    assert "/wallpapers/workflow/low-res/" in row["path"]
    assert row["relative_path"].startswith("anime/women/wallpapers/workflow/low-res/")
    workflow = conn.execute("SELECT original_path, original_relative_path FROM anime_women_images_transparency_workflow").fetchone()
    assert "/portraits/workflow/transparency/" in workflow["original_path"]
    assert workflow["original_relative_path"].startswith("anime/women/portraits/workflow/transparency/")
    assert module.check_layout(shared_root, conn, StringIO()) == 0
    conn.close()


def test_migrate_merges_legacy_inbox_into_existing_workflow(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    legacy = shared_root / "anime/women/wallpapers/inbox"
    workflow = shared_root / "anime/women/wallpapers/workflow"
    legacy.mkdir(parents=True)
    workflow.mkdir(parents=True)
    (legacy / "incoming").write_text("image\n", encoding="utf-8")
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    out = StringIO()

    assert module.migrate_layout(shared_root, conn, dry_run=False, out=out) == 0

    assert not legacy.exists()
    assert (workflow / "incoming").read_text(encoding="utf-8") == "image\n"
    assert "move" in out.getvalue()
    assert "rmdir" in out.getvalue()
    conn.close()


def test_migrate_rejects_merge_conflicts(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    legacy = shared_root / "anime/women/wallpapers/inbox"
    workflow = shared_root / "anime/women/wallpapers/workflow"
    legacy.mkdir(parents=True)
    workflow.mkdir(parents=True)
    (legacy / "codex-rejects").mkdir()
    (workflow / "codex-rejects").mkdir()
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    out = StringIO()

    assert module.migrate_layout(shared_root, conn, dry_run=False, out=out) == 1

    assert legacy.is_dir()
    assert "workflow migration conflict" in out.getvalue()
    conn.close()


def test_db_updates_tolerates_missing_tables_and_columns(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE anime_women_images (id INTEGER PRIMARY KEY, path TEXT NOT NULL)")
    conn.execute(
        "INSERT INTO anime_women_images VALUES (1, ?)",
        (str(shared_root / "anime/women/wallpapers/inbox/low-res/sfw/Re Zero/rem.png"),),
    )

    updates = module.db_updates(conn, shared_root)

    assert len(updates) == 1
    assert updates[0].column == "path"
    conn.close()


def test_main_dispatches_check_and_migrate_commands(load_module, monkeypatch, repo_root, tmp_path: Path):
    module = load_workflow_layout(load_module, monkeypatch, repo_root)
    shared_root = tmp_path / "shared-images"
    (shared_root / "anime/women/inbox").mkdir(parents=True)
    (shared_root / "anime/women/wallpapers/workflow").mkdir(parents=True)
    (shared_root / "anime/women/portraits/workflow").mkdir(parents=True)
    db = tmp_path / "shared-images.sqlite"
    conn = open_db(db)
    conn.close()
    check_out = StringIO()
    migrate_out = StringIO()

    assert module.main(["check", "--shared-root", str(shared_root), "--db", str(db)], stdout=check_out) == 0
    assert module.main(["migrate", "--dry-run", "--shared-root", str(shared_root), "--db", str(db)], stdout=migrate_out) == 0

    assert "workflow layout ok" in check_out.getvalue()
    assert "dry-run complete" in migrate_out.getvalue()
