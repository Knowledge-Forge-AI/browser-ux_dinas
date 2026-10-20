from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from shared_images_lib import DEFAULT_DB, connect_db, sha256_file


TRANSPARENCY_PATH_COLUMNS = [
    "production_destination",
    "original_path",
    "transparent_path",
    "superseded_path",
    "alternate_path",
    "final_path",
    "original_archive_path",
]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit the shared-images SQLite database against files on disk.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite DB path. Default: {DEFAULT_DB}")
    parser.add_argument("--check-hashes", action="store_true", help="Hash every canonical image and compare to DB.")
    parser.add_argument("--check-symlinks", action="store_true", help="Report broken by-artist symlinks.")
    return parser.parse_args(argv)


def count_missing(paths: Iterable[str | None]) -> tuple[int, int]:
    path_values = tuple(paths)
    blanks = sum(1 for path in path_values if not path)
    missing = sum(1 for path in path_values if path and not Path(path).exists())
    return blanks, missing


def _stream(stdout: TextIO | None, stderr: TextIO | None) -> tuple[TextIO, TextIO]:
    return stdout or sys.stdout, stderr or sys.stderr


def audit_database(
    conn,
    *,
    check_hashes: bool = False,
    check_symlinks: bool = False,
    home: Path | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out, err = _stream(stdout, stderr)
    failures = 0

    fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
    print(f"foreign_key_check_rows={len(fk_rows)}", file=out)
    failures += len(fk_rows)

    image_rows = conn.execute("SELECT id, path, sha256 FROM anime_women_images ORDER BY id").fetchall()
    blanks, missing = count_missing(row["path"] for row in image_rows)
    print(f"anime_women_images.path blanks={blanks} missing={missing}", file=out)
    failures += blanks + missing

    null_fks = conn.execute(
        "SELECT count(*) FROM anime_women_images WHERE image_type_id IS NULL OR res_type_id IS NULL",
    ).fetchone()[0]
    blank_artists = conn.execute(
        "SELECT count(*) FROM anime_women_images WHERE artist IS NULL OR artist = ''",
    ).fetchone()[0]
    print(f"anime_women_images.required_fk_nulls={null_fks}", file=out)
    print(f"anime_women_images.blank_artists={blank_artists}", file=out)
    failures += null_fks + blank_artists

    substitute_paths = (
        row["substitute_path"]
        for row in conn.execute("SELECT substitute_path FROM anime_women_images_high_res_substitutes")
    )
    blanks, missing = count_missing(substitute_paths)
    print(f"high_res_substitutes.substitute_path blanks={blanks} missing={missing}", file=out)
    failures += blanks + missing

    active_lowres_missing = 0
    for row in conn.execute(
        "SELECT original_lowres_path, low_res_original_deleted FROM anime_women_images_high_res_substitutes",
    ):
        if row["original_lowres_path"] and not row["low_res_original_deleted"]:
            if not Path(row["original_lowres_path"]).exists():
                active_lowres_missing += 1
    print(f"high_res_substitutes.active_original_lowres_missing={active_lowres_missing}", file=out)
    failures += active_lowres_missing

    query = "SELECT " + ", ".join(TRANSPARENCY_PATH_COLUMNS) + " FROM anime_women_images_transparency_workflow"
    workflow_paths: list[str | None] = []
    for row in conn.execute(query):
        workflow_paths.extend(row[col] for col in TRANSPARENCY_PATH_COLUMNS)
    blanks, missing = count_missing(workflow_paths)
    print(f"transparency_workflow.path_fields blanks={blanks} missing={missing}", file=out)
    failures += missing

    if check_hashes:
        mismatches = 0
        for row in image_rows:
            path = Path(row["path"])
            if path.exists() and sha256_file(path) != row["sha256"]:
                print(f"hash_mismatch id={row['id']} path={path}", file=err)
                mismatches += 1
        print(f"anime_women_images.hash_mismatches={mismatches}", file=out)
        failures += mismatches

    if check_symlinks:
        broken = 0
        shared_home = home or Path.home()
        roots = list(shared_home.glob("Pictures/shared-images/anime/women/*/prod/*/by-artist"))
        for root in roots:
            for link in root.rglob("*"):
                if link.is_symlink() and not Path(os.readlink(link)).exists():
                    print(f"broken_symlink {link} -> {os.readlink(link)}", file=err)
                    broken += 1
        print(f"by_artist_broken_symlinks={broken}", file=out)
        failures += broken

    return 1 if failures else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    conn = connect_db(args.db)
    try:
        return audit_database(conn, check_hashes=args.check_hashes, check_symlinks=args.check_symlinks)
    finally:
        conn.close()
