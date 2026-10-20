from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from shared_images_lib import (
    DEFAULT_DB,
    DEFAULT_SHARED_ROOT,
    append_note,
    artist_link_name,
    by_artist_dir,
    connect_db,
    image_dimensions_text,
    prod_dir,
    refresh_artist_link,
    relative_to_shared,
    remove_matching_symlinks,
    reset_symlink,
    sha256_file,
    transparency_dir,
)


PROMOTION_NOTE = "approved original promoted to production; transparent variant moved to transparency archive"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Promote an archived original over a transparent production variant.")
    parser.add_argument("originals", nargs="+", type=Path, help="Archived original image path(s).")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite DB path. Default: {DEFAULT_DB}")
    parser.add_argument(
        "--shared-root",
        type=Path,
        default=DEFAULT_SHARED_ROOT,
        help=f"Shared-images root for relative path values. Default: {DEFAULT_SHARED_ROOT}",
    )
    parser.add_argument("--replace", action="store_true", help="Replace an existing prod destination with different content.")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing.")
    return parser.parse_args(argv)


def copy_original_to_prod(
    original: Path,
    dest: Path,
    *,
    replace: bool = False,
    dry_run: bool = False,
    stdout: TextIO | None = None,
) -> None:
    out = stdout or sys.stdout
    if dest.exists():
        if sha256_file(dest) == sha256_file(original):
            print(f"prod already present: {dest}", file=out)
            return
        if not replace:
            raise FileExistsError(f"prod destination exists with different content: {dest}")
    if dry_run:
        print(f"copy {original} -> {dest}", file=out)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    shutil.copy2(original, dest)


def move_transparency(
    src: Path,
    dest: Path,
    *,
    dry_run: bool = False,
    stdout: TextIO | None = None,
) -> Path:
    out = stdout or sys.stdout
    if not src.exists():
        return dest
    if src.resolve() == dest.resolve():
        return dest
    if dest.exists():
        if sha256_file(src) != sha256_file(dest):
            raise FileExistsError(f"transparency destination exists with different content: {dest}")
        if dry_run:
            print(f"remove duplicate transparency source {src}", file=out)
        else:
            src.unlink()
        return dest
    if dry_run:
        print(f"move {src} -> {dest}", file=out)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return dest


def find_workflow_row(conn, original: Path):
    row = conn.execute(
        """
        SELECT *
        FROM anime_women_images_transparency_workflow
        WHERE original_path = ? OR original_archive_path = ?
        """,
        (str(original), str(original)),
    ).fetchone()
    if row is None:
        raise LookupError(f"no transparency workflow row references original: {original}")
    return row


def find_image_row(conn, workflow_row):
    row = conn.execute(
        """
        SELECT *
        FROM anime_women_images
        WHERE image_type_id = ? AND item_id = ?
        """,
        (workflow_row["image_type_id"], workflow_row["item_id"]),
    ).fetchone()
    if row is None:
        raise LookupError(f"no anime_women_images row for item_id={workflow_row['item_id']}")
    return row


def promoted_filename(original: Path) -> str:
    name = original.name
    if name.startswith("original-"):
        return name.removeprefix("original-")
    return name


def path_values(*values: str | None) -> list[Path]:
    return [Path(value) for value in values if value]


def promote_one(
    conn,
    original: Path,
    *,
    replace: bool = False,
    dry_run: bool = False,
    shared_root: Path = DEFAULT_SHARED_ROOT,
    stdout: TextIO | None = None,
) -> None:
    out = stdout or sys.stdout
    original = original.expanduser().resolve()
    if not original.exists():
        raise FileNotFoundError(original)
    workflow = find_workflow_row(conn, original)
    image = find_image_row(conn, workflow)

    prod_dest = prod_dir(workflow["image_type_id"], workflow["safety"], workflow["series"]) / promoted_filename(original)
    transparent_candidates = path_values(
        workflow["transparent_path"],
        workflow["final_path"],
        workflow["production_destination"],
        image["path"],
    )
    transparent_src = next((path for path in transparent_candidates if path.exists() and path.resolve() != original), None)
    transparent_dest = transparency_dir(workflow["image_type_id"], workflow["safety"], workflow["series"])
    if transparent_src is not None:
        transparent_dest = transparent_dest / transparent_src.name
    else:
        transparent_dest = transparent_dest / Path(workflow["transparent_path"]).name

    print(f"promote original: {original}", file=out)
    copy_original_to_prod(original, prod_dest, replace=replace, dry_run=dry_run, stdout=out)
    if transparent_src:
        move_transparency(transparent_src, transparent_dest, dry_run=dry_run, stdout=out)

    new_digest = sha256_file(original)
    new_dimensions = image_dimensions_text(original)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    artist_root = by_artist_dir(workflow["image_type_id"], workflow["safety"], workflow["artist"])
    needles = {
        Path(image["path"]).name,
        Path(workflow["transparent_path"]).name,
        str(Path(image["path"])),
        str(Path(workflow["transparent_path"])),
    }
    remove_matching_symlinks(artist_root, needles, dry_run=dry_run)

    if not dry_run:
        conn.execute(
            """
            UPDATE anime_women_images
            SET dimensions = ?,
                sha256 = ?,
                sha256_12 = ?,
                path = ?,
                relative_path = ?,
                source_note = ?
            WHERE id = ?
            """,
            (
                new_dimensions,
                new_digest,
                new_digest[:12],
                str(prod_dest),
                relative_to_shared(prod_dest, shared_root),
                append_note(image["source_note"], PROMOTION_NOTE),
                image["id"],
            ),
        )
        conn.execute(
            """
            UPDATE anime_women_images_transparency_workflow
            SET accepted_original = 1,
                accepted_transparent = 0,
                canonical_choice = 'original',
                workflow_status = 'approved_original_promoted_to_production',
                production_destination = ?,
                production_destination_relative_path = ?,
                transparent_path = ?,
                transparent_relative_path = ?,
                superseded_path = ?,
                superseded_relative_path = ?,
                alternate_path = ?,
                alternate_relative_path = ?,
                notes = ?,
                updated_utc = ?,
                final_path = ?,
                final_relative_path = ?,
                original_archive_path = ?,
                original_archive_relative_path = ?
            WHERE id = ?
            """,
            (
                str(prod_dest),
                relative_to_shared(prod_dest, shared_root),
                str(transparent_dest),
                relative_to_shared(transparent_dest, shared_root),
                str(transparent_dest),
                relative_to_shared(transparent_dest, shared_root),
                str(transparent_dest),
                relative_to_shared(transparent_dest, shared_root),
                append_note(workflow["notes"], PROMOTION_NOTE),
                now,
                str(prod_dest),
                relative_to_shared(prod_dest, shared_root),
                str(original),
                relative_to_shared(original, shared_root),
                workflow["id"],
            ),
        )

    updated_row = {
        **dict(image),
        "path": str(prod_dest),
        "image_type_id": workflow["image_type_id"],
        "safety": workflow["safety"],
        "series": workflow["series"],
        "artist": workflow["artist"],
    }
    refresh_artist_link(updated_row, dry_run=dry_run)
    original_link = artist_root / artist_link_name(workflow["safety"], workflow["series"], original.name, prefix="originals")
    reset_symlink(original_link, original, dry_run=dry_run)

    print(f"  prod={prod_dest}", file=out)
    print(f"  transparency={transparent_dest}", file=out)
    print(f"  sha256={new_digest}", file=out)


def promote_paths(
    conn,
    originals: Sequence[Path],
    *,
    replace: bool = False,
    dry_run: bool = False,
    shared_root: Path = DEFAULT_SHARED_ROOT,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    err = stderr or sys.stderr
    try:
        for original in originals:
            promote_one(
                conn,
                original,
                replace=replace,
                dry_run=dry_run,
                shared_root=shared_root,
                stdout=stdout,
            )
        if dry_run:
            conn.rollback()
        else:
            conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"error: {exc}", file=err)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    conn = connect_db(args.db)
    try:
        return promote_paths(
            conn,
            args.originals,
            replace=args.replace,
            dry_run=args.dry_run,
            shared_root=args.shared_root,
        )
    finally:
        conn.close()
