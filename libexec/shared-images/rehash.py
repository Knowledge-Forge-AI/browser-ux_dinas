from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from shared_images_lib import DEFAULT_DB, DEFAULT_SHARED_ROOT, connect_db, image_dimensions_text, relative_to_shared, sha256_file


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update sha256 metadata for existing anime_women_images rows.")
    parser.add_argument("paths", nargs="+", type=Path, help="Image path(s) already present in anime_women_images.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite DB path. Default: {DEFAULT_DB}")
    parser.add_argument(
        "--shared-root",
        type=Path,
        default=DEFAULT_SHARED_ROOT,
        help=f"Shared-images root for relative_path values. Default: {DEFAULT_SHARED_ROOT}",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print updates without writing.")
    return parser.parse_args(argv)


def rehash_paths(
    conn,
    paths: Sequence[Path],
    *,
    dry_run: bool = False,
    shared_root: Path = DEFAULT_SHARED_ROOT,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    changed = 0

    for raw_path in paths:
        path = raw_path.expanduser().resolve()
        if not path.exists():
            print(f"missing file: {path}", file=err)
            return 1
        row = conn.execute(
            "SELECT id, path, sha256, dimensions FROM anime_women_images WHERE path = ?",
            (str(path),),
        ).fetchone()
        if row is None:
            print(f"no anime_women_images row for: {path}", file=err)
            return 1

        digest = sha256_file(path)
        dimensions = image_dimensions_text(path)
        rel_path = relative_to_shared(path, shared_root)
        print(f"{path}", file=out)
        print(f"  sha256: {row['sha256']} -> {digest}", file=out)
        print(f"  dimensions: {row['dimensions']} -> {dimensions}", file=out)
        if not dry_run:
            cursor = conn.execute(
                """
                UPDATE anime_women_images
                SET sha256 = ?, sha256_12 = ?, dimensions = ?, relative_path = ?
                WHERE id = ?
                """,
                (digest, digest[:12], dimensions, rel_path, row["id"]),
            )
            changed += cursor.rowcount

    if dry_run:
        conn.rollback()
    else:
        conn.commit()
    print(f"updated_rows={changed if not dry_run else 0}", file=out)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    conn = connect_db(args.db)
    try:
        return rehash_paths(conn, args.paths, dry_run=args.dry_run, shared_root=args.shared_root)
    finally:
        conn.close()
