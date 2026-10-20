from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from shared_images_lib import DEFAULT_DB, by_artist_dir, connect_db, refresh_artist_link


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Refresh canonical by-artist symlinks from anime_women_images.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite DB path. Default: {DEFAULT_DB}")
    parser.add_argument("--image-type", choices=["wallpaper", "portrait"], help="Limit to one image type.")
    parser.add_argument("--safety", choices=["sfw", "nsfw"], help="Limit to one safety bucket.")
    parser.add_argument("--artist", help="Limit to one artist.")
    parser.add_argument("--prune-broken", action="store_true", help="Remove broken symlinks below selected by-artist dirs.")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing.")
    return parser.parse_args(argv)


def selected_rows(
    conn,
    *,
    image_type: str | None = None,
    safety: str | None = None,
    artist: str | None = None,
):
    clauses = []
    params = []
    if image_type:
        clauses.append("it.value = ?")
        params.append(image_type)
    if safety:
        clauses.append("i.safety = ?")
        params.append(safety)
    if artist:
        clauses.append("i.artist = ?")
        params.append(artist)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return conn.execute(
        f"""
        SELECT i.*
        FROM anime_women_images i
        JOIN image_types it ON it.id = i.image_type_id
        {where}
        ORDER BY i.image_type_id, i.safety, i.artist, i.series, i.path
        """,
        params,
    ).fetchall()


def prune_broken_links(root: Path, *, dry_run: bool = False, stdout: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    if not root.exists():
        return 0
    pruned = 0
    for link in root.rglob("*"):
        if link.is_symlink() and not Path(os.readlink(link)).exists():
            if dry_run:
                print(f"unlink broken {link} -> {os.readlink(link)}", file=out)
            else:
                link.unlink()
            pruned += 1
    return pruned


def refresh_artist_links(
    conn,
    *,
    image_type: str | None = None,
    safety: str | None = None,
    artist: str | None = None,
    prune_broken: bool = False,
    dry_run: bool = False,
    stdout: TextIO | None = None,
) -> tuple[int, int]:
    out = stdout or sys.stdout
    rows = selected_rows(conn, image_type=image_type, safety=safety, artist=artist)

    linked = 0
    for row in rows:
        if not Path(row["path"]).exists():
            print(f"skip missing canonical file: {row['path']}", file=out)
            continue
        with contextlib.redirect_stdout(out):
            refresh_artist_link(row, dry_run=dry_run)
        linked += 1

    pruned = 0
    if prune_broken:
        roots = {by_artist_dir(row["image_type_id"], row["safety"], row["artist"]) for row in rows}
        for root in roots:
            pruned += prune_broken_links(root, dry_run=dry_run, stdout=out)

    print(f"linked={linked} pruned_broken={pruned if prune_broken else 0}", file=out)
    return linked, pruned if prune_broken else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    conn = connect_db(args.db)
    try:
        refresh_artist_links(
            conn,
            image_type=args.image_type,
            safety=args.safety,
            artist=args.artist,
            prune_broken=args.prune_broken,
            dry_run=args.dry_run,
        )
    finally:
        conn.close()
    return 0
