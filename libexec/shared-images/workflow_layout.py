"""Check and migrate the shared-images intake/workflow directory layout."""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from shared_images_lib import (
    DEFAULT_DB,
    DEFAULT_SHARED_ROOT,
    IMAGE_TYPE_DIRS,
    connect_db,
    inbox_dir,
    legacy_inbox_dir,
    type_dir,
    workflow_dir,
)


WORKFLOW_SUBDIRS = (
    "codex-rejects",
    "low-res/sfw",
    "low-res/nsfw",
    "transparency/sfw",
    "transparency/nsfw",
    "processed-notes",
)

DB_PATH_COLUMNS = {
    "anime_women_images": (
        "path",
        "relative_path",
    ),
    "anime_women_images_high_res_substitutes": (
        "original_lowres_path",
        "original_lowres_relative_path",
        "substitute_path",
        "substitute_relative_path",
    ),
    "anime_women_images_transparency_workflow": (
        "production_destination",
        "production_destination_relative_path",
        "original_path",
        "original_relative_path",
        "transparent_path",
        "transparent_relative_path",
        "superseded_path",
        "superseded_relative_path",
        "alternate_path",
        "alternate_relative_path",
        "final_path",
        "final_relative_path",
        "original_archive_path",
        "original_archive_relative_path",
    ),
}


@dataclass(frozen=True)
class PathReplacement:
    old: str
    new: str
    relative: bool


@dataclass(frozen=True)
class DbUpdate:
    table: str
    column: str
    replacement: PathReplacement
    count: int


def replacement_pairs(shared_root: Path) -> tuple[PathReplacement, ...]:
    root = Path(shared_root)
    replacements: list[PathReplacement] = []
    for image_type_id in sorted(IMAGE_TYPE_DIRS):
        image_type_dir = type_dir(image_type_id)
        replacements.extend(
            [
                PathReplacement(
                    old=f"{legacy_inbox_dir(image_type_id, root)}/",
                    new=f"{workflow_dir(image_type_id, root)}/",
                    relative=False,
                ),
                PathReplacement(
                    old=f"anime/women/{image_type_dir}/inbox/",
                    new=f"anime/women/{image_type_dir}/workflow/",
                    relative=True,
                ),
            ],
        )
    return tuple(replacements)


def existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row["name"] if isinstance(row, sqlite3.Row) else row[1] for row in rows}


def db_updates(conn: sqlite3.Connection, shared_root: Path) -> list[DbUpdate]:
    replacements = replacement_pairs(shared_root)
    updates: list[DbUpdate] = []
    for table, columns in DB_PATH_COLUMNS.items():
        table_columns = existing_columns(conn, table)
        if not table_columns:
            continue
        for column in columns:
            if column not in table_columns:
                continue
            for replacement in replacements:
                column_is_relative = column == "relative_path" or column.endswith("_relative_path")
                if replacement.relative != column_is_relative:
                    continue
                count = conn.execute(
                    f"SELECT count(*) FROM {table} WHERE {column} LIKE ?",
                    (f"%{replacement.old}%",),
                ).fetchone()[0]
                if count:
                    updates.append(DbUpdate(table, column, replacement, count))
    return updates


def apply_db_updates(conn: sqlite3.Connection, updates: list[DbUpdate]) -> None:
    with conn:
        for update in updates:
            conn.execute(
                f"UPDATE {update.table} "
                f"SET {update.column} = replace({update.column}, ?, ?) "
                f"WHERE {update.column} LIKE ?",
                (update.replacement.old, update.replacement.new, f"%{update.replacement.old}%"),
            )


def workflow_conflicts(shared_root: Path) -> list[str]:
    conflicts: list[str] = []
    for image_type_id in sorted(IMAGE_TYPE_DIRS):
        legacy = legacy_inbox_dir(image_type_id, shared_root)
        target = workflow_dir(image_type_id, shared_root)
        if not legacy.exists() or not target.exists():
            continue
        for child in legacy.iterdir():
            if (target / child.name).exists():
                conflicts.append(str(target / child.name))
    return conflicts


def ensure_dir(path: Path, dry_run: bool, out: TextIO) -> None:
    if path.exists():
        return
    print(f"mkdir {path}", file=out)
    if not dry_run:
        path.mkdir(parents=True, exist_ok=True)


def migrate_workflow_dirs(shared_root: Path, dry_run: bool, out: TextIO) -> None:
    ensure_dir(inbox_dir(shared_root), dry_run, out)
    for image_type_id in sorted(IMAGE_TYPE_DIRS):
        legacy = legacy_inbox_dir(image_type_id, shared_root)
        target = workflow_dir(image_type_id, shared_root)
        if legacy.exists() and not target.exists():
            print(f"rename {legacy} -> {target}", file=out)
            if not dry_run:
                legacy.rename(target)
        elif legacy.exists() and target.exists():
            for child in sorted(legacy.iterdir()):
                destination = target / child.name
                print(f"move {child} -> {destination}", file=out)
                if not dry_run:
                    shutil.move(str(child), str(destination))
            print(f"rmdir {legacy}", file=out)
            if not dry_run:
                legacy.rmdir()
        else:
            ensure_dir(target, dry_run, out)

        for child in WORKFLOW_SUBDIRS:
            ensure_dir(target / child, dry_run, out)


def check_layout(shared_root: Path, conn: sqlite3.Connection, out: TextIO) -> int:
    issues: list[str] = []
    unified_inbox = inbox_dir(shared_root)
    if not unified_inbox.is_dir():
        issues.append(f"missing unified inbox: {unified_inbox}")

    for image_type_id in sorted(IMAGE_TYPE_DIRS):
        legacy = legacy_inbox_dir(image_type_id, shared_root)
        target = workflow_dir(image_type_id, shared_root)
        if legacy.exists():
            issues.append(f"legacy type-specific inbox still exists: {legacy}")
        if not target.is_dir():
            issues.append(f"missing workflow directory: {target}")

    for update in db_updates(conn, shared_root):
        issues.append(
            f"database still references legacy inbox: {update.table}.{update.column} "
            f"({update.count} rows)",
        )

    if issues:
        for issue in issues:
            print(issue, file=out)
        return 1
    print("shared-images workflow layout ok", file=out)
    return 0


def migrate_layout(shared_root: Path, conn: sqlite3.Connection, dry_run: bool, out: TextIO) -> int:
    conflicts = workflow_conflicts(shared_root)
    if conflicts:
        for conflict in conflicts:
            print(f"workflow migration conflict: {conflict}", file=out)
        return 1

    updates = db_updates(conn, shared_root)
    migrate_workflow_dirs(shared_root, dry_run, out)
    for update in updates:
        print(
            f"db replace {update.table}.{update.column}: "
            f"{update.replacement.old} -> {update.replacement.new} ({update.count} rows)",
            file=out,
        )
    if not dry_run:
        apply_db_updates(conn, updates)
    if dry_run:
        print("dry-run complete; no changes written", file=out)
    else:
        print("shared-images workflow layout migrated", file=out)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "migrate"))
    parser.add_argument("--shared-root", type=Path, default=DEFAULT_SHARED_ROOT)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, stdout: TextIO = sys.stdout) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    conn = connect_db(args.db)
    try:
        if args.command == "check":
            return check_layout(args.shared_root, conn, stdout)
        return migrate_layout(args.shared_root, conn, args.dry_run, stdout)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
