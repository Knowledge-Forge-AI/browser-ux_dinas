"""Shared helpers for the local shared-images archive scripts."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
from pathlib import Path


DEFAULT_SHARED_ROOT = Path.home() / "Pictures/shared-images"
DEFAULT_DB = DEFAULT_SHARED_ROOT / "shared-images-db.sqlite"
ANIME_WOMEN_ROOT = DEFAULT_SHARED_ROOT / "anime/women"

IMAGE_TYPE_DIRS = {
    1: "wallpapers",
    2: "portraits",
}

IMAGE_TYPE_NAMES = {
    1: "wallpaper",
    2: "portrait",
}


def connect_db(db_path: Path = DEFAULT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_to_shared(path: Path, shared_root: Path = DEFAULT_SHARED_ROOT) -> str:
    return str(path.resolve().relative_to(shared_root.resolve()))


def append_note(existing: str, note: str) -> str:
    existing = (existing or "").strip()
    if note in existing:
        return existing
    if not existing:
        return note
    return f"{existing}; {note}"


def image_dimensions(path: Path) -> tuple[int, int]:
    suffix = path.suffix.lower()
    if suffix == ".png":
        return _png_dimensions(path)
    if suffix in {".jpg", ".jpeg"}:
        return _jpeg_dimensions(path)
    raise ValueError(f"unsupported image type for dimensions: {path}")


def image_dimensions_text(path: Path) -> str:
    width, height = image_dimensions(path)
    return f"{width}x{height}"


def _png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as fh:
        header = fh.read(24)
    if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        raise ValueError(f"not a PNG file: {path}")
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def _jpeg_dimensions(path: Path) -> tuple[int, int]:
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    with path.open("rb") as fh:
        if fh.read(2) != b"\xff\xd8":
            raise ValueError(f"not a JPEG file: {path}")
        while True:
            marker_prefix = fh.read(1)
            if not marker_prefix:
                break
            if marker_prefix != b"\xff":
                continue
            marker = fh.read(1)
            while marker == b"\xff":
                marker = fh.read(1)
            if not marker:
                break
            marker_int = marker[0]
            if marker_int in {0xD8, 0xD9}:
                continue
            length_bytes = fh.read(2)
            if len(length_bytes) != 2:
                break
            segment_length = struct.unpack(">H", length_bytes)[0]
            if segment_length < 2:
                raise ValueError(f"invalid JPEG segment length in {path}")
            if marker_int in sof_markers:
                data = fh.read(5)
                if len(data) != 5:
                    break
                height, width = struct.unpack(">HH", data[1:5])
                return width, height
            fh.seek(segment_length - 2, os.SEEK_CUR)
    raise ValueError(f"could not read JPEG dimensions: {path}")


def type_dir(image_type_id: int) -> str:
    try:
        return IMAGE_TYPE_DIRS[image_type_id]
    except KeyError as exc:
        raise ValueError(f"unknown image_type_id: {image_type_id}") from exc


def anime_women_root(shared_root: Path | None = None) -> Path:
    if shared_root is None:
        return ANIME_WOMEN_ROOT
    return Path(shared_root) / "anime" / "women"


def type_root(image_type_id: int, shared_root: Path | None = None) -> Path:
    return anime_women_root(shared_root) / type_dir(image_type_id)


def inbox_dir(shared_root: Path | None = None) -> Path:
    return anime_women_root(shared_root) / "inbox"


def workflow_dir(image_type_id: int, shared_root: Path | None = None) -> Path:
    return type_root(image_type_id, shared_root) / "workflow"


def legacy_inbox_dir(image_type_id: int, shared_root: Path | None = None) -> Path:
    return type_root(image_type_id, shared_root) / "inbox"


def prod_dir(image_type_id: int, safety: str, series: str) -> Path:
    return ANIME_WOMEN_ROOT / type_dir(image_type_id) / "prod" / safety / series


def transparency_dir(image_type_id: int, safety: str, series: str) -> Path:
    return ANIME_WOMEN_ROOT / type_dir(image_type_id) / "transparency" / safety / series


def by_artist_dir(image_type_id: int, safety: str, artist: str) -> Path:
    return ANIME_WOMEN_ROOT / type_dir(image_type_id) / "prod" / safety / "by-artist" / artist


def artist_link_name(safety: str, series: str, filename: str, prefix: str | None = None) -> str:
    stem = f"{safety}__{series}__{filename}"
    if prefix:
        return f"{prefix}__{stem}"
    return stem


def reset_symlink(link_path: Path, target_path: Path, dry_run: bool = False) -> None:
    if dry_run:
        print(f"link {link_path} -> {target_path}")
        return
    link_path.parent.mkdir(parents=True, exist_ok=True)
    if link_path.is_symlink() or link_path.exists():
        link_path.unlink()
    os.symlink(str(target_path), str(link_path))


def remove_matching_symlinks(root: Path, needles: set[str], dry_run: bool = False) -> int:
    if not root.exists():
        return 0
    removed = 0
    for link in root.rglob("*"):
        if not link.is_symlink():
            continue
        target = os.readlink(link)
        haystack = f"{link.name}\n{target}"
        if any(needle and needle in haystack for needle in needles):
            if dry_run:
                print(f"unlink {link}")
            else:
                link.unlink()
            removed += 1
    return removed


def refresh_artist_link(row: sqlite3.Row, dry_run: bool = False) -> Path:
    target = Path(row["path"])
    artist_root = by_artist_dir(row["image_type_id"], row["safety"], row["artist"])
    link = artist_root / artist_link_name(row["safety"], row["series"], target.name)
    reset_symlink(link, target, dry_run=dry_run)
    return link
