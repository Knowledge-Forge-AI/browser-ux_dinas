from __future__ import annotations

import os
import hashlib
import struct
import zlib
from pathlib import Path

import pytest


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


def jpeg_bytes(width: int, height: int) -> bytes:
    return b"".join(
        [
            b"\xff\xd8",
            b"\xff\xe0",
            struct.pack(">H", 4),
            b"JF",
            b"\xff\xc0",
            struct.pack(">H", 8),
            b"\x08",
            struct.pack(">HH", height, width),
            b"\x03",
            b"\xff\xd9",
        ],
    )


def row(**values):
    class Row(dict):
        def __getitem__(self, key):
            return dict.__getitem__(self, key)

    return Row(values)


def test_connect_db_enables_foreign_keys_and_row_access(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    db = tmp_path / "shared-images.sqlite"

    conn = module.connect_db(db)
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        conn.execute("CREATE TABLE sample (name TEXT)")
        conn.execute("INSERT INTO sample VALUES ('rem')")
        result = conn.execute("SELECT name FROM sample").fetchone()
        assert result["name"] == "rem"
    finally:
        conn.close()


def test_sha256_file_hashes_large_files_in_chunks(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    sample = tmp_path / "sample.bin"
    payload = b"abc" * (512 * 1024)
    sample.write_bytes(payload)

    assert module.sha256_file(sample) == hashlib.sha256(payload).hexdigest()


def test_relative_to_shared_uses_resolved_paths(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    shared_root = tmp_path / "shared"
    nested = shared_root / "anime" / "women" / "rem.png"
    nested.parent.mkdir(parents=True)
    nested.write_text("image\n", encoding="utf-8")

    assert module.relative_to_shared(nested, shared_root) == "anime/women/rem.png"


def test_append_note_is_idempotent(load_module):
    module = load_module("libexec/shared-images/shared_images_lib.py")

    assert module.append_note("", "artist unresolved") == "artist unresolved"
    assert module.append_note("source unknown", "artist unresolved") == "source unknown; artist unresolved"
    assert module.append_note("artist unresolved", "artist unresolved") == "artist unresolved"


def test_png_dimensions_reads_ihdr_size(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    image = tmp_path / "sample.png"
    image.write_bytes(png_bytes(320, 180))

    assert module.image_dimensions(image) == (320, 180)
    assert module.image_dimensions_text(image) == "320x180"


def test_image_dimensions_reads_jpeg_sof_size(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    image = tmp_path / "sample.jpeg"
    image.write_bytes(jpeg_bytes(640, 480))

    assert module.image_dimensions(image) == (640, 480)
    assert module.image_dimensions_text(image) == "640x480"


def test_image_dimensions_rejects_unsupported_and_corrupt_files(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    gif = tmp_path / "sample.gif"
    png = tmp_path / "broken.png"
    jpg = tmp_path / "broken.jpg"
    short_jpg = tmp_path / "short.jpg"
    bad_segment_jpg = tmp_path / "bad-segment.jpg"
    gif.write_bytes(b"GIF89a")
    png.write_bytes(b"not a png")
    jpg.write_bytes(b"not a jpeg")
    short_jpg.write_bytes(b"\xff\xd8\xff\xc0\x00\x08\x08")
    bad_segment_jpg.write_bytes(b"\xff\xd8\xff\xe0\x00\x01")

    with pytest.raises(ValueError, match="unsupported image type"):
        module.image_dimensions(gif)
    with pytest.raises(ValueError, match="not a PNG file"):
        module.image_dimensions(png)
    with pytest.raises(ValueError, match="not a JPEG file"):
        module.image_dimensions(jpg)
    with pytest.raises(ValueError, match="could not read JPEG dimensions"):
        module.image_dimensions(short_jpg)
    with pytest.raises(ValueError, match="invalid JPEG segment length"):
        module.image_dimensions(bad_segment_jpg)


def test_type_dir_rejects_unknown_image_type(load_module):
    module = load_module("libexec/shared-images/shared_images_lib.py")

    with pytest.raises(ValueError, match="unknown image_type_id: 99"):
        module.type_dir(99)


def test_path_builders_and_artist_link_names(load_module):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    shared_root = Path("/tmp/shared-images")

    assert module.type_dir(1) == "wallpapers"
    assert module.anime_women_root(shared_root) == shared_root / "anime" / "women"
    assert module.type_root(2, shared_root) == shared_root / "anime" / "women" / "portraits"
    assert module.inbox_dir(shared_root) == shared_root / "anime" / "women" / "inbox"
    assert module.workflow_dir(1, shared_root) == shared_root / "anime" / "women" / "wallpapers" / "workflow"
    assert module.legacy_inbox_dir(2, shared_root) == shared_root / "anime" / "women" / "portraits" / "inbox"
    assert str(module.prod_dir(1, "sfw", "re_zero")).endswith("wallpapers/prod/sfw/re_zero")
    assert str(module.transparency_dir(2, "sfw", "re_zero")).endswith("portraits/transparency/sfw/re_zero")
    assert str(module.by_artist_dir(1, "nsfw", "unknown")).endswith("wallpapers/prod/nsfw/by-artist/unknown")
    assert module.artist_link_name("sfw", "re_zero", "rem.png") == "sfw__re_zero__rem.png"
    assert module.artist_link_name("sfw", "re_zero", "rem.png", prefix="originals") == "originals__sfw__re_zero__rem.png"


def test_reset_symlink_replaces_existing_path_and_reports_dry_run(load_module, tmp_path: Path, capsys):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    target = tmp_path / "target.png"
    link = tmp_path / "links" / "sample.png"
    target.write_text("image\n", encoding="utf-8")
    link.parent.mkdir()
    link.write_text("old file\n", encoding="utf-8")

    module.reset_symlink(link, target)

    assert link.is_symlink()
    assert Path(os.readlink(link)) == target

    dry_link = tmp_path / "dry" / "sample.png"
    module.reset_symlink(dry_link, target, dry_run=True)

    assert not dry_link.exists()
    assert f"link {dry_link} -> {target}" in capsys.readouterr().out


def test_remove_matching_symlinks_prunes_only_matching_links(load_module, tmp_path: Path, capsys):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    root = tmp_path / "links"
    target = tmp_path / "series" / "rem.png"
    other_target = tmp_path / "series" / "emilia.png"
    root.mkdir()
    target.parent.mkdir()
    target.write_text("image\n", encoding="utf-8")
    other_target.write_text("image\n", encoding="utf-8")
    keep = root / "keep.png"
    remove_by_name = root / "remove-rem.png"
    remove_by_target = root / "target-match.png"
    regular_file = root / "regular.txt"
    os.symlink(str(other_target), keep)
    os.symlink(str(other_target), remove_by_name)
    os.symlink(str(target), remove_by_target)
    regular_file.write_text("not a symlink\n", encoding="utf-8")

    assert module.remove_matching_symlinks(tmp_path / "missing", {"rem"}) == 0
    needles = {"remove-rem", "rem.png"}

    assert module.remove_matching_symlinks(root, needles, dry_run=True) == 2
    assert remove_by_name.is_symlink()
    assert remove_by_target.is_symlink()
    assert "unlink" in capsys.readouterr().out
    assert module.remove_matching_symlinks(root, needles) == 2
    assert keep.is_symlink()
    assert not remove_by_name.exists()
    assert not remove_by_target.exists()
    assert regular_file.exists()


def test_refresh_artist_link_creates_expected_symlink(load_module, tmp_path: Path):
    module = load_module("libexec/shared-images/shared_images_lib.py")
    target = tmp_path / "rem.png"
    target.write_text("image\n", encoding="utf-8")

    result = module.refresh_artist_link(
        row(
            path=str(target),
            image_type_id=1,
            safety="sfw",
            artist="artist_name",
            series="re_zero",
        ),
    )

    assert result.is_symlink()
    assert result.name == "sfw__re_zero__rem.png"
    assert Path(os.readlink(result)) == target
