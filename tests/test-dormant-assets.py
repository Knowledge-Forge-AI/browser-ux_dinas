"""Offline standard-library generator checks; uses the check's Python, not /usr/bin/python3."""
import pathlib
import struct
import subprocess
import sys
import tempfile
import zlib


def check_png(path, dimensions):
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    offset, compressed, kinds = 8, bytearray(), []
    while offset < len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
        assert zlib.crc32(kind + payload) & 0xffffffff == crc
        kinds.append(kind)
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            assert (width, height) == dimensions
            assert (depth, color, compression, filtering, interlace) == (8, 6, 0, 0, 0)
        if kind == b"IDAT":
            compressed.extend(payload)
        offset += length + 12
    assert kinds[0] == b"IHDR" and kinds[-1] == b"IEND" and offset == len(data)
    raw = zlib.decompress(compressed)
    stride = dimensions[0] * 4 + 1
    assert len(raw) == stride * dimensions[1]
    assert all(raw[row * stride] == 0 for row in range(dimensions[1]))


def main():
    generators = pathlib.Path(sys.argv[1]).resolve()
    icons = {
        "icon_16x16.png": 16, "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32, "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128, "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256, "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512, "icon_512x512@2x.png": 1024,
    }
    themes = {"theme_frame.png": (3000, 220), "theme_toolbar.png": (3000, 120),
              "theme_ntp_background.png": (1600, 1000)}
    with tempfile.TemporaryDirectory() as temporary:
        for script, expected in (
            ("generate-icon.py", {name: (size, size) for name, size in icons.items()}),
            ("generate-theme-assets.py", themes),
        ):
            output = pathlib.Path(temporary) / script
            output.mkdir()
            subprocess.run([sys.executable, str(generators / script), str(output)], check=True)
            assert {p.name for p in output.iterdir()} == set(expected)
            for name, dimensions in expected.items():
                check_png(output / name, dimensions)
    print("13 offline PNG assets: dimensions, CRCs and decoded RGBA payloads verified")


if __name__ == "__main__":
    main()
