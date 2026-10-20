#!/usr/bin/env python3
import os
import struct
import sys
import zlib


BLACK = (0, 0, 0, 255)
WHITE = (255, 255, 255, 255)
RED = (255, 0, 0, 255)
BLUE = (66, 133, 244, 255)
GREEN = (52, 168, 83, 255)
YELLOW = (251, 188, 5, 255)


def chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def in_polygon(x, y, points):
    inside = False
    px, py = points[-1]
    for cx, cy in points:
        if ((cy > y) != (py > y)) and (x < (px - cx) * (y - cy) / ((py - cy) or 1) + cx):
            inside = not inside
        px, py = cx, cy
    return inside


def in_triangle(x, y, points):
    (x1, y1), (x2, y2), (x3, y3) = points
    d1 = (x - x2) * (y1 - y2) - (x1 - x2) * (y - y2)
    d2 = (x - x3) * (y2 - y3) - (x2 - x3) * (y - y3)
    d3 = (x - x1) * (y3 - y1) - (x3 - x1) * (y - y1)
    has_neg = d1 < 0 or d2 < 0 or d3 < 0
    has_pos = d1 > 0 or d2 > 0 or d3 > 0
    return not (has_neg and has_pos)


def in_pill(x, y, x0, y0, x1, y1):
    radius = (y1 - y0) / 2
    cy = (y0 + y1) / 2
    if x0 + radius <= x <= x1 - radius and y0 <= y <= y1:
        return True
    return (x - (x0 + radius)) ** 2 + (y - cy) ** 2 <= radius ** 2 or (
        x - (x1 - radius)
    ) ** 2 + (y - cy) ** 2 <= radius ** 2


def lion_color(x, y, cx, cy, scale):
    mane = [
        (cx, cy - 0.46 * scale),
        (cx + 0.34 * scale, cy - 0.33 * scale),
        (cx + 0.47 * scale, cy + 0.03 * scale),
        (cx + 0.25 * scale, cy + 0.42 * scale),
        (cx, cy + 0.50 * scale),
        (cx - 0.25 * scale, cy + 0.42 * scale),
        (cx - 0.47 * scale, cy + 0.03 * scale),
        (cx - 0.34 * scale, cy - 0.33 * scale),
    ]
    face = [
        (cx, cy - 0.24 * scale),
        (cx + 0.20 * scale, cy - 0.10 * scale),
        (cx + 0.15 * scale, cy + 0.22 * scale),
        (cx, cy + 0.33 * scale),
        (cx - 0.15 * scale, cy + 0.22 * scale),
        (cx - 0.20 * scale, cy - 0.10 * scale),
    ]
    nose = [
        (cx, cy + 0.07 * scale),
        (cx + 0.06 * scale, cy + 0.14 * scale),
        (cx, cy + 0.20 * scale),
        (cx - 0.06 * scale, cy + 0.14 * scale),
    ]
    left_eye = [
        (cx - 0.13 * scale, cy - 0.05 * scale),
        (cx - 0.05 * scale, cy - 0.02 * scale),
        (cx - 0.12 * scale, cy + 0.03 * scale),
    ]
    right_eye = [
        (cx + 0.13 * scale, cy - 0.05 * scale),
        (cx + 0.05 * scale, cy - 0.02 * scale),
        (cx + 0.12 * scale, cy + 0.03 * scale),
    ]

    color = None
    if in_polygon(x, y, mane):
        color = RED
        if x < cx - 0.14 * scale or x > cx + 0.14 * scale:
            color = YELLOW
        if y > cy + 0.28 * scale:
            color = BLUE
    if in_polygon(x, y, face):
        color = WHITE
    if in_polygon(x, y, nose) or in_triangle(x, y, left_eye) or in_triangle(x, y, right_eye):
        color = BLACK
    return color


def write_png(path, size):
    rows = []
    side_bar = max(1, int(size * 0.075 + 0.999999))
    horizontal_bar = max(1, int(size * 0.055 + 0.999999))

    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            color = BLACK

            if x < side_bar or x >= size - side_bar:
                color = RED
            if y < horizontal_bar:
                color = BLUE
            if y >= size - horizontal_bar:
                color = GREEN

            lion = lion_color(x, y, size * 0.50, size * 0.45, size * 0.84)
            if lion:
                color = lion

            if in_pill(x, y, size * 0.17, size * 0.53, size * 0.83, size * 0.79):
                color = BLACK
            if in_pill(x, y, size * 0.20, size * 0.56, size * 0.80, size * 0.76):
                color = RED

            triangle = (
                (size * 0.45, size * 0.60),
                (size * 0.45, size * 0.72),
                (size * 0.59, size * 0.66),
            )
            if in_triangle(x, y, triangle):
                color = WHITE

            row.extend(color)
        rows.append(bytes(row))

    raw = b"".join(rows)
    payload = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as handle:
        handle.write(payload)


def main():
    iconset = sys.argv[1]
    for name, size in {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }.items():
        write_png(os.path.join(iconset, name), size)


if __name__ == "__main__":
    main()
