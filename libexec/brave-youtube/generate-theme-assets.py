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
FRAME_SAFE_LEFT = 260
FRAME_STRIPE_LEFT = 3
FRAME_STRIPE_RIGHT = 1916
FRAME_LION_CENTER_X = 1838
FRAME_LION_CENTER_Y = 52
FRAME_LION_SCALE = 58


def chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def write_png(path, width, height, pixel):
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            row.extend(pixel(x, y, width, height))
        rows.append(bytes(row))

    raw = b"".join(rows)
    payload = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as handle:
        handle.write(payload)


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
        (cx, cy - 0.26 * scale),
        (cx + 0.22 * scale, cy - 0.13 * scale),
        (cx + 0.17 * scale, cy + 0.23 * scale),
        (cx, cy + 0.35 * scale),
        (cx - 0.17 * scale, cy + 0.23 * scale),
        (cx - 0.22 * scale, cy - 0.13 * scale),
    ]
    left_eye = [
        (cx - 0.14 * scale, cy - 0.05 * scale),
        (cx - 0.04 * scale, cy - 0.02 * scale),
        (cx - 0.12 * scale, cy + 0.03 * scale),
    ]
    right_eye = [
        (cx + 0.14 * scale, cy - 0.05 * scale),
        (cx + 0.04 * scale, cy - 0.02 * scale),
        (cx + 0.12 * scale, cy + 0.03 * scale),
    ]
    nose = [
        (cx, cy + 0.08 * scale),
        (cx + 0.07 * scale, cy + 0.15 * scale),
        (cx, cy + 0.21 * scale),
        (cx - 0.07 * scale, cy + 0.15 * scale),
    ]

    if in_polygon(x, y, mane):
        color = RED
        if x < cx - 0.16 * scale or x > cx + 0.16 * scale:
            color = YELLOW
        if y > cy + 0.30 * scale:
            color = BLUE
    else:
        color = None
    if in_polygon(x, y, face):
        color = WHITE
    if in_triangle(x, y, left_eye) or in_triangle(x, y, right_eye) or in_polygon(x, y, nose):
        color = BLACK
    return color


def chrome_band(x, y, width, thickness, left_margin=0):
    if y >= thickness or x < left_margin:
        return None
    segment = int(((x - left_margin) / max(width - left_margin, 1)) * 4)
    return (RED, BLUE, GREEN, YELLOW)[min(segment, 3)]


def frame_pixel(x, y, width, height):
    lion = lion_color(x, y, FRAME_LION_CENTER_X, FRAME_LION_CENTER_Y, FRAME_LION_SCALE)
    if lion:
        return lion
    if FRAME_STRIPE_LEFT <= x <= FRAME_STRIPE_RIGHT and 18 <= y <= 24:
        return BLUE
    if FRAME_SAFE_LEFT <= x <= FRAME_STRIPE_RIGHT and 32 <= y <= 36:
        return GREEN
    return BLACK


def toolbar_pixel(x, y, width, height):
    return BLACK


def ntp_pixel(x, y, width, height):
    band = chrome_band(x, y, width, 18)
    if band:
        return band
    lion = lion_color(x, y, width // 2, height // 2, min(width, height) * 0.52)
    if lion:
        return lion
    if width * 0.10 <= x <= width * 0.90 and height * 0.80 <= y <= height * 0.83:
        return RED
    return BLACK


def main():
    theme_dir = sys.argv[1]
    write_png(os.path.join(theme_dir, "theme_frame.png"), 3000, 220, frame_pixel)
    write_png(os.path.join(theme_dir, "theme_toolbar.png"), 3000, 120, toolbar_pixel)
    write_png(os.path.join(theme_dir, "theme_ntp_background.png"), 1600, 1000, ntp_pixel)


if __name__ == "__main__":
    main()
