"""Generate PhishShield AI extension icons as simple true-color PNGs.

Pure standard library (zlib + struct), so no Pillow is required.
Draws a blue shield with a white check mark at any size we need.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"
BLUE = (26, 115, 232)
WHITE = (255, 255, 255)


def make_icon(size: int) -> bytes:
    rows: list[bytes] = []
    half = size / 2.0
    cx, cy = half, half
    for y in range(size):
        row = bytearray(b"\x00")
        for x in range(size):
            dx = (x - cx) / half
            dy = (y - cy + 0.45) / half  # shift down so the shield looks centred
            # Shield: top shoulders via a circle, bottom point via a cone.
            in_top = dx * dx + dy * dy <= 1.45 and dy <= 0.35
            in_bottom = abs(dx) <= 0.9 * abs(1 - dy) / 1.45 and 0.35 < dy <= 1.0
            inside = in_top or in_bottom
            # Check mark stroke: two segments.
            check_inside = False
            if inside:
                # left stroke  -> '/'-like line from (x-0.55,y+0.05) to (x-0.25,y-0.25)
                t1 = _dist_to_segment(x, y, cx - 0.55 * half, cy + 0.05 * half, cx - 0.25 * half, cy - 0.25 * half)
                # right stroke -> '\'-like
                t2 = _dist_to_segment(x, y, cx - 0.25 * half, cy - 0.25 * half, cx + 0.5 * half, cy + 0.3 * half)
                stroke = max(2.0, size * 0.055)
                check_inside = min(t1, t2) <= stroke
            if check_inside:
                row += bytes(WHITE)
            elif inside:
                row += bytes(BLUE)
            else:
                row += bytes((0, 0, 0))
        rows.append(bytes(row))
    raw = b"\x00\x00\x00\x00" + b"".join(rows)

    def _chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )


def _dist_to_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    c1 = vx * wx + vy * wy
    c2 = vx * vx + vy * vy
    if c2 == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, c1 / c2))
    return ((px - (ax + t * vx)) ** 2 + (py - (ay + t * vy)) ** 2) ** 0.5


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for size, name in ((16, "icon16.png"), (48, "icon48.png"), (128, "icon128.png")):
        (OUT / name).write_bytes(make_icon(size))
        print(f"wrote {OUT / name} ({size}x{size})")


if __name__ == "__main__":
    main()