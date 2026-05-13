#!/usr/bin/env python3
"""
Replay an AFL++ `script` capture through pyte to recover the final terminal frame,
then render it as a monochrome PNG suitable for inclusion in the LaTeX appendix.

Usage:
    python3 render-afl-status.py <capture.txt> <output.png> [cols=140] [rows=42]
"""

import sys
import pyte
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path


def render(capture_path, out_path, cols=140, rows=42):
    # Read the capture. script(1) wraps the session with two human-readable
    # header/footer lines; strip them so they don't pollute the rendered frame.
    raw = Path(capture_path).read_bytes()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith("Script started on"):
        lines = lines[1:]
    if lines and lines[-1].startswith("Script done on"):
        lines = lines[:-1]
    stream_data = "".join(lines)

    # Replay through pyte. Use a HistoryScreen so we capture the *last* frame
    # rather than the running cursor position. AFL++ paints the whole TUI on
    # every redraw, so the final post-replay state is what we want.
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)
    stream.feed(stream_data)
    frame = screen.display  # list[str], `rows` entries each `cols` wide

    # Pick a monospace font that the system definitely has on macOS.
    candidates = [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    font_path = next((p for p in candidates if Path(p).exists()), None)
    font_size = 12
    font = ImageFont.truetype(font_path, font_size) if font_path else ImageFont.load_default()

    # Measure glyph size. Try the modern API first, fall back to legacy.
    try:
        bbox = font.getbbox("M")
        ch_w = bbox[2] - bbox[0]
        ch_h = bbox[3] - bbox[1] + 4
    except AttributeError:
        ch_w, ch_h = font.getsize("M")
        ch_h += 4

    pad = 8
    img_w = cols * ch_w + 2 * pad
    img_h = rows * ch_h + 2 * pad

    img = Image.new("RGB", (img_w, img_h), color=(248, 248, 248))
    draw = ImageDraw.Draw(img)

    for y, line in enumerate(frame):
        # pyte stores trailing spaces; rstrip for a cleaner image
        draw.text((pad, pad + y * ch_h), line.rstrip(), fill=(20, 20, 20), font=font)

    img.save(out_path)
    print(f"[OK] {out_path}  ({img_w}x{img_h}, {Path(out_path).stat().st_size} B)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    cols = int(sys.argv[3]) if len(sys.argv) > 3 else 140
    rows = int(sys.argv[4]) if len(sys.argv) > 4 else 42
    render(sys.argv[1], sys.argv[2], cols, rows)
