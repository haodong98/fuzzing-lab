#!/usr/bin/env python3
"""Generate a small, diverse PNG seed corpus.

Why diversity matters (Q3):
    AFL++ starts from the smallest seed that reaches the maximum coverage in its initial
    queue. A monoculture corpus (e.g., only RGB images) leaves the fuzzer to discover all
    other color types from scratch through random mutation. We hand it one example of each
    important color_type x bit_depth x interlace combination so that the *initial* coverage
    already exercises the major branches of png_handle_IHDR, png_set_*, and the IDAT
    defilter pipeline.

Output: writes seeds/0X_*.png. Each file < 4 KB.
"""
import os
import sys
from pathlib import Path

try:
    from PIL import Image, PngImagePlugin
except ImportError:
    print("Pillow is required. Run: pip3 install --break-system-packages pillow", file=sys.stderr)
    sys.exit(1)

OUT = Path(__file__).resolve().parent.parent / "seeds"
OUT.mkdir(exist_ok=True)

# Drop any pre-existing seeds so we have a known set.
for f in OUT.glob("*.png"):
    f.unlink()

# (1) Grayscale 8-bit, no interlace
Image.new("L", (8, 8), color=128).save(OUT / "01_gray_8bit.png")

# (2) RGB 8-bit, no interlace — most common path
Image.new("RGB", (8, 8), color=(0, 128, 255)).save(OUT / "02_rgb_8bit.png")

# (3) Palette (color_type=3) — feeds the PLTE expansion path (CVE-2015-8126 region)
img_p = Image.new("P", (8, 8))
pal = []
for i in range(8):
    pal.extend([i*32, 255-i*32, 128])
pal.extend([0]*(768-len(pal)))
img_p.putpalette(pal)
img_p.save(OUT / "03_palette.png")

# (4) RGBA 8-bit — color_type=6, alpha channel exercises an extra defilter path
Image.new("RGBA", (8, 8), color=(255, 0, 0, 128)).save(OUT / "04_rgba.png")

# (5) Grayscale + alpha 8-bit — color_type=4
Image.new("LA", (8, 8), color=(64, 200)).save(OUT / "05_gray_alpha.png")

# (6) Adam7-interlaced RGB — exercises the 7-pass interlace state machine.
# PIL's interlace= kwarg is unreliable across versions, so build the IHDR by hand.
import struct, zlib
def _chunk(typ, data):
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))
def _adam7_rgb(w, h):
    sig = bytes.fromhex("89504e470d0a1a0a")
    ihdr = struct.pack(">II5B", w, h, 8, 2, 0, 0, 1)  # 8-bit RGB, interlace=1
    passes = [(2,2),(2,2),(4,2),(4,4),(8,4),(8,8),(16,8)]
    raw = b""
    for pw, ph in passes:
        for _ in range(ph):
            raw += b"\x00" + b"\x00" * (3 * pw)
    return sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")
(OUT / "06_interlaced.png").write_bytes(_adam7_rgb(16, 16))

# (7) PNG with text chunks — exercises tEXt path (CVE-2016-10087 region)
img7 = Image.new("RGB", (4, 4), color=(0, 0, 0))
meta = PngImagePlugin.PngInfo()
meta.add_text("Title", "fuzz")
meta.add_text("Author", "harness")
meta.add_text("Description", "exercise tEXt code path")
img7.save(OUT / "07_with_text.png", pnginfo=meta)

# (8) 16-bit grayscale — wider IDAT rows + integer arithmetic edge cases
img8 = Image.new("I;16", (4, 4))
img8.putdata([i*4096 for i in range(16)])
img8.save(OUT / "08_gray_16bit.png")

count = len(list(OUT.glob("*.png")))
sizes = sorted(int(f.stat().st_size) for f in OUT.glob("*.png"))
print(f"[OK] generated {count} seeds in {OUT}; sizes: {sizes}")
