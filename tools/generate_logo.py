"""Generate assets/logo.png and assets/icon.png (requires Pillow: pip install -r requirements-dev.txt).

Run from the project root:   python tools/generate_logo.py
The artwork is original (a shield with an envelope) and drawn with basic shapes.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
CYAN, BLUE, PURPLE, WHITE, NAVY = (34, 211, 238), (59, 130, 246), (139, 92, 246), (230, 237, 247), (7, 11, 20)
SCALE = 4  # supersampling for smooth edges


def _font(size: int, bold: bool = True) -> ImageFont.ImageFont:
    names = ["DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial Bold.ttf"] if bold else ["DejaVuSans.ttf", "arial.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _gradient(size: tuple[int, int], a: tuple, b: tuple) -> Image.Image:
    w, h = size
    img = Image.new("RGB", size)
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) * 0.6) + (y / max(h - 1, 1) * 0.4)
            px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return img


def draw_shield(size: int) -> Image.Image:
    s = size * SCALE
    mask = Image.new("L", (s, s), 0)
    d = ImageDraw.Draw(mask)
    pts = [(0.5, 0.04), (0.9, 0.18), (0.9, 0.52), (0.5, 0.96), (0.1, 0.52), (0.1, 0.18)]
    d.polygon([(x * s, y * s) for x, y in pts], fill=255)
    shield = _gradient((s, s), CYAN, PURPLE).convert("RGBA")
    shield.putalpha(mask)
    d = ImageDraw.Draw(shield)
    # envelope
    ex0, ey0, ex1, ey1 = 0.27 * s, 0.30 * s, 0.73 * s, 0.60 * s
    d.rounded_rectangle([ex0, ey0, ex1, ey1], radius=0.03 * s, fill=NAVY + (255,))
    d.line([(ex0, ey0), (0.5 * s, 0.49 * s), (ex1, ey0)], fill=WHITE + (255,), width=int(0.028 * s))
    # check mark
    d.line([(0.40 * s, 0.70 * s), (0.48 * s, 0.77 * s), (0.62 * s, 0.62 * s)], fill=WHITE + (255,), width=int(0.04 * s), joint="curve")
    return shield.resize((size, size), Image.LANCZOS)


def main() -> None:
    ASSETS.mkdir(exist_ok=True)
    icon = draw_shield(128)
    icon.save(ASSETS / "icon.png")

    w, h = 560, 120
    logo = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    logo.alpha_composite(draw_shield(100), (8, 10))
    d = ImageDraw.Draw(logo)
    d.text((124, 22), "EmailGuard", font=_font(46), fill=WHITE + (255,))
    d.text((126, 78), "SECURE. AUTHENTICATE. PROTECT.", font=_font(15, bold=False), fill=CYAN + (255,))
    logo.save(ASSETS / "logo.png")
    print("Wrote", ASSETS / "logo.png", "and", ASSETS / "icon.png")


if __name__ == "__main__":
    main()
