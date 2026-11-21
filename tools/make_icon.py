"""Draw the B-2FA icon (black tile, white "2", one red bar) into packaging\\b2fa.ico.

    python -I tools\\make_icon.py

Needs Pillow, only at build time (the app itself does not use it).
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "packaging" / "b2fa.ico"
SIZES = [16, 24, 32, 48, 64, 128, 256]
FONTS = [r"C:\Windows\Fonts\consolab.ttf", r"C:\Windows\Fonts\arialbd.ttf"]


def draw(size: int) -> Image.Image:
    # drawn at 4x then reduced, so small sizes stay smooth
    k = 4
    s = size * k
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.2), fill=(17, 17, 17, 255))
    font = None
    for path in FONTS:
        try:
            font = ImageFont.truetype(path, int(s * 0.68))
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default()
    box = d.textbbox((0, 0), "2", font=font)
    w, h = box[2] - box[0], box[3] - box[1]
    d.text(((s - w) / 2 - box[0], (s - h) / 2 - box[1] - s * 0.04), "2", font=font, fill=(255, 255, 255, 255))
    # the single red: a short bar under the digit (the countdown)
    bar_w, bar_h = s * 0.42, max(k * 2, s * 0.07)
    x0 = (s - bar_w) / 2
    y0 = s * 0.86 - bar_h
    d.rectangle((x0, y0, x0 + bar_w, y0 + bar_h), fill=(225, 6, 0, 255))
    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    big = draw(256)
    big.save(OUT, format="ICO", sizes=[(n, n) for n in SIZES])
    print("written", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
