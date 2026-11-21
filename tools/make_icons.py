"""Generuje ikony PWA (PNG) – wymagane przez Chrome/Android do instalacji na ekranie głównym.

Uruchomienie:  python tools/make_icons.py
Tworzy w web/icons/: icon-192.png, icon-512.png, maskable-512.png (z marginesem bezpiecznym), apple-touch-icon.png,
badge-96.png (monochromatyczna ikonka paska powiadomień Androida).
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "web" / "icons"
RED, WHITE = (211, 58, 44, 255), (255, 255, 255, 255)
SS = 4  # supersampling dla gładkich krawędzi


def radar(size: int, scale: float = 1.0, bg: bool = True, rounded: bool = True, fg=WHITE) -> Image.Image:
    s = size * SS
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    if bg:
        if rounded:
            d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.19), fill=RED)
        else:
            d.rectangle([0, 0, s - 1, s - 1], fill=RED)
    c, w = s / 2, max(1, int(s * 0.055 * scale))
    for r in (0.29, 0.137):
        rr = s * r * scale
        d.ellipse([c - rr, c - rr, c + rr, c + rr], outline=fg, width=w)
    d.line([c, c, c + s * 0.242 * scale, c - s * 0.207 * scale], fill=fg, width=w)
    dot = s * 0.035 * scale
    d.ellipse([c - dot, c - dot, c + dot, c + dot], fill=fg)
    return im.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    radar(192).save(OUT / "icon-192.png")
    radar(512).save(OUT / "icon-512.png")
    # maskable: pełne tło (system sam przycina kształt), motyw w strefie bezpiecznej (~80%)
    radar(512, scale=0.78, rounded=False).save(OUT / "maskable-512.png")
    radar(180, rounded=False).convert("RGB").save(OUT / "apple-touch-icon.png")
    radar(96, scale=1.25, bg=False).save(OUT / "badge-96.png")
    print("Zapisano ikony w", OUT)


if __name__ == "__main__":
    main()
