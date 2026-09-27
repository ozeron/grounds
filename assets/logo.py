"""Draw the grounds logo: a mound of grounds on a hex grid, with grains falling in.

  python3 assets/logo.py   # writes assets/grounds.svg and assets/grounds-wordmark.svg

Flat and transparent, so it reads on light and dark backgrounds alike.
"""
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
# light crema at the top of the mound down to dark roast at its foot
ROAST = ["#d9a066", "#c4864c", "#a86b3a", "#8a522b", "#6b3d21"]
STEP = 24       # grid spacing
BASE, W, H = 404, 180, 150   # the mound: foot line, half width, height


def jitter(i, j):
    # a fixed per-grain wobble, so every run draws the same logo
    return ((i * 73856093) ^ (j * 19349663)) % 1000 / 1000


def mound():
    out = []
    row = 0
    while True:
        y = BASE - row * STEP * math.sqrt(3) / 2
        if y < BASE - H:
            break
        off = (row % 2) * STEP / 2
        for i in range(-12, 13):
            x = 256 + i * STEP + off
            top = BASE - H * (1 - ((x - 256) / W) ** 2)
            if abs(x - 256) > W or y < top:
                continue
            k = jitter(i, row)
            band = min(len(ROAST) - 1, int((BASE - y) / H * len(ROAST)))
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{8.5 + 2.5 * k:.1f}" fill="{ROAST[len(ROAST) - 1 - band]}"/>')
        row += 1
    return out


def falling():
    # grains dropping onto the peak, smaller as they rise
    out = []
    for k, (dy, r) in enumerate([(26, 8), (58, 6.5), (86, 5), (110, 3.5)]):
        out.append(f'<circle cx="{256 + (k % 2) * 4 - 2}" cy="{BASE - H - dy:.1f}" r="{r}" fill="{ROAST[0]}" opacity="{1 - k * 0.2:.2f}"/>')
    return out


def svg(w, h, body, box=None):
    box = box or f"0 0 {w} {h}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{box}" width="{w}" height="{h}">\n'
            + "\n".join("  " + b for b in body) + "\n</svg>\n")


def main():
    mark = mound() + falling()
    (HERE / "grounds.svg").write_text(svg(512, 512, mark, "56 76 400 400"))
    word = ['<g transform="translate(-40 -60) scale(0.62)">'] + mark + ['</g>',
            '<text x="300" y="196" font-family="ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif" '
            'font-size="120" font-weight="700" letter-spacing="-3" fill="#8a522b">grounds</text>']
    (HERE / "grounds-wordmark.svg").write_text(svg(800, 256, word))


if __name__ == "__main__":
    main()
