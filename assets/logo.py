"""Draw the grounds logo: a mound of coffee grounds, poured onto a dark roast.

  python3 assets/logo.py   # writes assets/grounds.svg and assets/grounds-wordmark.svg
"""
import math
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROAST = ["#2b1a10", "#3d2415", "#55331d", "#6e4426", "#8a5731", "#a86d3e", "#c99461"]


def grain(rng, x, y, scale, shade):
    rx = rng.uniform(2.6, 6.0) * scale
    ry = rx * rng.uniform(0.45, 0.8)
    a = rng.uniform(0, 180)
    c = ROAST[max(0, min(len(ROAST) - 1, shade))]
    return (f'<ellipse cx="{x:.0f}" cy="{y:.0f}" rx="{rx:.1f}" ry="{ry:.1f}" '
            f'transform="rotate({a:.0f} {x:.0f} {y:.0f})" fill="{c}"/>')


def mark(rng):
    out = []
    base, peak, half = 392, 236, 165
    # the mound: a soft bell, packed densest at the base, lit from the top left
    for _ in range(1500):
        x = rng.gauss(256, 74)
        if abs(x - 256) > half:
            continue
        top = base - (base - peak) * math.exp(-((x - 256) / 92) ** 2)
        y = rng.uniform(top, base)
        if rng.random() < 0.18 and y > top + 18:
            continue
        depth = (y - top) / max(1, base - top)
        light = (256 - x) / half * 0.9 + (1 - depth) * 1.6
        shade = int(round(1 + light * 2 + rng.uniform(-1.2, 1.2)))
        out.append(grain(rng, x, y, 1.0 - depth * 0.25, shade))
    out.sort(key=lambda e: float(e.split('cy="')[1].split('"')[0]))
    # the pour: a thin stream falling onto the peak, loosening as it drops
    stream = []
    for i in range(46):
        t = i / 45
        y = 112 + t * (peak - 112)
        x = 256 + rng.gauss(0, 2 + t * 5) + math.sin(t * 5) * 3
        stream.append(grain(rng, x, y, 0.8 + t * 0.3, int(3 + rng.uniform(-1, 2))))
    # a few grains bouncing off the slopes
    for _ in range(26):
        side = rng.choice([-1, 1])
        x = 256 + side * rng.uniform(40, 150)
        y = base - rng.uniform(4, 60) * math.exp(-((x - 256) / 120) ** 2) - rng.uniform(0, 30)
        stream.append(grain(rng, x, y, 0.8, int(3 + rng.uniform(-1, 2))))
    return out, stream


def badge(rng):
    grains, stream = mark(rng)
    return f'''<defs>
    <radialGradient id="bg" cx="50%" cy="38%" r="75%">
      <stop offset="0" stop-color="#3a2618"/>
      <stop offset="0.6" stop-color="#1f140d"/>
      <stop offset="1" stop-color="#120b07"/>
    </radialGradient>
    <radialGradient id="glow" cx="50%" cy="50%" r="50%">
      <stop offset="0" stop-color="#e0a867" stop-opacity="0.28"/>
      <stop offset="1" stop-color="#e0a867" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="rim" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#d9a36a" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#d9a36a" stop-opacity="0.05"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="496" height="496" rx="116" fill="url(#bg)"/>
  <rect x="8" y="8" width="496" height="496" rx="116" fill="none" stroke="url(#rim)" stroke-width="3"/>
  <ellipse cx="256" cy="360" rx="230" ry="150" fill="url(#glow)"/>
  <ellipse cx="256" cy="400" rx="170" ry="16" fill="#000" opacity="0.45"/>
  <g>{"".join(grains)}</g>
  <g opacity="0.95">{"".join(stream)}</g>'''


def main():
    body = badge(random.Random(7))
    (HERE / "grounds.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">\n  {body}\n</svg>\n')
    (HERE / "grounds-wordmark.svg").write_text(
        f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1240 512" width="1240" height="512">
  <g>{body}</g>
  <text x="572" y="318" font-family="'Fraunces', 'Playfair Display', Georgia, serif" font-size="176"
    font-weight="600" letter-spacing="2" fill="#8a5731">grounds</text>
  <text x="580" y="382" font-family="'Inter', 'Helvetica Neue', Arial, sans-serif" font-size="34"
    letter-spacing="10" fill="#c99461">PROVEN BEND PACKAGES</text>
</svg>
''')
    print("wrote assets/grounds.svg, assets/grounds-wordmark.svg")


main()
