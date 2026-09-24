#!/usr/bin/env python3
"""Gera gui/Aegis.ico — o escudo do Aegis nas cores da casa (build-only).

Offline e deterministico: nenhuma rede, nenhuma dependencia alem de Pillow
(declarada em requirements-build.txt). A geometria segue o SVG do mock
aprovado (gui/web/index.html): polygon do escudo com stroke #2563EB e o
check interno #3B82F6, fundo transparente.

Uso:  python gui/make_icon.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

# Coreas da casa (mesmos tokens do app.css: --cobalt / --cobalt-hi)
COBALT = (37, 99, 235)      # #2563EB
COBALT_HI = (59, 130, 246)  # #3B82F6

# viewBox 0 0 24 24 do mock
SHIELD_TOP = (12.0, 2.0)
SHIELD_RIGHT = (20.0, 5.5)
SHIELD_RIGHT_BELT = (20.0, 10.7)
SHIELD_TIP = (12.0, 22.0)
SHIELD_LEFT_BELT = (4.0, 10.7)
SHIELD_LEFT = (4.0, 5.5)
# curvas cubicas do fundo do escudo (mesmos numbers do path 'c' do SVG)
CURVE_RIGHT = (SHIELD_RIGHT_BELT, (20.0, 15.8), (16.6, 19.6), SHIELD_TIP)
CURVE_LEFT = (SHIELD_TIP, (7.4, 19.6), (4.0, 15.8), SHIELD_LEFT_BELT)

CHECK = [(8.3, 12.2), (10.7, 14.6), (15.7, 9.3)]

SIZES = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
MASTER = 1024  # grande o bastante p/ downsample limpo (LANCZOS)


def _cubic(p0, p1, p2, p3, steps=64):
    """Amostra uma bezier cubica (dominio 0..24 do SVG)."""
    pts = []
    for i in range(1, steps + 1):
        t = i / steps
        mt = 1.0 - t
        x = (mt**3 * p0[0] + 3 * mt**2 * t * p1[0]
             + 3 * mt * t**2 * p2[0] + t**3 * p3[0])
        y = (mt**3 * p0[1] + 3 * mt**2 * t * p1[1]
             + 3 * mt * t**2 * p2[1] + t**3 * p3[1])
        pts.append((x, y))
    return pts


def _shield_outline():
    """Polilinha fechada do escudo: arestas retas + fundos em bezier."""
    pts = [SHIELD_TOP, SHIELD_RIGHT]
    pts += _cubic(*CURVE_RIGHT)
    pts += _cubic(*CURVE_LEFT)
    pts += [SHIELD_LEFT, SHIELD_TOP]  # fecha o poligono
    return pts


def _scaled(pts, k):
    return [(x * k, y * k) for x, y in pts]


def _vgradient(size, top, bottom):
    img = Image.new("RGBA", (size, size))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(size - 1, 1)
        row = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom))
        d.line([(0, y), (size, y)], fill=row + (255,))
    return img


def build_icon():
    k = MASTER / 24.0  # unidades do SVG -> pixels do mestre
    shield_stroke = max(int(round(1.6 * k)), 1)   # stroke-width 1.6 do mock
    check_stroke = max(int(round(1.8 * k)), 1)    # stroke-width 1.8 do mock

    canvas = Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0))

    # Anel do escudo: mascara da polilinha grossa, pintada com gradiente
    # cobalt->cobalt-hi (leitura do stroke solido do mock com vida propria).
    ring = Image.new("L", (MASTER, MASTER), 0)
    ImageDraw.Draw(ring).line(
        _scaled(_shield_outline(), k), fill=255, width=shield_stroke,
        joint="curve")
    canvas = Image.alpha_composite(canvas, Image.composite(
        _vgradient(MASTER, COBALT_HI, COBALT),
        Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0)), ring))

    # Check interno: cobalt-hi solido, pontas arredondadas (linecap round).
    check = Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0))
    dc = ImageDraw.Draw(check)
    pts = _scaled(CHECK, k)
    dc.line(pts, fill=COBALT_HI + (255,), width=check_stroke, joint="curve")
    r = check_stroke / 2.0
    for x, y in pts:  # capa redonda nas tres pontas
        dc.ellipse([x - r, y - r, x + r, y + r], fill=COBALT_HI + (255,))
    canvas = Image.alpha_composite(canvas, check)

    out = Path(__file__).resolve().parent / "Aegis.ico"
    master256 = canvas.resize((256, 256), Image.LANCZOS)
    master256.save(out, format="ICO", sizes=SIZES)
    return out


if __name__ == "__main__":
    path = build_icon()
    probe = Image.open(path)
    print(f"OK: {path} ({path.stat().st_size} bytes)")
    print(f"    formato={probe.format} sizes={sorted(probe.ico.sizes())}")
