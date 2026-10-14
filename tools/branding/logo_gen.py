"""Generate the disdetta logo: a Bitnami-style container under a magnifying glass, struck through.

Same system as the trasloco logo (flat isometric box, ink/paper swap for dark mode, one accent).
Usage: python tools/branding/logo_gen.py docs/assets [preview.html]
The optional preview page must not be committed.
"""
import base64, math, os, sys

OUT = sys.argv[1]
INK, PAPER, BOX, SLASH = "#1B2433", "#F6F3EC", "#2F7FE8", "#E5484D"
L = 46.0
C30, S30 = math.cos(math.radians(30)), math.sin(math.radians(30))
DX, DY = L * C30, L * S30
GAP = 3.4
LENS_R, RING_W = 21.0, 7.0


def pts(*ps):
    return " ".join(f"{x:.2f},{y:.2f}" for x, y in ps)


def mark(cx, top, ink, uid):
    A, B, D, E = (cx, top), (cx - DX, top + DY), (cx + DX, top + DY), (cx, top + 2 * DY)
    Bb, Eb, Db = (B[0], B[1] + L), (E[0], E[1] + L), (D[0], D[1] + L)
    # container ridges on the front-left face
    ridges = ""
    for t in (0.25, 0.5, 0.75):
        x = B[0] + DX * t
        y0 = B[1] + DY * t + 10
        ridges += f'<line x1="{x:.2f}" y1="{y0:.2f}" x2="{x:.2f}" y2="{y0 + 26:.2f}"/>'
    lc = (cx + 34, top + 68)  # lens centre
    mask = (
        f'<mask id="m{uid}" maskUnits="userSpaceOnUse"><rect x="-20" y="-20" width="200" height="200" fill="#fff"/>'
        f'<g fill="none" stroke="#000" stroke-width="{GAP}" stroke-linecap="square">'
        f'<polyline points="{pts(B, E, D)}"/><line x1="{E[0]:.2f}" y1="{E[1]:.2f}" x2="{Eb[0]:.2f}" y2="{Eb[1]:.2f}"/></g>'
        f'<g stroke="#000" stroke-width="4" stroke-linecap="round">{ridges}</g>'
        f'<circle cx="{lc[0]:.2f}" cy="{lc[1]:.2f}" r="{LENS_R + RING_W / 2 + GAP:.2f}" fill="#000"/>'
        f"</mask>"
    )
    box = (
        f'<g mask="url(#m{uid})"><g fill="{BOX}"><polygon points="{pts(A, D, E, B)}"/>'
        f'<polygon points="{pts(B, E, Eb, Bb)}"/><polygon points="{pts(E, D, Db, Eb)}"/></g></g>'
    )
    k = math.sqrt(0.5)
    h0 = (lc[0] + (LENS_R + RING_W / 2) * k, lc[1] + (LENS_R + RING_W / 2) * k)
    h1 = (h0[0] + 15, h0[1] + 15)
    s = LENS_R - 7
    glass = (
        f'<line x1="{lc[0] - s * k:.2f}" y1="{lc[1] - s * k:.2f}" x2="{lc[0] + s * k:.2f}" y2="{lc[1] + s * k:.2f}" '
        f'stroke="{SLASH}" stroke-width="6" stroke-linecap="round"/>'
        f'<circle cx="{lc[0]:.2f}" cy="{lc[1]:.2f}" r="{LENS_R:.2f}" fill="none" stroke="{ink}" stroke-width="{RING_W}"/>'
        f'<line x1="{h0[0]:.2f}" y1="{h0[1]:.2f}" x2="{h1[0]:.2f}" y2="{h1[1]:.2f}" stroke="{ink}" stroke-width="10" stroke-linecap="round"/>'
    )
    return f"<defs>{mask}</defs>{box}{glass}"


def svg(w, h, inner):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="disdetta"><title>disdetta</title>{inner}</svg>\n'


WORD = (
    "font-family=\"'JetBrains Mono','SFMono-Regular',Menlo,Consolas,'Liberation Mono',monospace\" "
    'font-size="54" font-weight="700" letter-spacing="-1.5"'
)
files = {
    "disdetta-icon.svg": svg(128, 128, mark(52, 14, INK, "il")),
    "disdetta-icon-dark.svg": svg(128, 128, mark(52, 14, PAPER, "id")),
    "disdetta-favicon.svg": svg(128, 128, mark(52, 14, INK, "fl")),
    "disdetta-logo.svg": svg(440, 128, mark(52, 14, INK, "ll") + f'<text x="150" y="86" fill="{INK}" {WORD}>disdetta</text>'),
    "disdetta-logo-dark.svg": svg(440, 128, mark(52, 14, PAPER, "ld") + f'<text x="150" y="86" fill="{PAPER}" {WORD}>disdetta</text>'),
}
os.makedirs(OUT, exist_ok=True)
for n, c in files.items():
    with open(os.path.join(OUT, n), "w", encoding="utf-8", newline="\n") as f:
        f.write(c)


def img(c, h):
    return f'<img style="height:{h}px" src="data:image/svg+xml;base64,{base64.b64encode(c.encode()).decode()}">'


def panel(bg, items):
    return f'<div style="background:{bg};padding:22px;border-radius:12px;display:flex;align-items:flex-end;gap:22px;flex-wrap:wrap">{items}</div>'


i_l, i_d, fav = files["disdetta-icon.svg"], files["disdetta-icon-dark.svg"], files["disdetta-favicon.svg"]
html = (
    "<!doctype html><meta charset=utf-8><title>disdetta concept</title>"
    '<body style="margin:0;padding:22px;background:#e6e3dc;display:grid;gap:14px">'
    + panel("#fff", img(i_l, 160) + img(i_l, 64) + img(i_l, 32) + img(fav, 16))
    + panel("#0d1117", img(i_d, 160) + img(i_d, 64) + img(i_d, 32))
    + panel("#fff", img(files["disdetta-logo.svg"], 96) + img(files["disdetta-logo.svg"], 40))
    + panel("#0d1117", img(files["disdetta-logo-dark.svg"], 96) + img(files["disdetta-logo-dark.svg"], 40))
    + "</body>"
)
if len(sys.argv) > 2:
    open(sys.argv[2], "w", encoding="utf-8").write(html)
print("ok")
