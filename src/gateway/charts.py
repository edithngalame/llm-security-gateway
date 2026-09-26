"""Dependency-free SVG charts for backtest reports and the README.

Every chart is a standalone SVG that:
- renders on GitHub (README images), in the HTML report, and in any browser,
- follows the viewer's light/dark setting via an embedded prefers-color-scheme style,
- has native hover tooltips (<title> on each mark) and text labels, so meaning
  never depends on colour alone.

Palette: slots 1-2 of a colour-blind-validated categorical palette.
Blue = catch rate (recall), orange = false-positive rate.
"""

from __future__ import annotations

from html import escape

W = 680  # viewBox width; SVGs scale to their container

STYLE = """<style>
  .bg{fill:#fcfcfb}.t1{fill:#0b0b0b}.t2{fill:#52514e}.grid{stroke:#e1e0d9}
  .s1{fill:#2a78d6;stroke:#2a78d6}.s2{fill:#eb6834;stroke:#eb6834}.ring{stroke:#fcfcfb}
  .l1{fill:none;stroke:#2a78d6}.l2{fill:none;stroke:#eb6834}
  .ref{stroke:#8a8983}
  text{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
  @media (prefers-color-scheme:dark){
    .bg{fill:#1a1a19}.t1{fill:#ffffff}.t2{fill:#c3c2b7}.grid{stroke:#2c2c2a}
    .s1{fill:#3987e5;stroke:#3987e5}.s2{fill:#d95926;stroke:#d95926}.ring{stroke:#1a1a19}
    .l1{stroke:#3987e5}.l2{stroke:#d95926}
    .ref{stroke:#8a8983}
  }
</style>"""


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def _svg(h: int, title: str, subtitle: str, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="100%" '
        f'role="img" aria-label="{escape(title)}">{STYLE}'
        f'<rect class="bg" width="{W}" height="{h}" rx="10"/>'
        f'<text class="t1" x="24" y="34" font-size="17" font-weight="650">{escape(title)}</text>'
        f'<text class="t2" x="24" y="56" font-size="13">{escape(subtitle)}</text>'
        f"{body}</svg>"
    )


def _hbar(x0: float, y: float, w: float, h: float, cls: str, tip: str) -> str:
    """Horizontal bar: square at the baseline, 4px rounded data-end."""
    if w <= 0:
        return f'<rect class="{cls}" x="{x0}" y="{y}" width="1.5" height="{h}"><title>{escape(tip)}</title></rect>'
    r = min(4, w, h / 2)
    d = (f"M{x0},{y} H{x0 + w - r} Q{x0 + w},{y} {x0 + w},{y + r} V{y + h - r} "
         f"Q{x0 + w},{y + h} {x0 + w - r},{y + h} H{x0} Z")
    return f'<path class="{cls}" d="{d}" stroke-width="0"><title>{escape(tip)}</title></path>'


def _x_axis(x0: float, x1: float, y_top: float, y_bot: float) -> str:
    out = []
    for i in range(0, 101, 25):
        x = x0 + (x1 - x0) * i / 100
        out.append(f'<line class="grid" x1="{x}" x2="{x}" y1="{y_top}" y2="{y_bot}" stroke-width="1"/>')
        out.append(f'<text class="t2" x="{x}" y="{y_bot + 16}" font-size="11" text-anchor="middle">{i}%</text>')
    return "".join(out)


def _legend(x: float, y: float, items: list[tuple[str, str]]) -> str:
    out = []
    for cls, label in items:
        out.append(f'<rect class="{cls}" x="{x}" y="{y - 9}" width="10" height="10" rx="2" stroke-width="0"/>')
        out.append(f'<text class="t2" x="{x + 16}" y="{y}" font-size="12">{escape(label)}</text>')
        x += 24 + 7.2 * len(label)
    return "".join(out)


def family_recall(rows: list[tuple[str, float | None, int]], subtitle: str) -> str:
    """rows: (family, recall, n_attacks), drawn weakest first."""
    rows = sorted(rows, key=lambda r: (r[1] or 0, r[0]))
    label_w, top, band, bar = 150, 78, 30, 18
    x0, x1 = 24 + label_w, W - 70
    h = top + band * len(rows) + 44
    body = [_x_axis(x0, x1, top - 6, top + band * len(rows))]
    for i, (fam, rec, n) in enumerate(rows):
        y = top + i * band + (band - bar) / 2
        w = (x1 - x0) * (rec or 0)
        body.append(f'<text class="t1" x="{x0 - 10}" y="{y + 13}" font-size="12" text-anchor="end">'
                    f'{escape(fam.replace("_", " "))}</text>')
        body.append(_hbar(x0, y, w, bar, "s1", f"{fam}: {_pct(rec)} of {n} attacks caught"))
        body.append(f'<text class="t2" x="{x0 + w + 6}" y="{y + 13}" font-size="12">{_pct(rec)}'
                    f'<tspan font-size="11"> ({n})</tspan></text>')
    return _svg(h, "Attacks caught, by attack family", subtitle, "".join(body))


def grouped_rates(groups: list[tuple[str, float | None, float | None]], title: str, subtitle: str) -> str:
    """groups: (name, recall, fpr). Two adjacent bars per group, 2px gap."""
    label_w, top, bar, gap, band = 110, 96, 16, 2, 58
    x0, x1 = 24 + label_w, W - 60
    h = top + band * len(groups) + 36
    body = [_legend(24, 80, [("s1", "attacks caught (recall)"), ("s2", "harmless messages blocked (FPR)")]),
            _x_axis(x0, x1, top - 6, top + band * len(groups) - 10)]
    for i, (name, rec, fpr) in enumerate(groups):
        y = top + i * band
        body.append(f'<text class="t1" x="{x0 - 10}" y="{y + bar + 5}" font-size="12" text-anchor="end">'
                    f'{escape(name)}</text>')
        for j, (val, cls, what) in enumerate(((rec, "s1", "recall"), (fpr, "s2", "false-positive rate"))):
            yy = y + j * (bar + gap)
            w = (x1 - x0) * (val or 0)
            body.append(_hbar(x0, yy, w, bar, cls, f"{name}: {what} {_pct(val)}"))
            body.append(f'<text class="t2" x="{x0 + w + 6}" y="{yy + 12}" font-size="11">{_pct(val)}</text>')
    return _svg(h, title, subtitle, "".join(body))


def threshold_sweep(rows: list[dict], current: float, source: str) -> str:
    """Recall and FPR as the block threshold moves. Both are rates, so one shared axis."""
    top, bottom, left, right = 96, 300, 64, W - 110
    h = bottom + 52
    xs = lambda t: left + (right - left) * t
    ys = lambda v: bottom - (bottom - top) * v
    body = [_legend(24, 80, [("s1", "attacks caught (recall)"), ("s2", "harmless messages blocked (FPR)")])]
    for i in range(0, 101, 25):
        y = ys(i / 100)
        body.append(f'<line class="grid" x1="{left}" x2="{right}" y1="{y}" y2="{y}" stroke-width="1"/>')
        body.append(f'<text class="t2" x="{left - 8}" y="{y + 4}" font-size="11" text-anchor="end">{i}%</text>')
    for t in (0.0, 0.25, 0.5, 0.75, 1.0):
        body.append(f'<text class="t2" x="{xs(t)}" y="{bottom + 18}" font-size="11" text-anchor="middle">{t:.2f}</text>')
    body.append(f'<text class="t2" x="{(left + right) / 2}" y="{bottom + 38}" font-size="12" '
                f'text-anchor="middle">block threshold</text>')
    cx = xs(current)
    body.append(f'<line class="ref" x1="{cx}" x2="{cx}" y1="{top - 4}" y2="{bottom}" stroke-width="1"/>')
    body.append(f'<text class="t2" x="{cx + 5}" y="{top + 8}" font-size="11">current: {current:.2f}</text>')

    for key, cls, name in (("recall", "s1", "recall"), ("fpr", "s2", "FPR")):
        pts = [(xs(r["threshold"]), ys(r[key])) for r in rows if r[key] is not None]
        if not pts:
            continue
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        body.append(f'<polyline class="{cls.replace("s", "l")}" points="{path}" stroke-width="2" '
                    f'stroke-linejoin="round" stroke-linecap="round"/>')
        for r in rows:
            if r[key] is None:
                continue
            body.append(f'<circle class="{cls} ring" cx="{xs(r["threshold"]):.1f}" cy="{ys(r[key]):.1f}" r="4" '
                        f'stroke-width="2"><title>threshold {r["threshold"]:.2f}: {name} {_pct(r[key])}'
                        f'</title></circle>')
    return _svg(h, f"Threshold trade-off: {source} messages",
                "Lower threshold = more attacks caught, but more harmless messages blocked", "".join(body))


def progress(history: list[dict]) -> str:
    """Recall and FPR per release, the 'before/after' evidence across versions."""
    top, bottom, left, right = 96, 280, 64, W - 110
    h = bottom + 44
    n = len(history)
    xs = lambda i: left + (right - left) * (i / (n - 1) if n > 1 else 0.5)
    ys = lambda v: bottom - (bottom - top) * v
    body = [_legend(24, 80, [("s1", "attacks caught (recall)"), ("s2", "harmless messages blocked (FPR)")])]
    for i in range(0, 101, 25):
        y = ys(i / 100)
        body.append(f'<line class="grid" x1="{left}" x2="{right}" y1="{y}" y2="{y}" stroke-width="1"/>')
        body.append(f'<text class="t2" x="{left - 8}" y="{y + 4}" font-size="11" text-anchor="end">{i}%</text>')
    for i, row in enumerate(history):
        body.append(f'<text class="t1" x="{xs(i)}" y="{bottom + 20}" font-size="12" text-anchor="middle">'
                    f'{escape(row["version"])}</text>')
    for key, cls, name in (("recall", "s1", "recall"), ("fpr", "s2", "FPR")):
        pts = [(xs(i), ys(r[key] or 0)) for i, r in enumerate(history)]
        if n > 1:
            path = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
            body.append(f'<polyline class="{cls.replace("s", "l")}" points="{path}" stroke-width="2" '
                        f'stroke-linejoin="round" stroke-linecap="round"/>')
        for (x, y), r in zip(pts, history):
            body.append(f'<circle class="{cls} ring" cx="{x:.1f}" cy="{y:.1f}" r="5" stroke-width="2">'
                        f'<title>{escape(r["version"])}: {name} {_pct(r[key])}</title></circle>')
        ex, ey = pts[-1]
        if key == "fpr":
            ry = ys(history[-1]["recall"] or 0)
            if abs(ey - ry) < 16:
                ey = ry + 16
        body.append(f'<text class="t1" x="{ex + 10}" y="{ey + 4}" font-size="12" font-weight="600">'
                    f'{_pct(history[-1][key])}<tspan class="t2" font-weight="400"> {name}</tspan></text>')
    return _svg(h, "Progress across releases", f"Same evaluation set: {history[-1].get('dataset', '')}",
                "".join(body))
