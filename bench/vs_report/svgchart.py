"""Small hand-written SVG chart kit for vs_report (stdlib only).

Every chart is an inline <svg> with a viewBox, so it scales with the page.
Colours come from CSS custom properties defined by the report page: a series
key K is drawn with class s-K (stroke) or f-K (fill), and the page maps those
to its validated palette, light and dark. Native <title> elements give hover
tooltips without JavaScript; every chart also has a table in the report.
"""

import math
from html import escape

W = 680          # total chart width (viewBox units ~ CSS px at full width)
PANEL_GAP = 28
M_LEFT, M_RIGHT, M_TOP, M_BOTTOM = 58, 14, 30, 44


# ---------------------------------------------------------------- formatting

def fmt_num(v, digits=3):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return '–'
    a = abs(v)
    if a >= 1e9:
        return f'{v / 1e9:.{digits}g}G'
    if a >= 1e6:
        return f'{v / 1e6:.{digits}g}M'
    if a >= 1e4:
        return f'{v / 1e3:.{digits}g}k'
    if a >= 1000:
        return f'{v:,.0f}'
    if a >= 1 or a == 0:
        return f'{v:.{digits}g}'
    return f'{v:.{digits}g}'


def fmt_us(v):
    """A duration given in microseconds."""
    if v is None:
        return '–'
    if v >= 1e6:
        return f'{v / 1e6:.3g} s'
    if v >= 1e3:
        return f'{v / 1e3:.3g} ms'
    if v >= 1:
        return f'{v:.3g} µs'
    return f'{v * 1e3:.3g} ns'


def fmt_ns(v):
    """A duration given in nanoseconds."""
    return fmt_us(v / 1000.0) if v is not None else '–'


# ---------------------------------------------------------------- scales

class Linear:
    def __init__(self, d0, d1, r0, r1):
        if d1 == d0:
            d1 = d0 + 1
        self.d0, self.d1, self.r0, self.r1 = d0, d1, r0, r1

    def __call__(self, v):
        return self.r0 + (v - self.d0) / (self.d1 - self.d0) * (self.r1 - self.r0)

    def ticks(self, n=5):
        span = self.d1 - self.d0
        raw = span / max(n, 1)
        mag = 10 ** math.floor(math.log10(raw))
        step = min((m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw), default=raw)
        t = math.ceil(self.d0 / step - 1e-9) * step
        out = []
        while t <= self.d1 + 1e-9 * span:
            out.append(round(t, 12))
            t += step
        return out


class Log:
    def __init__(self, d0, d1, r0, r1):
        d0 = max(d0, 1e-12)
        d1 = max(d1, d0 * 1.0001)
        self.l0, self.l1 = math.log10(d0), math.log10(d1)
        self.d0, self.d1, self.r0, self.r1 = d0, d1, r0, r1

    def __call__(self, v):
        v = max(v, self.d0)
        return self.r0 + (math.log10(v) - self.l0) / (self.l1 - self.l0) * (self.r1 - self.r0)

    def ticks(self, n=None):
        lo, hi = math.floor(self.l0 + 1e-9), math.ceil(self.l1 - 1e-9)
        mults = (1,) if hi - lo > 3 else ((1, 2, 5) if hi - lo > 1 else (1, 2, 3, 5))
        out = []
        for e in range(lo, hi + 1):
            for m in mults:
                v = m * 10 ** e
                if self.d0 * 0.999 <= v <= self.d1 * 1.001:
                    out.append(v)
        return out


def log_domain(values, pad=1.15):
    vals = [v for v in values if v is not None and v > 0]
    if not vals:
        return 1, 10
    lo, hi = min(vals), max(vals)
    return lo / pad, hi * pad


# ---------------------------------------------------------------- primitives

def _t(x, y, s, cls='lbl', anchor='start', extra=''):
    return (f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}" text-anchor="{anchor}"{extra}>'
            f'{escape(str(s))}</text>')


def _svg(width, height, body, label):
    return (f'<svg class="chart" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
            f'aria-label="{escape(label)}" xmlns="http://www.w3.org/2000/svg">'
            + ''.join(body) + '</svg>')


def _axes(xs, ys, x0, x1, y0, y1, xfmt, yfmt, xlabel, ylabel, title, xticks=None, yticks=None):
    """Gridlines, baseline, tick labels, axis titles and the panel title."""
    out = ['<g class="ax">']
    for v in (yticks if yticks is not None else ys.ticks()):
        y = ys(v)
        out.append(f'<line class="grid" x1="{x0:.1f}" x2="{x1:.1f}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(_t(x0 - 6, y + 3.5, yfmt(v), 'tick', 'end'))
    for v in (xticks if xticks is not None else xs.ticks()):
        x = xs(v)
        out.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{y0:.1f}" y2="{y1:.1f}"/>')
        out.append(_t(x, y0 + 15, xfmt(v), 'tick', 'middle'))
    out.append(f'<line class="base" x1="{x0:.1f}" x2="{x1:.1f}" y1="{y0:.1f}" y2="{y0:.1f}"/>')
    if xlabel:
        out.append(_t((x0 + x1) / 2, y0 + 33, xlabel, 'axt', 'middle'))
    if ylabel:
        out.append(f'<text class="axt" text-anchor="middle" transform="translate({x0 - 44:.1f},'
                   f'{(y0 + y1) / 2:.1f}) rotate(-90)">{escape(ylabel)}</text>')
    if title:
        out.append(_t(x0, y1 - 12, title, 'ptitle'))
    out.append('</g>')
    return out


def _panel_boxes(n, height):
    pw = (W - PANEL_GAP * (n - 1)) / n
    return [(i * (pw + PANEL_GAP), pw) for i in range(n)]


def _path(points):
    return 'M' + 'L'.join(f'{x:.1f},{y:.1f}' for x, y in points)


def legend(items):
    """HTML legend: items = [(key, label, kind)] with kind 'line', 'dot' or 'bar'."""
    parts = []
    for key, label, kind in items:
        parts.append(f'<span class="key"><svg width="18" height="10" aria-hidden="true">'
                     + (f'<line x1="1" x2="17" y1="5" y2="5" class="s-{key}" stroke-width="2.5"/>'
                        if kind == 'line' else
                        f'<line x1="1" x2="17" y1="5" y2="5" class="s-{key}" stroke-width="2.5" stroke-dasharray="4 3"/>'
                        if kind == 'dash' else
                        f'<circle cx="9" cy="5" r="4" class="f-{key}"/>' if kind == 'dot' else
                        f'<rect x="3" y="0" width="12" height="10" rx="2" class="f-{key}"/>')
                     + f'</svg>{escape(label)}</span>')
    return '<div class="legend">' + ''.join(parts) + '</div>'


# ---------------------------------------------------------------- chart forms

def ecdf(panels, xfmt, xlabel, height=300, label='ECDF', log=True, direct_labels=True):
    """panels: [{'title', 'series': [{'key', 'label', 'values' (sorted or not)}]}].
    Shared x domain across panels so they compare directly."""
    allv = [v for p in panels for s in p['series'] for v in s['values']]
    if log:
        d0, d1 = log_domain(allv)
    else:
        d0, d1 = min(allv), max(allv)
    body = []
    for (ox, pw), p in zip(_panel_boxes(len(panels), height), panels):
        x0, x1 = ox + M_LEFT, ox + pw - M_RIGHT
        y0, y1 = height - M_BOTTOM, M_TOP
        xs = (Log if log else Linear)(d0, d1, x0, x1)
        ys = Linear(0, 1, y0, y1)
        body += _axes(xs, ys, x0, x1, y0, y1, xfmt, lambda v: f'{v:g}', xlabel,
                      'fraction of queries ≤ x', p['title'], yticks=[0, 0.25, 0.5, 0.75, 1])
        labels = []
        for s in p['series']:
            vals = sorted(v for v in s['values'] if v is not None)
            n = len(vals)
            if not n:
                continue
            pts = [(xs(vals[0]), ys(0))]
            # thin to at most ~600 steps for file size
            stride = max(1, n // 600)
            for i in range(0, n, stride):
                x = xs(vals[i])
                pts.append((x, pts[-1][1]))
                pts.append((x, ys((i + 1) / n)))
            pts.append((xs(vals[-1]), ys(1)))
            med = vals[n // 2]
            body.append(f'<path class="line s-{s["key"]}" d="{_path(pts)}">'
                        f'<title>{escape(s["label"])}: n {n}, median {xfmt(med)}, '
                        f'max {xfmt(vals[-1])}</title></path>')
            labels.append((xs(med), s['label']))
        if direct_labels:
            labels.sort()
            ok = all(b[0] - a[0] > 70 for a, b in zip(labels, labels[1:]))
            if ok:
                for x, lab in labels:
                    body.append(_t(x + 5, ys(0.5) - 5, lab, 'dlbl'))
    return _svg(W, height, body, label)


def boxes(groups, xfmt, xlabel, label='box summary', log=True):
    """Horizontal box summaries. groups: [{'title', 'rows': [{'key', 'label', 'p01',
    'p25', 'median', 'p75', 'p99', 'mean', 'min', 'max'}]}]. Whiskers p1–p99,
    box p25–p75, a median tick and a mean dot; min and max as small ticks."""
    rows_n = sum(len(g['rows']) for g in groups)
    row_h, g_h = 26, 22
    height = M_TOP + rows_n * row_h + len(groups) * g_h + M_BOTTOM - 10
    allv = [r[k] for g in groups for r in g['rows'] for k in ('min', 'max', 'p01', 'p99')]
    d0, d1 = log_domain(allv) if log else (min(allv), max(allv))
    x0, x1 = 128, W - M_RIGHT
    y0, y1 = height - M_BOTTOM + 10, M_TOP - 10
    xs = (Log if log else Linear)(d0, d1, x0, x1)
    body = ['<g class="ax">']
    for v in xs.ticks():
        x = xs(v)
        body.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{y0:.1f}" y2="{y1:.1f}"/>')
        body.append(_t(x, y0 + 15, xfmt(v), 'tick', 'middle'))
    body.append(_t((x0 + x1) / 2, y0 + 33, xlabel, 'axt', 'middle'))
    body.append('</g>')
    y = M_TOP
    for g in groups:
        body.append(_t(4, y + 4, g['title'], 'ptitle'))
        y += g_h
        for r in g['rows']:
            cy = y + row_h / 2 - 6
            k = r['key']
            tip = (f'{g["title"]} / {r["label"]}: min {xfmt(r["min"])}, p1 {xfmt(r["p01"])}, '
                   f'p25 {xfmt(r["p25"])}, median {xfmt(r["median"])}, mean {xfmt(r["mean"])}, '
                   f'p75 {xfmt(r["p75"])}, p99 {xfmt(r["p99"])}, max {xfmt(r["max"])}')
            body.append(f'<g><title>{escape(tip)}</title>')
            body.append(_t(x0 - 8, cy + 4, r['label'], 'lbl', 'end'))
            body.append(f'<line class="whisk s-{k}" x1="{xs(r["p01"]):.1f}" x2="{xs(r["p99"]):.1f}" '
                        f'y1="{cy:.1f}" y2="{cy:.1f}"/>')
            for v in (r['min'], r['max']):
                body.append(f'<line class="whisk s-{k}" x1="{xs(v):.1f}" x2="{xs(v):.1f}" '
                            f'y1="{cy - 3:.1f}" y2="{cy + 3:.1f}"/>')
            bx0, bx1 = xs(r['p25']), xs(r['p75'])
            body.append(f'<rect class="box f-{k}" x="{bx0:.1f}" y="{cy - 7:.1f}" '
                        f'width="{max(bx1 - bx0, 1.5):.1f}" height="14" rx="3"/>')
            body.append(f'<line class="medtick" x1="{xs(r["median"]):.1f}" x2="{xs(r["median"]):.1f}" '
                        f'y1="{cy - 7:.1f}" y2="{cy + 7:.1f}"/>')
            body.append(f'<circle class="meandot f-{k}" cx="{xs(r["mean"]):.1f}" cy="{cy:.1f}" r="4"/>')
            body.append('</g>')
            y += row_h
    return _svg(W, height, body, label)


def _y_domain(panels):
    ysv = [y for p in panels for s in p['series'] for _, y in s['points'] if y is not None]
    ysv += [v for p in panels for bd in p.get('bands', []) for _, a, b in bd['points'] for v in (a, b)
            if v is not None]
    lo, hi = min(ysv), max(ysv)
    pad = (hi - lo) * 0.05 or 1
    return (min(0, lo - pad) if lo >= 0 else lo - pad, hi + pad)


def lines(panels, xfmt, yfmt, xlabel, ylabel, height=300, log_x=False, y_domain=None,
          x_domain=None, refs=(), label='line chart', share_y=True, xticks=None, log_y=False):
    """panels: [{'title', 'series': [{'key', 'label', 'points': [(x, y)], 'dash': bool,
    'marks': [(x, y, tip)]}], 'bands': [{'key', 'points': [(x, ylo, yhi)]}]}]; refs:
    [(y, text)] horizontal reference lines. share_y=False gives each panel its own y
    scale (say so in the caption). xticks: explicit tick positions; log_y: log y axis
    (give y_domain)."""
    xsv = [x for p in panels for s in p['series'] for x, _ in s['points']]
    if x_domain is None:
        x_domain = (min(xsv), max(xsv))
    body = []
    for (ox, pw), p in zip(_panel_boxes(len(panels), height), panels):
        x0, x1 = ox + M_LEFT, ox + pw - M_RIGHT
        y0, y1 = height - M_BOTTOM, M_TOP
        xs = (Log if log_x else Linear)(x_domain[0], x_domain[1], x0, x1)
        yd = y_domain or _y_domain(panels if share_y else [p])
        ys = (Log if log_y else Linear)(yd[0], yd[1], y0, y1)
        body += _axes(xs, ys, x0, x1, y0, y1, xfmt, yfmt, xlabel, ylabel, p['title'], xticks=xticks)
        for bd in p.get('bands', []):
            up = [(xs(x), ys(b)) for x, a, b in bd['points']]
            dn = [(xs(x), ys(a)) for x, a, b in reversed(bd['points'])]
            body.append(f'<path class="band f-{bd["key"]}" d="{_path(up + dn)}Z"/>')
        for yv, txt in refs:
            if yd[0] <= yv <= yd[1]:
                y = ys(yv)
                body.append(f'<line class="ref" x1="{x0:.1f}" x2="{x1:.1f}" y1="{y:.1f}" y2="{y:.1f}"/>')
                body.append(_t(x0 + 4, y - 4, txt, 'reflbl', 'start'))
        for s in p['series']:
            pts = [(xs(x), ys(y)) for x, y in s['points'] if y is not None]
            if not pts:
                continue
            dash = ' dash' if s.get('dash') else ''
            body.append(f'<path class="line s-{s["key"]}{dash}" d="{_path(pts)}">'
                        f'<title>{escape(s["label"])}</title></path>')
            for x, y, tip in s.get('marks', []):
                body.append(f'<circle class="dot f-{s["key"]}" cx="{xs(x):.1f}" cy="{ys(y):.1f}" r="4">'
                            f'<title>{escape(tip)}</title></circle>')
    return _svg(W, height, body, label)


def hist(panels, xfmt, xlabel, ylabel='queries', height=260, label='histogram', log_x=False,
         x_domain=None, log_y=False, share_x=True, yfmt=fmt_num):
    """panels: [{'title', 'key', 'bins': [(lo, hi, count)]}]; columns with a 2px surface
    gap. share_x=False: each panel's x domain from its own bins (x_domain ignored).
    log_y: bars rise from the bottom of a log axis (to show small tails)."""
    allc = [c for p in panels for _, _, c in p['bins'] if c > 0] or [1]
    ymax = max(allc)
    body = []
    for (ox, pw), p in zip(_panel_boxes(len(panels), height), panels):
        x0, x1 = ox + M_LEFT, ox + pw - M_RIGHT
        y0, y1 = height - M_BOTTOM, M_TOP
        bins = p['bins'] if not share_x else [b for q in panels for b in q['bins']]
        xd = x_domain if (x_domain and share_x) else (min(b[0] for b in bins), max(b[1] for b in bins))
        xs = (Log if log_x else Linear)(xd[0], xd[1], x0, x1)
        if log_y:
            ys = Log(10 ** math.floor(math.log10(min(allc))), ymax * 1.3, y0, y1)
        else:
            ys = Linear(0, ymax * 1.05, y0, y1)
        body += _axes(xs, ys, x0, x1, y0, y1, xfmt, yfmt, xlabel, ylabel, p['title'])
        for lo, hi, c in p['bins']:
            if c <= 0:
                continue
            bx0, bx1 = xs(lo) + 1, xs(hi) - 1
            w = max(bx1 - bx0, 1)
            h = y0 - ys(c)
            r = min(3, w / 2, h)
            # rounded data end, square at the baseline
            d = (f'M{bx0:.1f},{y0:.1f}V{y0 - h + r:.1f}Q{bx0:.1f},{y0 - h:.1f} {bx0 + r:.1f},{y0 - h:.1f}'
                 f'H{bx0 + w - r:.1f}Q{bx0 + w:.1f},{y0 - h:.1f} {bx0 + w:.1f},{y0 - h + r:.1f}V{y0:.1f}Z')
            body.append(f'<path class="bar f-{p["key"]}" d="{d}"><title>{xfmt(lo)} – {xfmt(hi)}: '
                        f'{c:,}</title></path>')
    return _svg(W, height, body, label)


def scatter(panels, xfmt, yfmt, xlabel, ylabel, height=320, log_x=True, log_y=True,
            label='scatter', x_domain=None, y_domain=None, fits=()):
    """panels: [{'title', 'series': [{'key', 'label', 'points': [(x, y, tip)]}]}]."""
    xsv = [x for p in panels for s in p['series'] for x, _, _ in s['points']]
    ysv = [y for p in panels for s in p['series'] for _, y, _ in s['points']]
    if x_domain is None:
        x_domain = log_domain(xsv) if log_x else (min(xsv), max(xsv))
    if y_domain is None:
        y_domain = log_domain(ysv) if log_y else (min(ysv), max(ysv))
    body = []
    for (ox, pw), p in zip(_panel_boxes(len(panels), height), panels):
        x0, x1 = ox + M_LEFT, ox + pw - M_RIGHT
        y0, y1 = height - M_BOTTOM, M_TOP
        xs = (Log if log_x else Linear)(x_domain[0], x_domain[1], x0, x1)
        ys = (Log if log_y else Linear)(y_domain[0], y_domain[1], y0, y1)
        body += _axes(xs, ys, x0, x1, y0, y1, xfmt, yfmt, xlabel, ylabel, p['title'])
        for s in p['series']:
            body.append(f'<g class="pts f-{s["key"]}">')
            for x, y, tip in s['points']:
                if (log_x and x <= 0) or (log_y and y <= 0):
                    continue
                body.append(f'<circle cx="{xs(x):.1f}" cy="{ys(y):.1f}" r="3"><title>{escape(tip)}'
                            f'</title></circle>')
            body.append('</g>')
    return _svg(W, height, body, label)
