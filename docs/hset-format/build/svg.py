"""Tiny SVG toolkit for the hset documentation figures.

Everything is emitted as inline SVG with a viewBox, so the figures scale with
the text column and inherit the page's fonts through CSS.
"""
import math
from html import escape

# palette (restrained, Tufte-ish)
INK = '#222'
INK2 = '#555'
GRAY = '#888'
LIGHT = '#c8c4b8'
RULE = '#b8b4a8'
PAPER = '#fffff8'

# field fills
F_TYPE = '#ece6d4'    # chunk types, magic, names
F_NUM = '#dbe6ee'     # integers, lengths, offsets
F_DATA = '#f3f1ea'    # payload bytes
F_HASH = '#e3ead9'    # hash / row bytes
F_PAD = '#f9f8f3'     # padding / reserved
F_HI = '#f6d9c9'      # highlight
F_HI2 = '#f0e6a6'     # second highlight

# semantic colors
Q_RED = '#b5473a'     # query / needle
S_BLUE = '#3d6b8e'    # stored rows / structure
G_GREEN = '#5a8a5b'   # ok / kept / left input
O_ORANGE = '#c98a2b'  # right input / second series
P_PURPLE = '#7b5c9e'


def fmt(v):
    if isinstance(v, float):
        s = ('%.3f' % v).rstrip('0').rstrip('.')
        return s if s not in ('', '-0') else '0'
    return str(v)


class SVG:
    def __init__(self, w, h, cls='fig', pad=0):
        self.w, self.h = w, h
        self.parts = []
        self.cls = cls
        self.defs = set()
        self.pad = pad

    # --- primitives -----------------------------------------------------
    def add(self, s):
        self.parts.append(s)

    def rect(self, x, y, w, h, fill='none', stroke=None, sw=1, rx=0, dash=None, opacity=None, cls=None, title=None):
        a = f'<rect x="{fmt(x)}" y="{fmt(y)}" width="{fmt(w)}" height="{fmt(h)}" fill="{fill}"'
        if stroke: a += f' stroke="{stroke}" stroke-width="{fmt(sw)}"'
        if rx: a += f' rx="{fmt(rx)}"'
        if dash: a += f' stroke-dasharray="{dash}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if cls: a += f' class="{cls}"'
        if title:
            a += f'><title>{escape(title)}</title></rect>'
        else:
            a += '/>'
        self.add(a)

    def line(self, x1, y1, x2, y2, stroke=INK, sw=1, dash=None, arrow=False, arrow_start=False, opacity=None, cap=None):
        a = f'<line x1="{fmt(x1)}" y1="{fmt(y1)}" x2="{fmt(x2)}" y2="{fmt(y2)}" stroke="{stroke}" stroke-width="{fmt(sw)}"'
        if dash: a += f' stroke-dasharray="{dash}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if cap: a += f' stroke-linecap="{cap}"'
        if arrow:
            a += f' marker-end="url(#{self.marker(stroke)})"'
        if arrow_start:
            a += f' marker-start="url(#{self.marker(stroke, True)})"'
        a += '/>'
        self.add(a)

    def marker(self, color, start=False):
        mid = 'm' + color.strip('#') + ('s' if start else 'e')
        if mid not in {d[0] for d in self.defs}:
            if start:
                path = 'M8,0 L0,3 L8,6 z'
            else:
                path = 'M0,0 L8,3 L0,6 z'
            self.defs.add((mid, f'<marker id="{mid}" viewBox="0 0 8 6" refX="{"1" if start else "7"}" refY="3" markerWidth="7" markerHeight="5" orient="auto"><path d="{path}" fill="{color}"/></marker>'))
        return mid

    def path(self, d, fill='none', stroke=INK, sw=1, dash=None, opacity=None, arrow=False, join=None):
        a = f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{fmt(sw)}"'
        if dash: a += f' stroke-dasharray="{dash}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if join: a += f' stroke-linejoin="{join}"'
        if arrow: a += f' marker-end="url(#{self.marker(stroke)})"'
        a += '/>'
        self.add(a)

    def polyline(self, pts, stroke=INK, sw=1, fill='none', dash=None, opacity=None, arrow=False, close=False):
        d = 'M' + ' L'.join(f'{fmt(x)},{fmt(y)}' for x, y in pts) + (' Z' if close else '')
        self.path(d, fill=fill, stroke=stroke, sw=sw, dash=dash, opacity=opacity, arrow=arrow)

    def circle(self, cx, cy, r, fill='none', stroke=None, sw=1, opacity=None, dash=None):
        a = f'<circle cx="{fmt(cx)}" cy="{fmt(cy)}" r="{fmt(r)}" fill="{fill}"'
        if stroke: a += f' stroke="{stroke}" stroke-width="{fmt(sw)}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if dash: a += f' stroke-dasharray="{dash}"'
        a += '/>'
        self.add(a)

    def dot(self, cx, cy, r=2, fill=INK, opacity=None):
        self.circle(cx, cy, r, fill=fill, opacity=opacity)

    def text(self, x, y, s, size=11, anchor='start', fill=INK, mono=False, italic=False, weight=None, dy=None, rotate=None, baseline=None, small_caps=False, opacity=None, letter=None):
        a = f'<text x="{fmt(x)}" y="{fmt(y)}" font-size="{fmt(size)}" text-anchor="{anchor}" fill="{fill}"'
        cls = []
        if mono: cls.append('mono')
        if italic: a += ' font-style="italic"'
        if weight: a += f' font-weight="{weight}"'
        if small_caps: a += ' font-variant="small-caps"'
        if dy is not None: a += f' dy="{fmt(dy)}"'
        if baseline: a += f' dominant-baseline="{baseline}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if letter: a += f' letter-spacing="{letter}"'
        if rotate is not None: a += f' transform="rotate({fmt(rotate)} {fmt(x)} {fmt(y)})"'
        if cls: a += f' class="{" ".join(cls)}"'
        a += f'>{escape(str(s))}</text>'
        self.add(a)

    def label(self, x, y, s, size=10, anchor='start', fill=INK2, italic=True, **kw):
        self.text(x, y, s, size=size, anchor=anchor, fill=fill, italic=italic, **kw)

    def group(self, inner, transform=None, opacity=None, cls=None):
        a = '<g'
        if transform: a += f' transform="{transform}"'
        if opacity is not None: a += f' opacity="{fmt(opacity)}"'
        if cls: a += f' class="{cls}"'
        a += '>' + inner + '</g>'
        self.add(a)

    def brace(self, x1, x2, y, label=None, size=10, up=True, color=INK2, tick=6, label_dy=None):
        """a horizontal bracket spanning [x1, x2] at y, label below (or above)."""
        d = 1 if up else -1
        self.path(f'M{fmt(x1)},{fmt(y - d*tick)} L{fmt(x1)},{fmt(y)} L{fmt(x2)},{fmt(y)} L{fmt(x2)},{fmt(y - d*tick)}', stroke=color, sw=0.8)
        if label is not None:
            ly = y + (size + 2 if up else -(size*0.5)) if label_dy is None else y + label_dy
            self.text((x1 + x2) / 2, ly, label, size=size, anchor='middle', fill=color, italic=True)

    def vbrace(self, y1, y2, x, label=None, size=10, right=True, color=INK2, tick=6):
        d = 1 if right else -1
        self.path(f'M{fmt(x - d*tick)},{fmt(y1)} L{fmt(x)},{fmt(y1)} L{fmt(x)},{fmt(y2)} L{fmt(x - d*tick)},{fmt(y2)}', stroke=color, sw=0.8)
        if label is not None:
            self.text(x + d*6, (y1 + y2) / 2, label, size=size, anchor='start' if right else 'end', fill=color, italic=True, baseline='middle')

    def leader(self, x1, y1, x2, y2, color=INK2):
        self.line(x1, y1, x2, y2, stroke=color, sw=0.6)

    def render(self, width=None, style=None, role_desc=None):
        defs = ''
        if self.defs:
            defs = '<defs>' + ''.join(d[1] for d in sorted(self.defs)) + '</defs>'
        attrs = f'viewBox="{fmt(-self.pad)} {fmt(-self.pad)} {fmt(self.w + 2*self.pad)} {fmt(self.h + 2*self.pad)}" class="{self.cls}" xmlns="http://www.w3.org/2000/svg"'
        if width:
            attrs += f' style="width:{width};max-width:100%"'
        if style:
            attrs += f' style="{style}"'
        if role_desc:
            attrs += f' role="img" aria-label="{escape(role_desc)}"'
        return f'<svg {attrs}>{defs}{"".join(self.parts)}</svg>'


# ---------------------------------------------------------------------------
# byte field diagrams
# ---------------------------------------------------------------------------

def bytefield(fields, unit=22, max_units=12, row_h=34, label_size=10.5, type_size=9, start_offset=0,
              offsets=True, x0=4, y0=18, mono_values=True, value_size=9.5, width=None, wrap=None):
    """Draw a sequence of fields as adjacent boxes.

    fields: list of dicts with
      name   : text inside the box
      size   : byte count (int) or None for variable length
      type   : small caption under the name (e.g. 'u64 LE')
      fill   : fill color
      value  : optional value shown under the box
      units  : optional width override in units
      trunc  : draw as a broken/elided box
    Returns an SVG object.
    """
    x = x0
    boxes = []
    off = start_offset
    known = True
    for f in fields:
        size = f.get('size')
        if 'units' in f:
            u = f['units']
        elif size is None:
            u = 5
        else:
            u = min(size, max_units) if size >= 1 else 1
            if size > max_units: u = max_units
        w = u * unit
        boxes.append((x, w, f, off if known else None))
        x += w
        if size is not None and 'units' not in f or (size is not None and f.get('exact_size')):
            off += size
        elif size is None or f.get('trunc'):
            known = False
        else:
            off += size
    total_w = x + 44
    values = any(f.get('value') is not None for f in fields)
    h = y0 + row_h + (28 if values else 10) + (6 if offsets else 0)
    s = SVG(total_w, h)
    for (bx, bw, f, boff) in boxes:
        fill = f.get('fill', F_DATA)
        if f.get('trunc'):
            # box with a torn right edge
            s.path(f'M{fmt(bx)},{fmt(y0)} L{fmt(bx+bw-10)},{fmt(y0)} l-3,{fmt(row_h/4)} l6,{fmt(row_h/4)} l-6,{fmt(row_h/4)} l3,{fmt(row_h/4)} L{fmt(bx)},{fmt(y0+row_h)} Z', fill=fill, stroke=INK, sw=0.9)
        else:
            s.rect(bx, y0, bw, row_h, fill=fill, stroke=INK, sw=0.9)
        name = f.get('name', '')
        ty = f.get('type')
        cy = y0 + row_h / 2
        if ty:
            s.text(bx + bw/2, cy - 2, name, size=label_size, anchor='middle', fill=INK, mono=f.get('mono', False))
            s.text(bx + bw/2, cy + 10, ty, size=type_size, anchor='middle', fill=INK2, italic=True)
        else:
            s.text(bx + bw/2, cy + 4, name, size=label_size, anchor='middle', fill=INK, mono=f.get('mono', False))
        if offsets and (boff is not None or f.get('offset_label')):
            s.line(bx, y0 - 4, bx, y0, stroke=INK2, sw=0.6)
            s.text(bx + 1.5, y0 - 6, fmt(boff) if not f.get('offset_label') else f['offset_label'], size=8.5, anchor='start', fill=INK2, mono=True)
        if f.get('value') is not None:
            s.text(bx + bw/2, y0 + row_h + 14, f['value'], size=value_size, anchor='middle', fill=Q_RED if f.get('value_hi') else INK, mono=mono_values)
        if f.get('size') is not None and f.get('show_size', True):
            s.text(bx + bw - 2, y0 + row_h + (28 if values else 11), f"{f['size']} B" if not f.get('size_label') else f['size_label'], size=8, anchor='end', fill=GRAY)
        elif f.get('size_label'):
            s.text(bx + bw - 2, y0 + row_h + (28 if values else 11), f['size_label'], size=8, anchor='end', fill=GRAY)
    if offsets and known:
        # final offset tick
        s.line(x, y0 - 4, x, y0, stroke=INK2, sw=0.6)
        s.text(x + 1.5, y0 - 6, fmt(off), size=8.5, anchor='start', fill=INK2, mono=True)
    return s


def hexgrid(data, spans, cols=16, cell=21, x0=48, y0=16, start=0, show_ascii=True, note_rows=True, legend=True, ascii_gap=10):
    """Annotated hex dump. data: bytes. spans: list of (start, length, fill, label).
    Byte offsets shown at left; colored spans with labels listed as a legend."""
    rows = math.ceil(len(data) / cols)
    legend_h = 0
    if legend:
        legend_h = 14 * len(spans) + 8
    w = x0 + cols * cell + (ascii_gap + cols * 7.5 if show_ascii else 0) + 8
    h = y0 + rows * cell + 6 + legend_h
    s = SVG(w, h)
    fills = {}
    for (st, ln, fill, label) in spans:
        for i in range(st, min(st + ln, start + len(data))):
            fills[i] = fill
    for r in range(rows):
        y = y0 + r * cell
        s.text(x0 - 6, y + cell*0.68, '%04x' % (start + r*cols), size=9, anchor='end', fill=GRAY, mono=True)
        for c in range(cols):
            i = r * cols + c
            if i >= len(data): break
            x = x0 + c * cell
            f = fills.get(start + i)
            if f:
                s.rect(x, y, cell, cell, fill=f)
            s.text(x + cell/2, y + cell*0.68, '%02x' % data[i], size=9.6, anchor='middle', fill=INK, mono=True)
            if show_ascii:
                ch = chr(data[i]) if 32 <= data[i] < 127 else '·'
                ax = x0 + cols * cell + ascii_gap + c * 7.5
                if f:
                    s.rect(ax - 0.5, y, 7.5, cell, fill=f)
                s.text(ax + 3.5, y + cell*0.68, ch, size=9.6, anchor='middle', fill=INK if ch != '·' else LIGHT, mono=True)
    # grid lines (light)
    for r in range(rows + 1):
        s.line(x0, y0 + r*cell, x0 + cols*cell, y0 + r*cell, stroke='#e6e2d6', sw=0.5)
    if legend:
        ly = y0 + rows * cell + 14
        for (st, ln, fill, label) in spans:
            s.rect(x0, ly - 9, 12, 10, fill=fill, stroke=INK, sw=0.4)
            s.text(x0 + 18, ly, f'{label}', size=9.5, fill=INK2)
            s.text(w - 8, ly, f'{st:#06x} +{ln}', size=8.5, anchor='end', fill=GRAY, mono=True)
            ly += 14
    return s


def axis_ticks(lo, hi, n=5):
    span = hi - lo
    if span <= 0: return [lo]
    raw = span / n
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        step = m * mag
        if span / step <= n + 0.5:
            break
    t0 = math.ceil(lo / step) * step
    ticks = []
    t = t0
    while t <= hi + 1e-9:
        ticks.append(round(t, 10))
        t += step
    return ticks


class Plot:
    """Minimal scatter/line plot with Tufte-ish axes (no box, light ticks)."""
    def __init__(self, svg, x, y, w, h, xlim, ylim, xlabel=None, ylabel=None, xticks=None, yticks=None, xfmt=fmt, yfmt=fmt, tick_size=9, grid=False, xaxis_at=None):
        self.s = svg
        self.x, self.y, self.w, self.h = x, y, w, h
        self.xlim, self.ylim = xlim, ylim
        xt = xticks if xticks is not None else axis_ticks(*xlim)
        yt = yticks if yticks is not None else axis_ticks(*ylim)
        ay = y + h
        svg.line(x, ay, x + w, ay, stroke=INK2, sw=0.8)
        if xaxis_at is not None:
            svg.line(x, self.Y(xaxis_at), x + w, self.Y(xaxis_at), stroke=GRAY, sw=0.6)
        svg.line(x, y, x, y + h, stroke=INK2, sw=0.8)
        for t in xt:
            px = self.X(t)
            svg.line(px, ay, px, ay + 4, stroke=INK2, sw=0.8)
            svg.text(px, ay + 14, xfmt(t), size=tick_size, anchor='middle', fill=INK2)
            if grid and t != xlim[0]:
                svg.line(px, y, px, y + h, stroke='#eee9dc', sw=0.6)
        for t in yt:
            py = self.Y(t)
            svg.line(x - 4, py, x, py, stroke=INK2, sw=0.8)
            svg.text(x - 7, py + 3, yfmt(t), size=tick_size, anchor='end', fill=INK2)
            if grid and t != ylim[0]:
                svg.line(x, py, x + w, py, stroke='#eee9dc', sw=0.6)
        if xlabel:
            svg.text(x + w, ay + 28, xlabel, size=10, anchor='end', fill=INK2, italic=True)
        if ylabel:
            svg.text(x - 4, y - 8, ylabel, size=10, anchor='start', fill=INK2, italic=True)

    def X(self, v):
        return self.x + (v - self.xlim[0]) / (self.xlim[1] - self.xlim[0]) * self.w

    def Y(self, v):
        return self.y + self.h - (v - self.ylim[0]) / (self.ylim[1] - self.ylim[0]) * self.h

    def points(self, pts, r=1.5, fill=INK, opacity=0.7):
        # one path of tiny circles is lighter than many <circle>s
        d = ''.join(f'M{fmt(self.X(x))},{fmt(self.Y(y))} m-{fmt(r)},0 a{fmt(r)},{fmt(r)} 0 1,0 {fmt(2*r)},0 a{fmt(r)},{fmt(r)} 0 1,0 -{fmt(2*r)},0 ' for x, y in pts)
        self.s.path(d, fill=fill, stroke='none', opacity=opacity)

    def line(self, pts, stroke=INK, sw=1.2, dash=None, opacity=None, arrow=False):
        self.s.polyline([(self.X(x), self.Y(y)) for x, y in pts], stroke=stroke, sw=sw, dash=dash, opacity=opacity, arrow=arrow)

    def step(self, xs, ys, stroke=INK, sw=1, dash=None, opacity=None):
        pts = []
        for i in range(len(ys)):
            pts.append((self.X(xs[i]), self.Y(ys[i])))
            pts.append((self.X(xs[i+1]), self.Y(ys[i])))
        self.s.polyline(pts, stroke=stroke, sw=sw, dash=dash, opacity=opacity)

    def band(self, xs, lo, hi, fill, opacity=0.35):
        top = []
        bot = []
        for i in range(len(lo)):
            top += [(self.X(xs[i]), self.Y(hi[i])), (self.X(xs[i+1]), self.Y(hi[i]))]
            bot += [(self.X(xs[i]), self.Y(lo[i])), (self.X(xs[i+1]), self.Y(lo[i]))]
        pts = top + bot[::-1]
        self.s.polyline(pts, stroke='none', fill=fill, opacity=opacity, close=True)

    def hline(self, yv, stroke=GRAY, sw=0.8, dash='3,3', label=None, size=9, x_from=None):
        xf = self.x if x_from is None else self.X(x_from)
        self.s.line(xf, self.Y(yv), self.x + self.w, self.Y(yv), stroke=stroke, sw=sw, dash=dash)
        if label:
            self.s.text(self.x + self.w + 4, self.Y(yv) + 3, label, size=size, fill=stroke, italic=True)

    def vline(self, xv, stroke=GRAY, sw=0.8, dash='3,3', label=None, size=9, y_from=None, label_dy=-4):
        self.s.line(self.X(xv), self.y if y_from is None else self.Y(y_from), self.X(xv), self.y + self.h, stroke=stroke, sw=sw, dash=dash)
        if label:
            self.s.text(self.X(xv), self.y + label_dy, label, size=size, anchor='middle', fill=stroke, italic=True)

    def text(self, xv, yv, s, **kw):
        self.s.text(self.X(xv), self.Y(yv), s, **kw)


def table_svg(rows, col_w, x0=0, y0=0, row_h=18, size=10, header=True, mono_cols=(), align=None, hi_rows=(), hi_cells=None, fills=None):
    """Render a small table as SVG (for traces). rows: list of lists of str."""
    ncol = len(col_w)
    w = x0 + sum(col_w) + 2
    h = y0 + row_h * len(rows) + 4
    s = SVG(w, h)
    y = y0
    for ri, row in enumerate(rows):
        x = x0
        if ri in hi_rows:
            s.rect(x0, y, sum(col_w), row_h, fill=F_HI)
        for ci, cellv in enumerate(row):
            cw = col_w[ci]
            if hi_cells and (ri, ci) in hi_cells:
                s.rect(x, y, cw, row_h, fill=hi_cells[(ri, ci)])
            if fills and (ri, ci) in fills:
                s.rect(x + 1, y + 1, cw - 2, row_h - 2, fill=fills[(ri, ci)])
            a = (align[ci] if align else ('start' if ci == 0 else 'end'))
            tx = x + 4 if a == 'start' else (x + cw - 4 if a == 'end' else x + cw/2)
            isheader = header and ri == 0
            s.text(tx, y + row_h*0.7, cellv, size=size, anchor=a, fill=INK2 if isheader else INK, italic=isheader, mono=(ci in mono_cols and not isheader))
            x += cw
        if header and ri == 0:
            s.line(x0, y + row_h, x0 + sum(col_w), y + row_h, stroke=INK2, sw=0.7)
        y += row_h
    s.line(x0, y, x0 + sum(col_w), y, stroke=INK2, sw=0.7)
    return s
