"""lookup.html: bounded exact-match lookup."""
import hashlib, math, random, struct
from svg import *
from common import *

# ---------------------------------------------------------------------------
# simulated data: genuine MD5 digests of a counter, sorted
# ---------------------------------------------------------------------------
def make_set(n, salt='hset-doc'):
    hs = sorted(hashlib.md5(f'{salt}:{i}'.encode()).digest() for i in range(n))
    return hs

def expected_index(h, n):
    high32 = struct.unpack('>I', h[:4])[0]
    return (high32 * n) >> 32

def deviations(hs):
    n = len(hs)
    return [(expected_index(h, n), i - expected_index(h, n)) for i, h in enumerate(hs)]

def block_bounds(hs, bits=8):
    n = len(hs)
    nb = 1 << bits
    mn = [None] * nb
    mx = [None] * nb
    for i, h in enumerate(hs):
        e = expected_index(h, n)
        d = i - e
        b = ((h[0] << 8) | h[1]) >> (16 - bits)
        mn[b] = d if mn[b] is None else min(mn[b], d)
        mx[b] = d if mx[b] is None else max(mx[b], d)
    return mn, mx

N = 4096
HS = make_set(N)
DEV = deviations(HS)
MN8, MX8 = block_bounds(HS, 8)
MN4, MX4 = block_bounds(HS, 4)


def hull(points):
    """Andrew's monotone chain; returns (lower, upper) hulls of points sorted by x."""
    pts = sorted(set(points))
    if len(pts) < 3:
        return pts, pts
    def cross(o, a, b):
        return (a[0]-o[0])*(b[1]-o[1]) - (a[1]-o[1])*(b[0]-o[0])
    lower = []
    for p in pts:
        while len(lower) >= 2 and cross(lower[-2], lower[-1], p) <= 0:
            lower.pop()
        lower.append(p)
    upper = []
    for p in reversed(pts):
        while len(upper) >= 2 and cross(upper[-2], upper[-1], p) <= 0:
            upper.pop()
        upper.append(p)
    return lower, upper[::-1]


def min_width_slab(points):
    """the sloped slab of minimum height enclosing the points, slopes from hull edges (as hull_lines.h)"""
    lo, up = hull(points)
    slopes = [0.0]
    for h in (lo, up):
        for a, b in zip(h, h[1:]):
            if abs(b[0] - a[0]) > 1e-9:
                slopes.append((b[1] - a[1]) / (b[0] - a[0]))
    best = None
    for s in slopes:
        r = [y - s * x for x, y in points]
        w = max(r) - min(r)
        if best is None or w < best[0]:
            best = (w, s, min(r), max(r))
    return best  # width, slope, c_lo, c_hi


# ---------------------------------------------------------------------------
# figures
# ---------------------------------------------------------------------------
def fig_staircase():
    W, H = 900, 420
    s = SVG(W, H)
    # left: full staircase; right: zoom
    p = Plot(s, 50, 20, 380, 340, (0, 1), (0, N), xlabel='leading 32 bits of the hash, as a fraction of 2³²', ylabel='index in the sorted array', xticks=[0, 0.25, 0.5, 0.75, 1], yticks=[0, 1024, 2048, 3072, 4096])
    pts = [(struct.unpack('>I', h[:4])[0] / 2**32, i) for i, h in enumerate(HS)]
    p.points(pts[::2], r=1.1, fill=S_BLUE, opacity=0.8)
    p.line([(0, 0), (1, N)], stroke=Q_RED, sw=1, dash='5,3')
    s.text(p.X(0.62), p.Y(0.62 * N) - 14, 'i = e(h) = ⌊h₃₂ · n / 2³²⌋', size=10.5, fill=Q_RED, italic=True, anchor='end')
    # zoom box
    za, zb = 0.50, 0.53
    ia, ib = int(za * N) - 60, int(zb * N) + 60
    s.rect(p.X(za), p.Y(ib), p.X(zb) - p.X(za), p.Y(ia) - p.Y(ib), fill='none', stroke=INK2, sw=0.8)
    p2 = Plot(s, 520, 20, 350, 340, (za, zb), (ia, ib), xlabel='the same, magnified 30×', xticks=[0.50, 0.51, 0.52, 0.53], yticks=[2000, 2050, 2100, 2150, 2200], xfmt=lambda v: f'{v:.2f}')
    s.line(p.X(zb), p.Y(ib), p2.x, p2.y, stroke=INK2, sw=0.5, dash='2,2')
    s.line(p.X(zb), p.Y(ia), p2.x, p2.y + p2.h, stroke=INK2, sw=0.5, dash='2,2')
    zpts = [(x, i) for x, i in pts if za <= x <= zb and ia <= i <= ib]
    p2.points(zpts, r=2.2, fill=S_BLUE, opacity=0.9)
    p2.line([(za, za * N), (zb, zb * N)], stroke=Q_RED, sw=1, dash='5,3')
    # deviation arrow for one point
    x, i = zpts[len(zpts) // 3]
    e = int(x * N)
    s.line(p2.X(x), p2.Y(e), p2.X(x), p2.Y(i), stroke=INK, sw=1, arrow=True)
    s.text(p2.X(x) + 6, (p2.Y(e) + p2.Y(i)) / 2 + 3, f'd = i − e = {i - e:+d}', size=10, fill=INK, italic=True)
    s.text(20, H - 8, f'{N} MD5 digests of a counter (computed by the generator, not drawn by hand); every plot on this page uses this set.', size=9.5, fill=INK2, italic=True)
    return s


def fig_expected_index():
    s = bytefield([
        {'name': 'h[0]', 'size': 1, 'fill': F_HI, 'units': 2, 'value': 'd4'},
        {'name': 'h[1]', 'size': 1, 'fill': F_HI, 'units': 2, 'value': '04'},
        {'name': 'h[2]', 'size': 1, 'fill': F_HI, 'units': 2, 'value': 'b1'},
        {'name': 'h[3]', 'size': 1, 'fill': F_HI, 'units': 2, 'value': '25'},
        {'name': 'h[4] … h[15]', 'size': 12, 'type': 'ignored by e(h)', 'fill': F_HASH, 'units': 10, 'trunc': True},
    ], unit=24)
    return s


def fig_bridge():
    W, H = 900, 300
    s = SVG(W, H)
    dmin = min(d for e, d in DEV); dmax = max(d for e, d in DEV)
    lim = max(-dmin, dmax) + 8
    p = Plot(s, 50, 20, 820, 220, (0, N), (-lim, lim), xlabel='expected index e', ylabel='deviation d = i − e', xticks=[0, 512, 1024, 1536, 2048, 2560, 3072, 3584, 4096], xaxis_at=0)
    # block bands (8-bit)
    xs = [b * N / 256 for b in range(257)]
    lo = [MN8[b] if MN8[b] is not None else 0 for b in range(256)]
    hi = [MX8[b] if MX8[b] is not None else 0 for b in range(256)]
    p.band(xs, lo, hi, fill=S_BLUE, opacity=0.18)
    p.step(xs, lo, stroke=S_BLUE, sw=0.7)
    p.step(xs, hi, stroke=S_BLUE, sw=0.7)
    # the walk
    pts = sorted(DEV)
    p.line(pts, stroke=INK, sw=0.8)
    # block ticks
    for b in range(0, 257, 32):
        s.line(p.X(b * N / 256), p.y + p.h, p.X(b * N / 256), p.y + p.h + 3, stroke=S_BLUE, sw=0.6)
    s.text(p.X(0), p.y + p.h + 30, 'blue steps: the 0x6208 HINT, min and max of d over each of the 256 leading-byte blocks (16 rows per block here)', size=9.5, fill=S_BLUE, italic=True)
    s.text(p.X(0), p.y + p.h + 44, f'the walk is pinned to 0 at both ends; its excursion is about ±√n/2 = ±{int(math.sqrt(N)/2)} rows, but within one block it moves far less', size=9.5, fill=INK2, italic=True)
    return s


def fig_window():
    """zoom on one block: the band, a query's e, its window, and the probes"""
    W, H = 900, 330
    s = SVG(W, H)
    b = 0x9a
    e0, e1 = b * N // 256, (b + 1) * N // 256
    pts = [(e, d) for e, d in DEV if e0 <= e < e1]
    lo, hi = MN8[b], MX8[b]
    p = Plot(s, 60, 24, 420, 250, (e0 - 1, e1 + 1), (lo - 6, hi + 6), xlabel=f'expected index e, block 0x{b:02x}', ylabel='deviation d', xticks=[e0, e0 + 4, e0 + 8, e0 + 12, e1], yticks=list(range(lo - 6, hi + 7, 2)))
    s.rect(p.X(e0 - 1), p.Y(hi), p.X(e1 + 1) - p.X(e0 - 1), p.Y(lo) - p.Y(hi), fill=S_BLUE, opacity=0.15)
    p.hline(hi, stroke=S_BLUE, dash=None, sw=0.8, label=f'max = {hi:+d}')
    p.hline(lo, stroke=S_BLUE, dash=None, sw=0.8, label=f'min = {lo:+d}')
    p.points(pts, r=3, fill=INK, opacity=0.9)
    # a query: pick the e of the 5th point
    qe, qd = pts[5]
    p.vline(qe, stroke=Q_RED, dash='3,3', label=f'query: e = {qe}', label_dy=-6)
    # right: the index axis with the window
    x0 = 560
    y0 = 40
    rh = 16
    s.text(x0, y0 - 14, 'the sorted array around e', size=10, italic=True, fill=INK2)
    lo_i, hi_i = qe + lo, qe + hi + 1
    for k, i in enumerate(range(lo_i - 3, hi_i + 3)):
        y = y0 + k * rh
        inwin = lo_i <= i < hi_i
        s.rect(x0, y, 200, rh, fill=(F_HI if inwin else F_PAD), stroke=INK, sw=0.4)
        s.text(x0 + 4, y + 12, f'{i}', size=9, fill=INK2, mono=True)
        s.text(x0 + 50, y + 12, HS[i][:6].hex() + '…', size=9, mono=True)
        if i == qe:
            s.text(x0 + 206, y + 12, '← e', size=10, fill=Q_RED, italic=True)
        if i == qe + qd:
            s.text(x0 + 206 + (28 if i == qe else 0), y + 12, '← the row with this hash', size=10, fill=G_GREEN, italic=True)
    s.vbrace(y0 + 3 * rh, y0 + (3 + hi_i - lo_i) * rh, x0 - 8, f'window [e{lo:+d}, e{hi + 1:+d}): {hi_i - lo_i} rows', right=False, size=9.5)
    s.text(x0, y0 + (hi_i - lo_i + 7) * rh + 6, f'a binary search over {hi_i - lo_i} rows touches ⌈log₂ {hi_i - lo_i}⌉ = {math.ceil(math.log2(hi_i - lo_i))} of them,', size=9.5, fill=INK2, italic=True)
    s.text(x0, y0 + (hi_i - lo_i + 7) * rh + 20, f'against ⌈log₂ {N}⌉ = {math.ceil(math.log2(N))} over the whole array', size=9.5, fill=INK2, italic=True)
    return s, hi_i - lo_i, math.ceil(math.log2(hi_i - lo_i)), math.ceil(math.log2(N))


def fig_binary_search_trace():
    """trace of the branchless lower_bound over a window of primary keys"""
    b = 0x9a
    e0 = b * N // 256
    lo, hi = MN8[b], MX8[b]
    pts = [(e, d) for e, d in DEV if e0 <= e < (b + 1) * N // 256]
    qe, qd = pts[5]
    lo_i, hi_i = qe + lo, qe + hi + 1
    target = HS[qe + qd]
    hk = struct.unpack('>Q', target[:8])[0]
    rows = [['step', 'pos', 'len', 'half', 'probe', 'key[probe] (first 8 bytes)', 'key < hk ?', 'new pos', 'new len']]
    pos, ln = lo_i, hi_i - lo_i
    step = 0
    while ln > 0:
        half = ln >> 1
        probe = pos + half
        pk = struct.unpack('>Q', HS[probe][:8])[0]
        lt = pk < hk
        npos = probe + 1 if lt else pos
        nlen = ln - half - 1 if lt else half
        rows.append([str(step), str(pos), str(ln), str(half), str(probe), HS[probe][:8].hex(), 'yes' if lt else 'no', str(npos), str(nlen)])
        pos, ln = npos, nlen
        step += 1
    rows.append(['end', str(pos), '0', '', '', HS[pos][:8].hex() + (' = hk → confirm bytes 8–15' if HS[pos][:8] == target[:8] else ''), '', '', ''])
    s = table_svg(rows, [40, 50, 40, 40, 50, 230, 80, 70, 70], mono_cols=(5,), align=['end', 'end', 'end', 'end', 'end', 'start', 'end', 'end', 'end'], size=10, hi_rows=(len(rows) - 1,))
    return s, target, qe + qd


def fig_primary_key():
    return bytefield([
        {'name': 'primary key: bytes 0–7 as one big-endian u64', 'size': 8, 'type': 'one integer compare decides almost every probe', 'fill': F_NUM, 'units': 10},
        {'name': 'bytes 8–15', 'size': 8, 'type': 'memcmp only when primary keys are equal', 'fill': F_HASH, 'units': 8},
    ], unit=24)


def fig_batch():
    """software pipeline: D lanes, rounds; each cell a probe; prefetch one round ahead"""
    W, H = 900, 300
    s = SVG(W, H)
    D = 6
    x0, y0 = 90, 40
    cw, rh = 54, 30
    rounds = 13
    rnd = random.Random(3)
    s.text(x0, y0 - 22, 'rounds →  (each round visits every active lane once; a lane does one probe per round)', size=10, italic=True, fill=INK2)
    for r in range(rounds):
        s.text(x0 + r * cw + cw / 2, y0 - 6, str(r), size=9, anchor='middle', fill=GRAY)
    qid = 0
    legend_done = False
    for d in range(D):
        y = y0 + d * rh
        s.text(x0 - 8, y + rh * 0.65, f'lane {d}', size=10, anchor='end', fill=INK2, italic=True)
        r = 0
        while r < rounds:
            steps = rnd.randint(3, 6)
            q = qid; qid += 1
            fill = [F_HI, F_NUM, F_HASH, '#e9dfe6', '#f3e6cf', '#e6e9d7'][q % 6]
            for k in range(steps):
                if r + k >= rounds: break
                x = x0 + (r + k) * cw
                s.rect(x, y, cw, rh - 4, fill=fill, stroke=INK, sw=0.5)
                s.text(x + cw / 2, y + rh * 0.62, f'q{q}·{k}', size=9, anchor='middle', mono=True)
                if k + 1 < steps and r + k + 1 < rounds:
                    # prefetch arrow to next probe
                    s.line(x + cw - 10, y + 4, x + cw + 10, y + 4, stroke=Q_RED, sw=0.8, arrow=True)
            r += steps
    s.text(x0, y0 + D * rh + 16, 'q7·2: the third probe of query 7. Red arrows: the prefetch of the next probe\'s cache line, issued as soon as this probe\'s comparison is known.', size=9.5, fill=INK2, italic=True)
    s.text(x0, y0 + D * rh + 30, 'When a lane finishes a query (hit, or an empty range) it dispatches the next one in the same round. With D = 32 lanes, 32 cache misses are in flight at once.', size=9.5, fill=INK2, italic=True)
    s.text(x0, y0 + D * rh + 44, 'Serial lookups wait for each miss before issuing the next; the pipeline overlaps them, and the eval measured 2.2× on 40M SHA-1s (790 → 322 ns).', size=9.5, fill=INK2, italic=True)
    return s


def fig_slab():
    """one 4-bit block: flat band vs min-width sloped slab from the convex hull"""
    W, H = 960, 360
    s = SVG(W, H)
    best = None
    for bb in range(16):
        e0, e1 = bb * N // 16, (bb + 1) * N // 16
        pp = [(e, d) for e, d in DEV if e0 <= e < e1]
        flat = max(d for e, d in pp) - min(d for e, d in pp)
        ww = min_width_slab([(float(e), float(d)) for e, d in pp])[0]
        if best is None or flat - ww > best[0]:
            best = (flat - ww, bb)
    b = best[1]
    e0, e1 = b * N // 16, (b + 1) * N // 16
    pts = [(e, d) for e, d in DEV if e0 <= e < e1]
    fl_lo, fl_hi = min(d for e, d in pts), max(d for e, d in pts)
    w, sl, clo, chi = min_width_slab([(float(e), float(d)) for e, d in pts])
    lo_h, up_h = hull([(float(e), float(d)) for e, d in pts])
    p = Plot(s, 60, 24, 560, 280, (e0, e1), (fl_lo - 8, fl_hi + 8), xlabel=f'expected index e (block {b} of 16, drawn with 4-bit blocks so the shapes are visible)', ylabel='deviation d', xticks=[e0, e0 + 64, e0 + 128, e0 + 192, e1])
    # flat band
    s.rect(p.X(e0), p.Y(fl_hi), p.X(e1) - p.X(e0), p.Y(fl_lo) - p.Y(fl_hi), fill=S_BLUE, opacity=0.12)
    p.hline(fl_hi, stroke=S_BLUE, dash=None, sw=0.8)
    p.hline(fl_lo, stroke=S_BLUE, dash=None, sw=0.8)
    # hulls
    p.line(lo_h, stroke=GRAY, sw=0.8, dash='3,2')
    p.line(up_h, stroke=GRAY, sw=0.8, dash='3,2')
    # slab
    xa, xb = e0, e1
    s.polyline([(p.X(xa), p.Y(sl * xa + chi)), (p.X(xb), p.Y(sl * xb + chi)), (p.X(xb), p.Y(sl * xb + clo)), (p.X(xa), p.Y(sl * xa + clo))], fill=Q_RED, stroke='none', opacity=0.12, close=True)
    p.line([(xa, sl * xa + chi), (xb, sl * xb + chi)], stroke=Q_RED, sw=1)
    p.line([(xa, sl * xa + clo), (xb, sl * xb + clo)], stroke=Q_RED, sw=1)
    p.points(pts, r=2.2, fill=INK, opacity=0.85)
    # legend
    lx, ly = 640, 60
    s.rect(lx, ly, 14, 10, fill=S_BLUE, opacity=0.3); s.text(lx + 20, ly + 9, f'flat band (block bounds): height {fl_hi - fl_lo + 1} rows', size=10)
    s.rect(lx, ly + 22, 14, 10, fill=Q_RED, opacity=0.3); s.text(lx + 20, ly + 31, f'min-width slab: slope {sl:.4f}, height {w + 1:.1f} rows', size=10)
    s.line(lx, ly + 50, lx + 14, ly + 50, stroke=GRAY, sw=0.8, dash='3,2'); s.text(lx + 20, ly + 53, 'upper and lower convex hulls', size=10)
    s.text(lx, ly + 90, 'Candidate slopes are the hull edges;', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 104, 'for each, the slab is max − min of', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 118, 'd − s·e, and the narrowest wins.', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 140, 'Stored as three floats per block', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 154, '(s, c_lo, c_hi), then widened until', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 168, 'every stored row is inside again.', size=9.5, fill=INK2, italic=True)
    return s


def fig_global_hull():
    W, H = 900, 300
    s = SVG(W, H)
    dmin = min(d for e, d in DEV); dmax = max(d for e, d in DEV)
    lim = max(-dmin, dmax) + 8
    p = Plot(s, 50, 20, 820, 220, (0, N), (-lim, lim), xlabel='expected index e', ylabel='deviation d', xticks=[0, 1024, 2048, 3072, 4096], xaxis_at=0)
    pts = [(float(e), float(d)) for e, d in DEV]
    lo_h, up_h = hull(pts)
    # fill between hulls
    poly = [(p.X(x), p.Y(y)) for x, y in up_h] + [(p.X(x), p.Y(y)) for x, y in reversed(lo_h)]
    s.polyline(poly, fill=P_PURPLE, stroke='none', opacity=0.12, close=True)
    p.line(sorted(DEV), stroke=INK, sw=0.7)
    p.line(up_h, stroke=P_PURPLE, sw=1.2)
    p.line(lo_h, stroke=P_PURPLE, sw=1.2)
    for x, y in up_h + lo_h:
        s.dot(p.X(x), p.Y(y), r=2.5, fill=P_PURPLE)
    s.text(p.X(60), p.y + 12, f'{len(up_h)} upper + {len(lo_h)} lower hull vertices', size=9.5, fill=P_PURPLE, italic=True)
    s.text(p.X(0), p.y + p.h + 30, 'one upper and one lower hull over all (e, d) points; a query evaluates both piecewise-linear functions at its e (a binary search over the vertices) to get its window', size=9.5, fill=INK2, italic=True)
    return s


def fig_results():
    """dot plot of ns/lookup and touches from the frozen eval (NSRL SHA-1, 40.4M)"""
    data = [
        ('c0 plain binary search', 1915, 1898, None),
        ('c1 block256  (shipped, 8-bit)', 790, 322, 9.25),
        ('c2 block + sloped slab', 749, 315, 8.78),
        ('c3 global hull', 1139, 1189, 6.45),
        ('c4 fine block (14-bit)', 543, 244, 6.47),
        ('c5 slab + interpolation', 693, 675, 9.80),
        ('c6 slab + interp + batch', 753, 644, 10.46),
        ('phmap (not sorted)', 253, 250, None),
    ]
    W, H = 900, 330
    s = SVG(W, H)
    x0, y0, rh = 230, 30, 28
    p = Plot(s, x0, y0, 420, rh * len(data), (0, 2000), (0, len(data)), xlabel='ns per lookup, 1M misses, Xeon E5645', yticks=[], xticks=[0, 500, 1000, 1500, 2000])
    for i, (name, single, batch, touch) in enumerate(data):
        y = y0 + i * rh + rh / 2
        s.text(x0 - 8, y + 4, name, size=10, anchor='end', fill=INK if 'c1' in name or 'c4' in name else INK2, italic=('phmap' in name))
        s.line(p.X(min(single, batch)), y, p.X(max(single, batch)), y, stroke=LIGHT, sw=1)
        s.dot(p.X(single), y, r=4, fill=INK)
        s.dot(p.X(batch), y, r=4, fill=Q_RED)
        s.text(p.X(single) + 7, y - 4, str(single), size=8.5, fill=INK)
        s.text(p.X(batch), y + 14, str(batch), size=8.5, fill=Q_RED, anchor='middle')
        if touch:
            s.text(x0 + 440 + 60, y + 4, f'{touch:.2f}', size=10, anchor='end', mono=True)
    s.text(x0 + 440 + 60, y0 - 6, 'rows touched', size=9.5, anchor='end', fill=INK2, italic=True)
    s.text(x0 + 440 + 60, y0 + 6, 'per lookup', size=9.5, anchor='end', fill=INK2, italic=True)
    s.dot(x0, H - 10, r=4, fill=INK); s.text(x0 + 8, H - 6, 'one lookup at a time', size=9.5)
    s.dot(x0 + 160, H - 10, r=4, fill=Q_RED); s.text(x0 + 168, H - 6, 'batched (contains_batch)', size=9.5)
    s.text(x0 + 340, H - 6, 'NSRL SHA-1, 40 406 763 rows, min of repetitions', size=9.5, fill=INK2, italic=True)
    return s


def fig_tlsh_cell_lookup():
    W, H = 900, 150
    s = SVG(W, H)
    x0, y = 20, 60
    s = bytefield([
        {'name': 'L', 'size': 1, 'fill': F_HI, 'units': 2, 'value': '2a'},
        {'name': 'Q', 'size': 1, 'fill': F_HI2, 'units': 2, 'value': 'e1'},
        {'name': 'planes, checksum, 0', 'size': 34, 'fill': F_HASH, 'units': 10, 'trunc': True},
    ], unit=24)
    return s


def window_stats(n, bits_list=(8, 14)):
    hs = make_set(n, salt='hset-doc-big')
    out = {}
    for bits in bits_list:
        mn, mx = block_bounds(hs, bits)
        widths = [mx[b] - mn[b] + 1 for b in range(1 << bits) if mn[b] is not None]
        avg = sum(widths) / len(widths)
        out[bits] = (avg, max(widths), sum(math.log2(w) for w in widths) / len(widths))
    out['n'] = n
    return out


def build():
    body = []
    B = body.append
    trace_svg, target, trow = fig_binary_search_trace()
    stats = window_stats(1 << 18)

    B('''<p>Exact lookup is the question the file was built for: given a digest, is one of the n sorted rows equal to it? Binary search answers in ⌈log₂ n⌉ probes, and on a 40-million-row set that is 26 probes, each of them a cache miss into an 800 MB array that no cache holds. The hint stored in every hash section cuts the probes to about nine, and a batch interface overlaps the misses of independent lookups. This page shows why the hint can be so small (4 KiB for any set size) and how far the idea was pushed before the simplest version won.</p>''')
    B('<ul class="toc">' + ''.join(f'<li><span class="n">{n}</span><a href="#{a}">{t}</a></li>' for n, t, a in [
        (1, 'A sorted array of random numbers is a line', 'a-sorted-array-of-random-numbers-is-a-line'), (2, 'The predicted index', 'the-predicted-index'),
        (3, 'The error is a random walk', 'the-error-is-a-random-walk'), (4, 'The hint: observed error per block', 'the-hint-observed-error-per-block'),
        (5, 'The window and the search inside it', 'the-window-and-the-search-inside-it'), (6, 'Many lookups at once', 'many-lookups-at-once'),
        (7, 'Fitting lines to the error', 'fitting-lines-to-the-error'), (8, 'What the measurements said', 'what-the-measurements-said'),
        (9, 'TLSH rows: the cell index', 'tlsh-rows-the-cell-index')]) + '</ul>')

    B(h2(1, 'A sorted array of random numbers is a line'))
    B(f'''<p>A cryptographic digest is, for every purpose here, a uniformly random bit string. Sort n of them and plot each row's value against its index: the points lie almost exactly on the diagonal, because a uniform value h lands at the fraction h/2<sup>bits</sup> of the way through the set. The sorted array is the quantile function of a uniform distribution, and that function is a straight line.{sn('Correctness never depends on this. The bounds in §4 are computed over every stored row, so a query equal to a stored row is always inside its window. Uniformity decides only how narrow the window is, which is to say how fast the lookup is; the eval included a deliberately skewed, clustered "adversarial" set, and every strategy stayed exact on it.')}</p>''')
    B(fig(fig_staircase(), 'Left: the value of each of 4 096 sorted MD5 digests (leading 32 bits, as a fraction) against its index, with the line i = e(h). Right: a 30× magnification of the boxed region. The vertical distance from a point to the line is its deviation d; here it is a few rows out of 4 096.', 'wide'))

    B(h2(2, 'The predicted index'))
    B('''<p>The line gives every hash a <em>predicted</em> or <em>expected index</em> e(h) = ⌊h · n / 2<sup>bits</sup>⌋. Only the leading bits of h can matter when n fits in 32 bits, so the code takes the first four bytes as a big-endian 32-bit integer h₃₂ and computes (h₃₂ · n) ≫ 32 in a single 64-bit multiply that cannot overflow: no memory is touched, and no floating point is involved.</p>''')
    B(fig(fig_expected_index(), 'e(h) = (h₃₂ · n) ≫ 32, where h₃₂ is the first four bytes of the hash read big-endian. For the row shown, with n = 340, h₃₂ = 0xd404b125 and e = 281.', 'col'))

    B(h2(3, 'The error is a random walk'))
    B(f'''<p>Subtract the prediction from the truth and plot d = i − e against e. Figure 3 shows the result for the same 4 096 digests, drawn as a connected line in order of e. It is not noise: it is a random walk pinned to zero at both ends, a <em>Brownian bridge</em>, because d(e) counts how many rows fell below their predicted position so far, and each new row changes that count by at most one. Its excursion is about ±√n/2 overall, but between neighbouring e values it barely moves.{sn('For n = 40 million the whole bridge wanders about ±3 000 rows, yet within one 8-bit block of 156 000 consecutive rows it varies by only a few hundred, and within a 14-bit block of 2 400 rows by a few tens. That locality is why a per-block band is tight and why finer blocks are tighter still.')}</p>
<p>That is the whole opportunity. A query's row, if it exists, sits at e + d for some d the walk took near e. If the file records how far the walk strayed in the neighbourhood of e, the search can be confined to that strip.</p>''')
    B(fig(fig_bridge(), 'The deviation d against e for the 4 096 digests (black), with the shipped hint drawn over it: the minimum and maximum of d in each of the 256 leading-byte blocks (blue steps; the shaded band between them is where every stored row lies).', 'wide'))

    B(h2(4, 'The hint: observed error per block'))
    B(f'''<p>The 0x6208 HINT is exactly Figure 3's blue steps. The writer passes once over the sorted rows; for each row it computes d and folds it into the running minimum and maximum of the row's block, the block being the row's leading byte. Because e grows with h, the 256 blocks are also 256 equal slices of the e axis, each n/256 rows wide. The result is 256 pairs of signed 64-bit integers, 4 098 bytes with the type tag, regardless of n. A block no stored hash begins with keeps the sentinels (INT64_MAX, INT64_MIN), which the reader recognises as "certain miss".{sn('The eval\'s winning variant used 14-bit blocks keyed by the first two bytes (16 384 blocks, 256 KB), 1.3–1.6× faster than 8-bit blocks on 40M rows. It is not what the file stores today: a fixed 256 KB table is larger than the data for a 10 000-row set, and the size-adaptive scheme the analysis recommends was left as an open decision. The header of a HINT carries the type precisely so a later block size can be added.')}</p>''')

    B(h2(5, 'The window and the search inside it'))
    B('''<p>At query time, the window is two additions: lo = e + min<sub>b</sub>, hi = e + max<sub>b</sub> + 1, clamped to [0, n). The stored row, if present, has the same leading byte and the same e as the query, so its d lies within the block's recorded range and the row lies within the window.</p>''')
    win_svg, win_rows, win_probes, full_probes = fig_window()
    B(fig(win_svg, f'One block of the 4 096-row set, magnified. Left: the 16 stored rows of block 0x9a as (e, d) points, the recorded min and max, and a query whose e is the dotted line. Right: the rows of the array around e; the shaded window is where the stored row must be. The search touches {["", "one", "two", "three", "four", "five"][win_probes]} rows instead of {full_probes}.', 'wide'))
    B(f'''<p>Inside the window the code runs a <em>branchless</em> lower-bound search on the <em>primary key</em>, the first eight bytes of each row read as one big-endian integer. Random keys make an ordinary binary search's branch unpredictable, so half its comparisons mispredict; the branchless form computes both outcomes and selects with a conditional move, and its loop runs a fixed ⌈log₂ len⌉ times. Only when a probe's primary key equals the query's are the remaining bytes compared, and two different 20-byte digests sharing eight leading bytes is a one-in-2<sup>64</sup> event.</p>''')
    B(fig(fig_primary_key(), 'A row as the search sees it: an 8-byte integer key, then bytes consulted only on a tie.', 'col'))
    B(fig(trace_svg, f'The branchless search for row {trow} of the 4 096-row set (its first eight bytes are {target[:8].hex()}), over the window of Figure 4. Each step halves <i>len</i>; <i>pos</i> advances past the probe exactly when the probe\'s key is smaller. The final position holds the key, and bytes 8–15 confirm the full digest.', 'wide'))

    B(h2(6, 'Many lookups at once'))
    B('''<p>A single lookup is latency-bound: each probe's address depends on the previous probe's result, so its cache misses are serial. Scanning a disk image produces thousands of independent queries, and <code>sfhash_hashset_lookup_bulk</code> exploits that. It keeps D = 32 queries in flight as <em>lanes</em>; each round advances every active lane by one probe and immediately prefetches the cache line of that lane's next probe. The hardware then has up to 32 misses outstanding instead of one. Results are bit-identical to calling the single lookup on each query.</p>''')
    B(fig(fig_batch(), 'The software pipeline, drawn for six lanes. Each box is one probe of one query; colours distinguish queries. A lane that finishes its query takes the next one in the same round, so the lanes stay full until the batch runs out.', 'wide'))

    B(h2(7, 'Fitting lines to the error'))
    B('''<p>A flat band per block is the crudest possible fit to the walk: slope zero, height max − min. The evaluation harness tried to do better by fitting <em>lines</em>. Within a block the walk often trends, and a sloped slab d ∈ [s·e + c<sub>lo</sub>, s·e + c<sub>hi</sub>] can be narrower than the flat band. The narrowest enclosing slab of a point set is found through its convex hull: the optimal slope is the slope of some hull edge, so the builder computes the upper and lower hulls, tries each edge's slope, and keeps the one whose slab is thinnest. The three numbers are stored as floats and then <em>verified and widened</em>: every stored row is re-checked with the stored floats and c<sub>lo</sub> or c<sub>hi</sub> is nudged out by one until none falls outside, which keeps float rounding from ever excluding a real row.</p>''')
    B(fig(fig_slab(), 'One block of the 4 096-row set, with 4-bit blocks (256 rows) so that the shapes are visible. The flat band (blue) against the minimum-width slab (red) found through the two convex hulls (dashed). Here the slab is a little thinner; on uniform data the gain is small, on skewed data it is large.', 'wide'))
    B('''<p>Taken to its limit, the idea gives one global pair of hulls over all n points: a piecewise-linear upper and lower bound on the walk, tight everywhere, with a few dozen vertices. A query locates its segment by binary search over the vertices and interpolates; the window is the tightest of any candidate. A third family, interpolation search, uses the keys at the window's ends to estimate where the query falls inside it.</p>''')
    B(fig(fig_global_hull(), 'The global upper and lower convex hulls of the 4 096 (e, d) points (purple), with their vertices. Every stored row lies between them; the band is tightest where the walk is quiet.', 'wide'))

    B(h2(8, 'What the measurements said'))
    B(f'''<p>All candidates were raced on the same frozen harness against a <code>std::binary_search</code> oracle, on synthetic sets, an adversarial set, and the real NSRL SHA-1 and MD5 sets of 40.4 million rows. The ranking was cross-checked against machine-independent probe counters and hardware cache-miss counters. The result overturned the plan: the flat band at a finer resolution beat every line fit.{sn('Why: on a memory-latency-bound problem the window computation must cost nothing, and a flat band costs one integer add. The sloped slab needs two float multiplies and a floor and ceil; the global hull a binary search over its vertices; interpolation two extra <em>dependent</em> reads of the window\'s end keys, which break the memory-level parallelism of the batch pipeline, so c6\'s batch mode came out three times slower than c1\'s.')}</p>''')
    B(fig(fig_results(), 'The frozen evaluation on NSRL SHA-1 (40 406 763 rows). Black: one lookup at a time; red: batched. The right column counts rows touched per lookup, the quantity the latency follows.', 'wide'))
    B(f'''<p>The block-bound mechanism scales as the random-walk picture predicts. On a {stats['n']:,}-row simulated set, the generator measured these windows:</p>''')
    B(table(['block bits', 'blocks', 'mean window (rows)', 'largest window', 'mean log₂ window'],
            [(str(b), f'{1 << b:,}', f'{stats[b][0]:.1f}', f'{stats[b][1]}', f'{stats[b][2]:.2f}') for b in (8, 14)], numeric=(0, 1, 2, 3, 4)))
    B('''<p>Finer blocks give tighter windows for free at query time and cost only table size; the table's fixed size is the one thing that stopped the 14-bit version from being wired into the format for every set.</p>''')

    B(h2(9, 'TLSH rows: the cell index'))
    B('''<p>TLSH digests are not uniform: their first byte is a log-scaled file length, so most rows crowd into a few dozen L values. The expected-index trick would fail them, and their section carries the 0x7400 hint instead: 65 537 offsets that locate the run of rows sharing the digest's first two bytes. A lookup reads L and Q, takes the run [offset[c], offset[c+1]) with c = L ≪ 8 | Q, and binary-searches inside it. With rows spread over a few thousand non-empty cells the run is typically a few dozen rows, and the search touches five or six of them.</p>''')
    B(fig(fig_tlsh_cell_lookup(), 'A TLSH lookup keys on the first two bytes: cell 0x2ae1 is L = 42, Q1 = 14, Q2 = 1.', 'col'))
    return page('lookup.html', 'Exact lookup', 'How a sorted array of random digests becomes a line, how the file records the line\'s error, and how a lookup touches a handful of rows.', ''.join(body))
