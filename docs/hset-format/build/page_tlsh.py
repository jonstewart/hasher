"""tlsh.html: the TLSH digest, the lower-bound embedding, the TIVF index and the kNN search."""
import json, math, os, random, struct
from svg import *
from common import *
import tlshlib as T

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, 'data', 'fixtures.json')))
ROWS = T.load_rows(open(os.path.join(HERE, 'data', 'inc_master.hdat'), 'rb').read())
IVF = T.Ivf(open(os.path.join(HERE, 'data', 'inc_master.tivf'), 'rb').read())

HEX_A = 'T1DB238748A9C959F09B40DD5FA21DA7B6932B0966F9D730122B2A36064FB303B5F6CDC1'
DA, RAW_A = T.from_hex(HEX_A)

CODE_FILL = ['#f6d9c9', '#f3f1ea', '#dbe6ee', '#cfe0cf']


# ---------------------------------------------------------------------------
def fig_hex_to_row():
    """the 70 hex characters -> 35 raw bytes -> 36-byte canonical row"""
    W, H = 960, 250
    s = SVG(W, H)
    h = HEX_A[2:]
    cw = 12.6
    x0, y0 = 30, 30
    s.text(x0, y0 - 12, 'the hex transport form: "T1" then 70 hex characters = 35 bytes', size=10, italic=True, fill=INK2)
    s.text(x0 - 4, y0 + 14, 'T1', size=10.5, anchor='end', mono=True, fill=GRAY)
    for i in range(35):
        x = x0 + i * 2 * cw
        fill = F_NUM if i == 0 else (F_HI if i == 1 else (F_HI2 if i == 2 else F_HASH))
        s.rect(x, y0, 2 * cw, 20, fill=fill, stroke=INK, sw=0.4)
        s.text(x + cw, y0 + 14, h[2*i:2*i+2], size=10.5, anchor='middle', mono=True)
    s.brace(x0, x0 + 6 * cw, y0 + 42, None, size=9.5)
    s.text(x0 + 3 * cw, y0 + 56, 'raw[0..2]', size=8.5, anchor='middle', fill=INK2, italic=True)
    s.brace(x0 + 6 * cw, x0 + 70 * cw, y0 + 42, 'raw[3..34]: body, 4 bucket codes per byte, in reverse bucket order', size=9.5)
    # row
    y1 = 150
    s.text(x0, y1 - 12, 'the 36-byte canonical row', size=10, italic=True, fill=INK2)
    row = DA.raw
    bw = 24.5
    fields = [(0, 1, F_HI, 'L'), (1, 1, F_HI2, 'Q'), (2, 16, '#e3ead9', 'plane_hi'), (18, 16, '#d6e2d6', 'plane_lo'), (34, 1, F_NUM, 'chk'), (35, 1, F_PAD, '0')]
    for (a, n, fill, name) in fields:
        for i in range(a, a + n):
            x = x0 + i * bw
            s.rect(x, y1, bw, 20, fill=fill, stroke=INK, sw=0.4)
            s.text(x + bw / 2, y1 + 14, '%02x' % row[i], size=10, anchor='middle', mono=True)
        s.text(x0 + (a + n / 2) * bw, y1 + 32, name, size=9, anchor='middle', fill=INK2, italic=True)
    # arrows: raw[0] -> checksum (swap), raw[1] -> L (swap), raw[2] -> Q (as is)
    def arc(xa, ya, xb, yb, label, lx, color=Q_RED):
        cx = (xa + xb) / 2; cy = (ya + yb) / 2 + 10
        s.path(f'M{fmt(xa)},{fmt(ya)} Q{fmt(cx)},{fmt(cy)} {fmt(xb)},{fmt(yb)}', stroke=color, sw=0.9, arrow=True)
        s.text(lx, 112 if 'raw[1]' in label or 'raw[0]' in label or 'raw[3' in label else 124, label, size=8.5, anchor='start', fill=color, italic=True)
    arc(x0 + cw, y0 + 20, x0 + 34.5 * bw, y1 - 1, f'raw[0] {RAW_A[0]:02x} → checksum {DA.checksum:02x} (nibble swap)', 560)
    arc(x0 + 3 * cw, y0 + 20, x0 + 0.5 * bw, y1 - 1, f'raw[1] {RAW_A[1]:02x} → L {DA.L:02x} = {DA.L} (nibble swap)', 110)
    arc(x0 + 5 * cw, y0 + 20, x0 + 1.5 * bw, y1 - 1, f'raw[2] {RAW_A[2]:02x} → Q as is: Q1 = {DA.q1()}, Q2 = {DA.q2()}', 110)
    arc(x0 + 38 * cw, y0 + 20, x0 + 18 * bw, y1 - 1, 'raw[3..34] reversed, codes split into two bit planes', 330, color=S_BLUE)
    s.text(x0, y1 + 60, f'Digest {HEX_A[:14]}… from the test suite. L = {DA.L} (log-scaled length), Q1 = {DA.q1()}, Q2 = {DA.q2()}, checksum 0x{DA.checksum:02x}; cell = 0x{DA.cell():04x}.', size=9.5, italic=True, fill=INK2)
    s.text(x0, y1 + 74, 'The bytewise order of the row is (L, Q1, Q2, body, checksum): the canonical TLSH sort order, so the generic hset sort and binary search apply unchanged.', size=9.5, italic=True, fill=INK2)
    return s


def fig_planes():
    """bucket codes -> hi/lo planes for the first 16 buckets of A"""
    W, H = 900, 215
    s = SVG(W, H)
    x0, y0 = 120, 30
    bw = 44
    codes = DA.codes()[:16]
    s.text(x0 - 8, y0 + 14, 'bucket i', size=10, anchor='end', fill=INK2, italic=True)
    s.text(x0 - 8, y0 + 44, 'code (0–3)', size=10, anchor='end', fill=INK2, italic=True)
    s.text(x0 - 8, y0 + 84, 'plane_hi bit i', size=10, anchor='end', fill=INK2, italic=True)
    s.text(x0 - 8, y0 + 114, 'plane_lo bit i', size=10, anchor='end', fill=INK2, italic=True)
    for i, c in enumerate(codes):
        x = x0 + i * bw
        s.text(x + bw / 2, y0 + 14, str(i), size=10, anchor='middle', fill=GRAY)
        s.rect(x, y0 + 28, bw - 2, 22, fill=CODE_FILL[c], stroke=INK, sw=0.5)
        s.text(x + bw / 2, y0 + 44, str(c), size=11, anchor='middle', mono=True)
        s.text(x + bw / 2, y0 + 62, format(c, '02b'), size=8.5, anchor='middle', fill=GRAY, mono=True)
        s.rect(x, y0 + 70, bw - 2, 20, fill='#e3ead9', stroke=INK, sw=0.5)
        s.text(x + bw / 2, y0 + 84, str(c >> 1), size=11, anchor='middle', mono=True)
        s.rect(x, y0 + 100, bw - 2, 20, fill='#d6e2d6', stroke=INK, sw=0.5)
        s.text(x + bw / 2, y0 + 114, str(c & 1), size=11, anchor='middle', mono=True)
        s.line(x + bw / 2 - 6, y0 + 50, x + bw / 2 - 6, y0 + 69, stroke=INK2, sw=0.5, arrow=True)
        s.line(x + bw / 2 + 6, y0 + 50, x + bw / 2 + 6, y0 + 99, stroke=INK2, sw=0.5, arrow=True)
    s.brace(x0, x0 + 8 * bw - 2, y0 + 126, f'byte 0 of each plane: hi = 0x{DA.raw[2]:02x}, lo = 0x{DA.raw[18]:02x} (bit 0 is bucket 0)', size=9.5)
    s.brace(x0 + 8 * bw, x0 + 16 * bw - 2, y0 + 126, f'byte 1: hi = 0x{DA.raw[3]:02x}, lo = 0x{DA.raw[19]:02x}', size=9.5)
    s.text(x0, y0 + 166, 'The 128 two-bit codes of a digest are stored as two 128-bit planes rather than 32 packed bytes,', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 180, 'so that a distance between two digests is a few 128-bit boolean operations and popcounts.', size=9.5, italic=True, fill=INK2)
    return s


def fig_costs():
    """L cost, Q cost, per-bucket body cost"""
    W, H = 900, 275
    s = SVG(W, H)
    # L
    p = Plot(s, 50, 30, 220, 160, (0, 12), (0, 150), xlabel='k = |L_a − L_b| (mod 256)', ylabel='L cost', xticks=[0, 2, 4, 6, 8, 10, 12], yticks=[0, 48, 96, 144])
    pts = [(k, T.l_cost(k)) for k in range(13)]
    for k, c in pts:
        s.dot(p.X(k), p.Y(c), r=3, fill=INK)
    p.line([(2, 24), (12, 144)], stroke=GRAY, sw=0.6, dash='2,2')
    s.text(p.X(6), p.Y(100), '0, 1, then 12k', size=9.5, italic=True, fill=INK2)
    # Q
    p2 = Plot(s, 340, 30, 220, 160, (0, 8), (0, 90), xlabel='k = circular |Q_a − Q_b| (mod 16)', ylabel='Q cost (each of Q1, Q2)', xticks=[0, 2, 4, 6, 8], yticks=[0, 24, 48, 72])
    for k in range(9):
        s.dot(p2.X(k), p2.Y(T.q_cost(k)), r=3, fill=INK)
    s.text(p2.X(3), p2.Y(70), '0, 1, then 12(k − 1)', size=9.5, italic=True, fill=INK2)
    # body matrix
    x0, y0 = 640, 50
    cw = 40
    s.text(x0 + 2 * cw, y0 - 24, 'body cost per bucket', size=10, anchor='middle', fill=INK2, italic=True)
    s.text(x0 - 6, y0 - 8, 'a \\ b', size=9, anchor='end', fill=GRAY, italic=True)
    for i in range(4):
        s.text(x0 + i * cw + cw / 2, y0 - 8, str(i), size=10, anchor='middle', fill=GRAY, mono=True)
        s.text(x0 - 8, y0 + i * cw + cw / 2 + 4, str(i), size=10, anchor='end', fill=GRAY, mono=True)
        for j in range(4):
            c = T.BODY_COST[abs(i - j)]
            s.rect(x0 + j * cw, y0 + i * cw, cw, cw, fill=['#fff', '#f3f1ea', '#e8e3d3', '#f6d9c9'][abs(i - j)], stroke=INK, sw=0.5)
            s.text(x0 + j * cw + cw / 2, y0 + i * cw + cw / 2 + 4, str(c), size=12, anchor='middle', mono=True)
    s.text(x0, y0 + 4 * cw + 18, '0, 1, 2 or 6 for |a − b| = 0, 1, 2, 3;', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 4 * cw + 32, 'summed over 128 buckets, plus', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 4 * cw + 46, '1 if the checksums differ.', size=9.5, italic=True, fill=INK2)
    return s


def fig_kernel_table():
    rows = [['a', 'b', 'hi_a lo_a', 'hi_b lo_b', 'X = lo_a⊕lo_b', 'Y = hi_a⊕hi_b', 'S = ¬(lo_a⊕hi_a)', 'X⊕Y', 'Y', 'X∧Y∧S', '1·(X⊕Y) + 1·Y + 5·(X∧Y∧S)', 'TLSH cost']]
    fills = {}
    for a in range(4):
        for b in range(4):
            ha, la, hb, lb = a >> 1, a & 1, b >> 1, b & 1
            X, Y, S = la ^ lb, ha ^ hb, 1 - (la ^ ha)
            t = (X ^ Y) + Y + 5 * (X & Y & S)
            rows.append([str(a), str(b), f'{ha} {la}', f'{hb} {lb}', str(X), str(Y), str(S), str(X ^ Y), str(Y), str(X & Y & S), str(t), str(T.BODY_COST[abs(a - b)])])
            if X & Y & S:
                fills[(len(rows) - 1, 9)] = F_HI
                fills[(len(rows) - 1, 10)] = F_HI
    return table_svg(rows, [26, 26, 70, 70, 90, 90, 105, 50, 36, 62, 190, 70], mono_cols=tuple(range(0, 10)), align=['end'] * 12, size=10, fills=fills)


def fig_simd():
    """the NEON evaluation: four 16-byte registers in, one byte-count vector out"""
    W, H = 1000, 300
    s = SVG(W, H)
    x0 = 120
    bw = 34
    def reg(y, name, vals, fill, note=None):
        s.text(x0 - 8, y + 15, name, size=10.5, anchor='end', mono=True)
        for i in range(16):
            s.rect(x0 + i * bw, y, bw, 22, fill=fill, stroke=INK, sw=0.5)
            if vals is not None:
                s.text(x0 + i * bw + bw / 2, y + 15, vals[i], size=9.5, anchor='middle', mono=True)
        if note:
            s.text(x0 + 16 * bw + 8, y + 15, note, size=9.5, fill=INK2, italic=True)
    rnd = random.Random(11)
    q = DA; r = ROWS[12345]
    la, ha = q.lo.to_bytes(16, 'little'), q.hi.to_bytes(16, 'little')
    lb, hb = r.lo.to_bytes(16, 'little'), r.hi.to_bytes(16, 'little')
    X = bytes(a ^ b for a, b in zip(la, lb)); Y = bytes(a ^ b for a, b in zip(ha, hb)); S = bytes((~(a ^ b)) & 255 for a, b in zip(la, ha))
    B = bytes(x & y & z for x, y, z in zip(X, Y, S)); XY = bytes(x ^ y for x, y in zip(X, Y))
    cnt = [bin(XY[i]).count('1') + bin(Y[i]).count('1') + 5 * bin(B[i]).count('1') for i in range(16)]
    hx = lambda bs: ['%02x' % v for v in bs]
    reg(20, 'lo_a, hi_a, s', None, F_HI, 'query planes and S = ¬(lo_a ⊕ hi_a):')
    s.text(x0 + 16 * bw + 8, 20 + 29, 'three registers, loaded once per query', size=9.5, fill=INK2, italic=True)
    s.text(x0 + 8 * bw, 35, 'held for the whole scan', size=9, anchor='middle', fill=GRAY, italic=True)
    reg(60, 'lo_r', hx(lb), '#d6e2d6', 'row planes: two 16-byte loads')
    reg(86, 'hi_r', hx(hb), '#e3ead9')
    reg(122, 'X = lo_a⊕lo_r', hx(X), F_NUM)
    reg(148, 'Y = hi_a⊕hi_r', hx(Y), F_NUM)
    reg(174, 'B = X∧Y∧S', hx(B), F_HI2)
    reg(214, 'cnt', [str(c) for c in cnt], '#f0dcc8', 'per byte: popcnt(X⊕Y) + popcnt(Y)')
    s.text(x0 + 16 * bw + 8, 214 + 29, '+ 5·popcnt(B)   (vcnt, shifts, adds)', size=9.5, fill=INK2, italic=True)
    s.line(x0 + 16 * bw / 2, 236, x0 + 16 * bw / 2, 262, stroke=INK, sw=1, arrow=True)
    s.text(x0 + 16 * bw / 2 + 8, 256, 'vaddlvq_u8: one horizontal sum', size=9.5, fill=INK2, italic=True)
    s.text(x0 + 16 * bw / 2, 282, f'body distance = {sum(cnt)}', size=11, anchor='middle', mono=True)
    s.text(x0 + 16 * bw / 2 + 120, 282, f'(checked: {T.body_diff(q, r)} by the per-bucket table)', size=9.5, fill=INK2, italic=True)
    return s


def fig_staircase():
    W, H = 900, 300
    s = SVG(W, H)
    # left: the four points
    cx, cy, u = 170, 170, 90
    pts = {0: (1, 0), 1: (0, 0), 2: (0, 1), 3: (-1, 1)}
    def P(x, y): return (cx + x * u, cy - y * u)
    s.line(cx - 1.4 * u, cy, cx + 1.4 * u, cy, stroke=LIGHT, sw=0.6)
    s.line(cx, cy + 0.4 * u, cx, cy - 1.4 * u, stroke=LIGHT, sw=0.6)
    edges = [((0, 1), 1, 1), ((1, 2), 1, 1), ((2, 3), 1, 1), ((0, 2), 2, 2), ((1, 3), 2, 2), ((0, 3), 5, 6)]
    for (a, b), d2, cost in edges:
        (xa, ya), (xb, yb) = P(*pts[a]), P(*pts[b])
        s.line(xa, ya, xb, yb, stroke=INK if cost == d2 else Q_RED, sw=1 if cost == d2 else 1.4, dash=None if d2 < 5 else '4,3')
        mx, my = (xa + xb) / 2, (ya + yb) / 2
        off = {(0, 1): (0, 14), (1, 2): (-14, 0), (2, 3): (0, -8), (0, 2): (12, -8), (1, 3): (-14, -6), (0, 3): (8, 18)}[(a, b)]
        s.text(mx + off[0], my + off[1], f'{d2}' + (f' (TLSH {cost})' if cost != d2 else ''), size=9.5, anchor='middle', fill=INK if cost == d2 else Q_RED, italic=True)
    for c, (x, y) in pts.items():
        X, Y = P(x, y)
        s.circle(X, Y, 9, fill=CODE_FILL[c], stroke=INK, sw=0.8)
        s.text(X, Y + 4, str(c), size=10.5, anchor='middle', mono=True)
        pos = {0: (X + 12, Y + 16, 'start'), 1: (X - 12, Y + 18, 'end'), 2: (X + 12, Y - 10, 'start'), 3: (X - 12, Y - 10, 'end')}[c]
        s.text(pos[0], pos[1], f'({x}, {y})', size=9, fill=INK2, anchor=pos[2])
    s.text(cx - 1.4 * u, cy + 0.4 * u + 24, 'one bucket = one 2-D block of the embedding; code c ↦ a corner of the staircase', size=9.5, italic=True, fill=INK2)
    # right: table of squared distances vs costs
    x0, y0 = 480, 50
    cw, rh = 54, 24
    s.text(x0, y0 - 24, 'squared Euclidean distance between corners, and the TLSH cost', size=10, italic=True, fill=INK2)
    hdr = ['pair', '|a−b|', 'emb²', 'TLSH', 'slack']
    for j, hname in enumerate(hdr):
        s.text(x0 + j * cw + cw / 2, y0 + 15, hname, size=10, anchor='middle', fill=INK2, italic=True)
    s.line(x0, y0 + rh, x0 + 5 * cw, y0 + rh, stroke=INK2, sw=0.6)
    for i, ((a, b), d2, cost) in enumerate(edges):
        y = y0 + (i + 1) * rh
        vals = [f'{a}, {b}', str(abs(a - b)), str(d2), str(cost), str(cost - d2)]
        for j, v in enumerate(vals):
            s.text(x0 + j * cw + cw / 2, y + 16, v, size=10.5, anchor='middle', mono=True, fill=Q_RED if (j == 4 and v != '0') else INK)
    s.line(x0, y0 + 7 * rh, x0 + 5 * cw, y0 + 7 * rh, stroke=INK2, sw=0.6)
    s.text(x0, y0 + 7 * rh + 20, 'Every pair has emb² ≤ cost, so summed over the 128 buckets', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 7 * rh + 34, 'the body embedding distance never exceeds the body cost.', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 7 * rh + 54, 'Why not 6 for (0, 3)? Through corner 2 the triangle inequality', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 7 * rh + 68, 'gives d(0,3) ≤ d(0,2) + d(2,3) = √2 + 1, so d² ≤ 5.83; with', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + 7 * rh + 82, 'coordinates in {−1, 0, 1} the best integer value is 5.', size=9.5, italic=True, fill=INK2)
    return s


def fig_vector_layout():
    W, H = 960, 120
    s = SVG(W, H)
    x0, y0 = 20, 30
    total = 264
    scale = 900 / total
    blocks = [(0, 256, '#e3ead9', 'body: 128 buckets × (x, y)'), (256, 1, F_HI, 'L'), (257, 2, F_HI2, 'Q1'), (259, 2, F_HI2, 'Q2'), (261, 3, F_NUM, 'chk')]
    for (a, n, fill, name) in blocks:
        x = x0 + a * scale; w = n * scale
        s.rect(x, y0, w, 30, fill=fill, stroke=INK, sw=0.6)
        if n > 20:
            s.text(x + w / 2, y0 + 19, name, size=10.5, anchor='middle')
        if a == 0:
            s.text(x, y0 - 6, str(a), size=8.5, fill=INK2, mono=True)
    s.text(x0 + 264 * scale, y0 - 6, '264', size=8.5, fill=INK2, mono=True, anchor='end')
    # bucket pair ticks in the body
    for i in range(0, 256, 2):
        s.line(x0 + i * scale, y0 + 30, x0 + i * scale, y0 + 33, stroke=INK2, sw=0.3)
    s.text(x0 + 2 * scale, y0 + 44, 'dims 2i, 2i+1 = (x, y) of bucket i', size=9, fill=INK2, italic=True)
    # labels for the tail with leaders
    tail = [(256.5, 'L: the length byte as a float (dim 256)'), (258, 'Q1 on a 16-gon (257, 258)'), (260, 'Q2 on a 16-gon (259, 260)'), (262.5, 'checksum bits 0–2, each × 1/√3 (261–263)')]
    for k, (d, lab) in enumerate(tail):
        x = x0 + d * scale
        ly = y0 + 46 + k * 13
        s.line(x, y0 + 30, x, ly - 3, stroke=INK2, sw=0.5)
        s.text(x + 3, ly, lab, size=9, fill=INK2, italic=True, anchor='end')
    return s


def fig_qgon():
    W, H = 900, 320
    s = SVG(W, H)
    cx, cy, R = 150, 150, 100
    s.circle(cx, cy, R, fill='none', stroke=LIGHT, sw=0.6, dash='3,3')
    pts = [(cx + R * math.cos(2 * math.pi * q / 16), cy - R * math.sin(2 * math.pi * q / 16)) for q in range(16)]
    s.polyline(pts, stroke=INK, sw=0.8, close=True)
    for q, (x, y) in enumerate(pts):
        s.circle(x, y, 7, fill=F_HI2 if q in (3, 5) else '#fff', stroke=INK, sw=0.7)
        s.text(x, y + 3.5, str(q), size=8.5, anchor='middle', mono=True)
    # chord 3 -> 5 (k = 2) and 3 -> 7 (k = 4)
    s.line(*pts[3], *pts[5], stroke=Q_RED, sw=1.2)
    s.line(*pts[3], *pts[7], stroke=Q_RED, sw=1.2, dash='4,3')
    s.text(20, cy + R + 30, 'a regular 16-gon of radius 1/(2 sin(π/16)) ≈ 2.563:', size=9.5, italic=True, fill=INK2)
    s.text(20, cy + R + 44, 'adjacent values exactly 1 apart. Chord 3–5 (k = 2): length² 3.85', size=9.5, italic=True, fill=INK2)
    s.text(20, cy + R + 58, 'against TLSH cost 12; chord 3–7 (k = 4): 13.1 against 36.', size=9.5, italic=True, fill=INK2)
    # bars: chord² vs cost
    p = Plot(s, 420, 30, 440, 200, (0.5, 8.5), (0, 90), xlabel='circular difference k', ylabel='squared distance / cost', xticks=list(range(1, 9)), yticks=[0, 12, 24, 36, 48, 60, 72, 84])
    for k in range(1, 9):
        chord2 = (math.sin(math.pi * k / 16) / math.sin(math.pi / 16)) ** 2
        cost = T.q_cost(k)
        s.rect(p.X(k - 0.3), p.Y(cost), p.X(k) - p.X(k - 0.3), p.Y(0) - p.Y(cost), fill=F_HASH, stroke=INK, sw=0.5)
        s.rect(p.X(k), p.Y(chord2), p.X(k + 0.3) - p.X(k), p.Y(0) - p.Y(chord2), fill=Q_RED, stroke=INK, sw=0.5, opacity=0.7)
        s.text(p.X(k + 0.15), p.Y(chord2) - 3, f'{chord2:.1f}', size=8, anchor='middle', fill=Q_RED)
        s.text(p.X(k - 0.15), p.Y(cost) - 3, str(cost), size=8, anchor='middle', fill=INK2)
    s.rect(p.X(5.5), p.Y(85), 10, 8, fill=F_HASH, stroke=INK, sw=0.5); s.text(p.X(5.5) + 14, p.Y(85) + 7, 'TLSH cost', size=9)
    s.rect(p.X(5.5), p.Y(78), 10, 8, fill=Q_RED, opacity=0.7); s.text(p.X(5.5) + 14, p.Y(78) + 7, 'chord² (the embedding)', size=9)
    return s


def fig_lbound():
    W, H = 900, 230
    s = SVG(W, H)
    p = Plot(s, 60, 24, 500, 160, (0, 14), (0, 200), xlabel='k = |L_a − L_b|', ylabel='cost', xticks=[0, 2, 4, 6, 8, 10, 12, 14], yticks=[0, 48, 96, 144, 196])
    p.line([(k, k * k) for k in range(0, 15)], stroke=Q_RED, sw=1.2)
    for k in range(15):
        s.dot(p.X(k), p.Y(T.l_cost(k)), r=2.5, fill=INK)
    p.hline(144, label='144', stroke=GRAY)
    p.vline(12, stroke=GRAY, label='k = 12', label_dy=-4)
    s.text(p.X(9), p.Y(60), 'k² (embedding)', size=9.5, fill=Q_RED, italic=True)
    s.text(p.X(4.3), p.Y(80), 'TLSH: 12k', size=9.5, fill=INK, italic=True)
    s.text(600, 60, 'L is a single linear coordinate.', size=10, italic=True, fill=INK2)
    s.text(600, 76, 'k² ≤ 12k exactly while k ≤ 12, and at', size=10, italic=True, fill=INK2)
    s.text(600, 92, 'k = 12 the L term alone is 144: the', size=10, italic=True, fill=INK2)
    s.text(600, 108, 'distance beyond which TLSH carries no', size=10, italic=True, fill=INK2)
    s.text(600, 124, 'similarity information. Hence the cap:', size=10, italic=True, fill=INK2)
    s.text(600, 140, 'the full 264-dim bound holds for diff ≤ 144.', size=10, italic=True, fill=INK2)
    s.text(600, 164, 'The index never uses this coordinate:', size=10, italic=True, fill=INK2)
    s.text(600, 180, 'L is constant inside a cell.', size=10, italic=True, fill=INK2)
    return s


def fig_bound_scatter():
    """diff vs squared embedding distance on perturbed pairs from the real rows"""
    rnd = random.Random(21)
    pts = []
    for _ in range(600):
        base = ROWS[rnd.randrange(len(ROWS))]
        codes = base.codes()
        for _ in range(rnd.randint(1, 40)):
            i = rnd.randrange(128); codes[i] = (codes[i] + rnd.choice([1, 2, 3])) & 3
        L = (base.L + rnd.choice([0, 0, 0, 1, -1, 2, -2, 3])) & 255
        q1 = (base.q1() + rnd.choice([0, 0, 0, 1, -1, 2])) & 15
        q2 = (base.q2() + rnd.choice([0, 0, 0, 1, -1])) & 15
        chk = base.checksum ^ rnd.choice([0, 0, 1, 5])
        q = T.Digest.from_parts(L, q1, q2, chk, codes)
        d = T.diff(base, q); e2 = T.embed_dist2(base, q)
        if d <= 200: pts.append((d, e2))
    W, H = 900, 330
    s = SVG(W, H)
    p = Plot(s, 60, 20, 500, 260, (0, 200), (0, 200), xlabel='TLSH distance diff(a, b)', ylabel='‖φ(a) − φ(b)‖²', xticks=[0, 50, 100, 144, 200], yticks=[0, 50, 100, 144, 200])
    p.line([(0, 0), (200, 200)], stroke=GRAY, sw=0.8, dash='4,3')
    p.vline(144, stroke=GRAY, label='bound guaranteed here', label_dy=-6)
    p.points(pts, r=2, fill=S_BLUE, opacity=0.6)
    ratio = sum(e / d for d, e in pts if 0 < d <= 144) / max(1, sum(1 for d, e in pts if 0 < d <= 144))
    below = all(e <= d + 1e-6 for d, e in pts if d <= 144)
    s.text(600, 60, f'{len(pts)} pairs: a row of the real set', size=10, italic=True, fill=INK2)
    s.text(600, 76, 'against a mutated copy of it', size=10, italic=True, fill=INK2)
    s.text(600, 92, '(1–40 bucket codes changed, L, Q and', size=10, italic=True, fill=INK2)
    s.text(600, 108, 'checksum jittered), computed here.', size=10, italic=True, fill=INK2)
    s.text(600, 132, f'Every point with diff ≤ 144 lies on or', size=10, italic=True, fill=INK2)
    s.text(600, 148, f'below the diagonal: {"verified" if below else "VIOLATED"}.', size=10, italic=True, fill=Q_RED if not below else INK2)
    s.text(600, 172, f'Mean ratio emb² / diff over them: {ratio:.2f}', size=10, italic=True, fill=INK2)
    s.text(600, 188, '(the docs report 0.78 on the family corpus).', size=10, italic=True, fill=INK2)
    return s


def fig_cells_heatmap():
    d = FX['inc_master']
    cells = d['cell_rows']
    Ls = sorted(set(c >> 8 for c, n in cells))
    Lmin, Lmax = min(Ls), max(Ls)
    W = 960
    cw = 3.4
    ch = 5
    x0, y0 = 60, 30
    H = y0 + (Lmax - Lmin + 1) * ch + 72
    s = SVG(W, H)
    mx = max(n for c, n in cells)
    for c, n in cells:
        L, Q = c >> 8, c & 255
        t = math.log(n + 1) / math.log(mx + 1)
        # blend from pale to deep blue
        r = int(235 - t * (235 - 61)); g = int(235 - t * (235 - 107)); b = int(240 - t * (240 - 142))
        s.rect(x0 + Q * cw, y0 + (L - Lmin) * ch, cw, ch, fill=f'rgb({r},{g},{b})')
    for L in range(Lmin, Lmax + 1, 5):
        s.text(x0 - 6, y0 + (L - Lmin) * ch + ch, str(L), size=8.5, anchor='end', fill=INK2, mono=True)
    s.text(x0 - 6, y0 - 8, 'L', size=9.5, anchor='end', fill=INK2, italic=True)
    for q1 in range(16):
        s.text(x0 + q1 * 16 * cw, y0 + (Lmax - Lmin + 1) * ch + 12, f'{q1:x}', size=8.5, fill=INK2, mono=True)
        s.line(x0 + q1 * 16 * cw, y0, x0 + q1 * 16 * cw, y0 + (Lmax - Lmin + 1) * ch, stroke='#fff', sw=0.6)
    s.text(x0 + 256 * cw, y0 + (Lmax - Lmin + 1) * ch + 26, 'Q byte: Q1 (groups of 16) then Q2', size=9, anchor='end', fill=INK2, italic=True)
    s.text(x0, H - 18, f'test/inc_master.hset: {d["n"]:,} rows in {d["nonempty_cells"]:,} non-empty cells of 65 536; darker = more rows (log scale, up to {mx}). Rows live where L is 17–53: a synthetic corpus of mid-sized files.', size=9.5, italic=True, fill=INK2)
    s.text(x0, H - 4, 'Q1 and Q2 each take all 16 values, so a given L spreads over ~256 cells; a query\'s header cost grows with its circular distance from the query\'s own cell in this grid.', size=9.5, italic=True, fill=INK2)
    return s


def fig_bisect_tree():
    W, H = 900, 300
    s = SVG(W, H)
    def node(x, y, w, label, fill, sub=None):
        s.rect(x - w / 2, y - 14, w, 28, fill=fill, stroke=INK, sw=0.7, rx=3)
        s.text(x, y - 1 if sub else y + 4, label, size=10, anchor='middle')
        if sub: s.text(x, y + 11, sub, size=8.5, anchor='middle', fill=INK2, italic=True)
    node(450, 30, 220, 'cell: m = 11 000 rows', F_NUM, 'm > 4096: split by two far pivots')
    node(260, 90, 170, '5 200 rows', F_NUM, 'still > 4096: split again')
    node(640, 90, 170, '5 800 rows', F_NUM, 'split again')
    leaves = [(150, 150, '2 100'), (370, 150, '3 100'), (540, 150, '2 900'), (750, 150, '2 900')]
    for x, y, lab in leaves:
        node(x, y, 120, f'{lab} rows', '#e3ead9', '≤ 4096: flat integer k-means')
    for (a, b) in [((450, 44), (260, 76)), ((450, 44), (640, 76)), ((260, 104), (150, 136)), ((260, 104), (370, 136)), ((640, 104), (540, 136)), ((640, 104), (750, 136))]:
        s.line(a[0], a[1], b[0], b[1], stroke=INK2, sw=0.7, arrow=True)
    # lists under leaves
    y = 215
    s.text(20, y - 20, 'lists, in depth-first order of the tree (each leaf yields ⌈s / 32⌉ lists, ids ascending inside a list):', size=9.5, italic=True, fill=INK2)
    x = 20
    rnd = random.Random(2)
    colors = ['#e3ead9', '#dbe6ee', '#f3e6cf', '#e9dfe6']
    for li, (lx, ly, lab) in enumerate(leaves):
        n = math.ceil(int(lab.replace(' ', '')) / 32)
        shown = min(n, 22)
        for k in range(shown):
            s.rect(x, y, 8, 18, fill=colors[li], stroke=INK, sw=0.4)
            x += 9
        s.text(x - shown * 9 / 2, y + 32, f'leaf {li}: {n} lists', size=8.5, anchor='middle', fill=INK2, italic=True)
        s.line(lx, ly + 14, x - shown * 9 / 2, y - 3, stroke=LIGHT, sw=0.5)
        x += 16
    s.text(20, y + 60, 'A cell with at most 4096 rows is a single leaf: k-means into ⌈m / 32⌉ lists straight away, which is every cell of the real file above (largest cell: 175 rows, 6 lists).', size=9.5, italic=True, fill=INK2)
    return s


def synth_cluster_points(seed=4, nclust=3, per=16):
    rnd = random.Random(seed)
    pts = []
    centers = [(60, 70), (190, 60), (120, 170)]
    for ci, (cx, cy) in enumerate(centers[:nclust]):
        for _ in range(per):
            pts.append((cx + rnd.gauss(0, 22), cy + rnd.gauss(0, 20), ci))
    return pts


def fig_pivot_split():
    W, H = 900, 280
    s = SVG(W, H)
    pts = [(x * 1.1 + 40, y + 30, c) for x, y, c in synth_cluster_points(seed=7, per=22)]
    def dist(a, b): return math.hypot(a[0] - b[0], a[1] - b[1])
    p0 = pts[5]
    A = max(pts, key=lambda p: dist(p, p0))
    Bp = max(pts, key=lambda p: dist(p, A))
    # panel 1: p0 and A
    def panel(ox, title):
        s.text(ox, 20, title, size=10, italic=True, fill=INK2)
        s.rect(ox, 28, 280, 215, fill='none', stroke=LIGHT, sw=0.6)
    panel(0, '1. a random member p₀; A = the member farthest from p₀')
    for x, y, c in pts:
        s.dot(x, y, r=2.5, fill=INK2, opacity=0.6)
    s.circle(p0[0], p0[1], 5, fill=F_HI2, stroke=INK, sw=0.8); s.text(p0[0] + 8, p0[1] + 4, 'p₀', size=10)
    s.circle(A[0], A[1], 5, fill=Q_RED, stroke=INK, sw=0.8); s.text(A[0] + 8, A[1] + 4, 'A', size=10)
    s.line(p0[0], p0[1], A[0], A[1], stroke=GRAY, sw=0.6, dash='3,2')
    panel(300, '2. B = the member farthest from A')
    for x, y, c in pts:
        s.dot(x + 300, y, r=2.5, fill=INK2, opacity=0.6)
    s.circle(A[0] + 300, A[1], 5, fill=Q_RED, stroke=INK, sw=0.8); s.text(A[0] + 308, A[1] + 4, 'A', size=10)
    s.circle(Bp[0] + 300, Bp[1], 5, fill=S_BLUE, stroke=INK, sw=0.8); s.text(Bp[0] + 308, Bp[1] + 4, 'B', size=10)
    s.line(A[0] + 300, A[1], Bp[0] + 300, Bp[1], stroke=GRAY, sw=0.6, dash='3,2')
    panel(600, '3. each member goes to its nearer pivot (ties to A)')
    na = nb = 0
    for x, y, c in pts:
        toA = dist((x, y), A) <= dist((x, y), Bp)
        s.dot(x + 600, y, r=2.5, fill=Q_RED if toA else S_BLUE, opacity=0.8)
        na += toA; nb += not toA
    # perpendicular bisector
    mx, my = (A[0] + Bp[0]) / 2 + 600, (A[1] + Bp[1]) / 2
    dx, dy = Bp[0] - A[0], Bp[1] - A[1]
    L = math.hypot(dx, dy); ux, uy = -dy / L, dx / L
    s.line(mx - ux * 140, my - uy * 140, mx + ux * 140, my + uy * 140, stroke=GRAY, sw=0.6, dash='3,2')
    s.text(610, 238, f'{na} rows to A, {nb} to B', size=8.5, fill=INK2, italic=True)
    s.text(0, 258, 'Schematic in two dimensions; the real split runs in the 256-dimensional body embedding with the integer kernel: O(m) kernel calls per level, no floating point.', size=9.5, italic=True, fill=INK2)
    s.text(0, 272, 'If a side would get under 1/8 of the rows, the node is sorted by (distance to A, row) and cut at the median instead, so every split makes progress.', size=9.5, italic=True, fill=INK2)
    return s


def fig_int_kmeans():
    W, H = 900, 300
    s = SVG(W, H)
    # left: schematic k-means on the synthetic points with centroid = (S, n)
    pts = [(x * 1.1 + 40, y + 40, c) for x, y, c in synth_cluster_points(seed=9, per=18)]
    s.text(0, 20, 'flat integer k-means in a leaf: centroids are exact integer sums', size=10, italic=True, fill=INK2)
    cols = [Q_RED, S_BLUE, G_GREEN]
    cents = []
    for ci in range(3):
        mem = [(x, y) for x, y, c in pts if c == ci]
        Sx, Sy = sum(x for x, y in mem), sum(y for x, y in mem)
        n = len(mem)
        cents.append((Sx, Sy, n))
        for x, y in mem:
            s.dot(x, y, r=2.5, fill=cols[ci], opacity=0.7)
            s.line(x, y, Sx / n, Sy / n, stroke=cols[ci], sw=0.3, opacity=0.5)
        s.rect(Sx / n - 5, Sy / n - 5, 10, 10, fill='#fff', stroke=cols[ci], sw=1.5)
        s.text(Sx / n + 10, Sy / n - 6, f'(S, n) = ({int(Sx)}, {int(Sy)}; {n})', size=8.5, fill=cols[ci], italic=True)
    s.text(0, 256, 'A centroid is never divided: it is stored as the coordinate', size=9.5, italic=True, fill=INK2)
    s.text(0, 270, 'sum S (int32 per dimension) and the member count n.', size=9.5, italic=True, fill=INK2)
    s.text(0, 284, 'Schematic in 2-D; the real coordinates are the 256 body dims, each in {−1, 0, 1}.', size=9.5, italic=True, fill=INK2)
    # right: the comparison
    x0 = 480
    s.text(x0, 50, 'which centroid is nearer to a row x?', size=10.5, italic=True, fill=INK2)
    lines = [
        ('squared distance to (S, n):', '‖x − S/n‖²  =  ‖n·x − S‖² / n²  =  N / n²'),
        ('with', 'N = n²‖x‖² − 2n (x·S) + ‖S‖²,  an integer'),
        ('compare a and b exactly:', 'N_a / n_a² < N_b / n_b²   ⇔   N_a · n_b² < N_b · n_a²'),
        ('bound:', '|n·x_j − S_j| ≤ 2n, so N ≤ 256 · 4n² = 2¹⁰ n²;'),
        ('', 'with n ≤ 4096 = 2¹², N·n² ≤ 2³⁴ · 2²⁴ = 2⁵⁸ < 2⁶⁴'),
    ]
    y = 74
    for a, b in lines:
        s.text(x0, y, a, size=9.5, fill=INK2, italic=True)
        s.text(x0 + 150, y, b, size=10, mono=True)
        y += 21
    s.text(x0, y + 10, 'So the assignment is decided by 64-bit integer', size=9.5, italic=True, fill=INK2)
    s.text(x0, y + 24, 'multiplications, bit-identical on every machine,', size=9.5, italic=True, fill=INK2)
    s.text(x0, y + 38, 'and the TIVF bytes are reproducible.', size=9.5, italic=True, fill=INK2)
    s.text(x0, y + 62, 'Rounds: k-means++ seeding with the kernel, then', size=9.5, italic=True, fill=INK2)
    s.text(x0, y + 76, 'at most 10 rounds of reassign / recompute S, n.', size=9.5, italic=True, fill=INK2)
    return s


def fig_one_center():
    """a real list: the member minimizing the max distance, and the radius; drawn as a distance matrix"""
    d = FX['inc_master']['two_list_cell']
    lst = d['lists'][0]
    ids = lst['ids']
    digs = [T.Digest(bytes.fromhex(d['digests'][str(i)])) for i in ids]
    n = len(ids)
    W, H = 900, 60 + n * 22 + 60
    s = SVG(W, H)
    x0, y0 = 90, 50
    cw = 32
    s.text(x0, y0 - 30, f'list 0 of cell 0x{d["cell"]:04x} in test/inc_master.hset: squared body-embedding distance between every pair of its {n} members', size=10, italic=True, fill=INK2)
    rowmax = []
    for i in range(n):
        s.text(x0 - 6, y0 + i * 22 + 15, str(ids[i]), size=9, anchor='end', mono=True, fill=INK2)
        s.text(x0 + i * cw + cw / 2, y0 - 6, str(ids[i]), size=8, anchor='middle', mono=True, fill=INK2, rotate=-60)
        m = 0
        for j in range(n):
            v = T.emb_body2(digs[i], digs[j])
            m = max(m, v)
            t = v / 200
            s.rect(x0 + j * cw, y0 + i * 22, cw, 22, fill=f'rgb({int(255 - t * 120)},{int(248 - t * 150)},{int(240 - t * 160)})', stroke='#fff', sw=0.5)
            s.text(x0 + j * cw + cw / 2, y0 + i * 22 + 15, str(v), size=9, anchor='middle', mono=True, fill=INK if v < 120 else '#fff')
        rowmax.append(m)
        s.text(x0 + n * cw + 10, y0 + i * 22 + 15, f'max {m}', size=9.5, mono=True, fill=Q_RED if m == min(rowmax[:i+1]) and i == rowmax.index(min(rowmax)) else INK2)
    best = min(range(n), key=lambda i: (rowmax[i], ids[i]))
    s.rect(x0 - 2, y0 + best * 22, n * cw + 4, 22, fill='none', stroke=Q_RED, sw=1.5)
    s.text(x0 + n * cw + 70, y0 + best * 22 + 15, f'← 1-center: row {ids[best]} is the medoid, radius2 = {rowmax[best]}', size=10, fill=Q_RED, italic=True)
    s.text(x0, y0 + n * 22 + 20, f'The file stores medoid {lst["medoid"][:12]}… (row {ids[best]}) with radius2 = {lst["radius2"]}: the row whose farthest member is nearest.', size=9.5, italic=True, fill=INK2)
    s.text(x0, y0 + n * 22 + 34, 'Every member is within radius2 of it, which is all the search needs. Computing the 1-center is O(s²) kernel calls per list of s rows.', size=9.5, italic=True, fill=INK2)
    return s, ids[best], rowmax[best], lst['radius2']


def fig_index_stats():
    d = FX['inc_master']
    W, H = 900, 260
    s = SVG(W, H)
    # list sizes histogram
    sizes = dict(d['list_sizes'])
    p = Plot(s, 50, 30, 380, 170, (0, 70), (0, max(sizes.values()) * 1.05), xlabel='rows in a list', ylabel='lists', xticks=[0, 16, 32, 48, 64])
    for k, v in sizes.items():
        s.rect(p.X(k - 0.5), p.Y(v), p.X(k + 0.5) - p.X(k - 0.5), p.Y(0) - p.Y(v), fill=S_BLUE, opacity=0.8)
    p.vline(32, stroke=Q_RED, label='target T = 32', label_dy=-6)
    s.text(p.X(36), p.Y(max(sizes.values()) * 0.8), f'{d["lists"]:,} lists over {d["n"]:,} rows', size=9.5, italic=True, fill=INK2)
    s.text(p.X(36), p.Y(max(sizes.values()) * 0.7), f'mean {d["n"] / d["lists"]:.1f} rows per list;', size=9.5, italic=True, fill=INK2)
    s.text(p.X(36), p.Y(max(sizes.values()) * 0.6), 'small cells make small lists', size=9.5, italic=True, fill=INK2)
    r2 = dict(d['radius2'])
    p2 = Plot(s, 500, 30, 380, 170, (0, 260), (0, max(v for k, v in r2.items() if k > 0) * 1.05), xlabel='radius2 of a list (squared body-embedding distance)', ylabel='lists', xticks=[0, 64, 128, 192, 256])
    for k, v in r2.items():
        if k == 0: continue
        s.rect(p2.X(k - 0.5), p2.Y(v), p2.X(k + 0.5) - p2.X(k - 0.5), p2.Y(0) - p2.Y(v), fill=O_ORANGE, opacity=0.85)
    s.text(p2.X(130), p2.Y(max(v for k, v in r2.items() if k > 0) * 0.85), f'{r2.get(0, 0):,} lists have radius2 = 0', size=9.5, italic=True, fill=INK2)
    s.text(p2.X(130), p2.Y(max(v for k, v in r2.items() if k > 0) * 0.75), '(a single row, or identical bodies); off scale', size=9.5, italic=True, fill=INK2)
    lpc = dict(d['lists_per_cell'])
    s.text(50, H - 10, 'lists per non-empty cell: ' + ', '.join(f'{k} list{"s" if k > 1 else ""}: {v:,} cells' for k, v in lpc.items()), size=9.5, italic=True, fill=INK2)
    return s


def fig_list_bound():
    W, H = 900, 300
    s = SVG(W, H)
    cx, cy = 300, 160
    r = 85
    # medoid, radius, query
    qx, qy = 60, 90
    s.circle(cx, cy, r, fill=F_HASH, stroke=INK, sw=0.8)
    rnd = random.Random(3)
    for _ in range(14):
        a = rnd.uniform(0, 2 * math.pi); d = r * math.sqrt(rnd.uniform(0, 1))
        s.dot(cx + d * math.cos(a), cy + d * math.sin(a), r=2.5, fill=S_BLUE, opacity=0.7)
    s.dot(cx, cy, r=4, fill=INK)
    s.text(cx + 8, cy + 4, 'medoid m', size=10)
    s.line(cx, cy, cx + r * math.cos(0.9), cy - r * math.sin(0.9), stroke=INK2, sw=0.8)
    s.text(cx + 30, cy - 36, '√radius2', size=9.5, fill=INK2, italic=True)
    s.circle(qx, qy, 4, fill=Q_RED)
    s.text(qx - 8, qy - 8, 'query q', size=10, anchor='end', fill=Q_RED)
    s.line(qx, qy, cx, cy, stroke=Q_RED, sw=0.8, dash='4,3')
    s.text((qx + cx) / 2 + 30, (qy + cy) / 2 - 12, '√d2(q, m)', size=9.5, fill=Q_RED, italic=True)
    # the nearest point of the disc
    L = math.hypot(cx - qx, cy - qy)
    nx, ny = cx + (qx - cx) / L * r, cy + (qy - cy) / L * r
    s.line(qx, qy, nx, ny, stroke=G_GREEN, sw=2.2)
    s.text((qx + nx) / 2 - 20, (qy + ny) / 2 + 26, 'bound: √d2 − √radius2', size=9.5, fill=G_GREEN, italic=True)
    x0 = 470
    lines = [
        ('For every member r of the list, by the triangle inequality in the', INK2),
        ('body-embedding space:', INK2),
        ('', INK2),
        ('    √emb²(q, r)  ≥  √emb²(q, m) − √radius2', INK),
        ('', INK2),
        ('and for every pair, emb²(q, r) ≤ body(q, r) (Figure 6). So', INK2),
        ('', INK2),
        ('    body(q, r)  ≥  (√d2 − √radius2)²  =  b', INK),
        ('', INK2),
        ('The header cost ch is identical for every row of the cell. If', INK2),
        ('ch + b > τ, no row of the list can beat the k-th best found so far,', INK2),
        ('and the whole list is skipped. One kernel call per list decides it.', INK2),
        ('', INK2),
        ('The float bound is relaxed by 0.01 so rounding never prunes a row', INK2),
        ('that an exact computation would keep.', INK2),
    ]
    y = 50
    for t, col in lines:
        s.text(x0, y, t, size=10, fill=col, mono=(col == INK))
        y += 16
    return s


def fig_header_order(q, tau):
    """the (L, Q) grid around a query with header costs, and the visiting order"""
    W, H = 900, 350
    s = SVG(W, H)
    # Q grid 16 x 16
    x0, y0, cw = 40, 40, 17
    s.text(x0, y0 - 14, f'q_cost over the 256 Q bytes for the query (Q1 = {q.q1()}, Q2 = {q.q2()}); shaded ≤ τ − l_cost', size=10, italic=True, fill=INK2)
    for Q1 in range(16):
        s.text(x0 - 6, y0 + Q1 * cw + 12, f'{Q1:x}', size=8.5, anchor='end', fill=GRAY, mono=True)
        for Q2 in range(16):
            c = T.q_cost(T.mod_diff(Q1, q.q1(), 16)) + T.q_cost(T.mod_diff(Q2, q.q2(), 16))
            x, y = x0 + Q2 * cw, y0 + Q1 * cw
            fill = F_HI if c <= tau else '#fff'
            if c <= tau - 24: fill = F_HI
            if c <= 1: fill = Q_RED
            s.rect(x, y, cw, cw, fill=fill, stroke='#ddd', sw=0.4)
            if c <= tau:
                s.text(x + cw / 2, y + 12, str(c), size=7.5, anchor='middle', fill='#fff' if c <= 1 else INK, mono=True)
    for Q2 in range(16):
        s.text(x0 + Q2 * cw + cw / 2, y0 + 16 * cw + 11, f'{Q2:x}', size=8.5, anchor='middle', fill=GRAY, mono=True)
    s.text(x0 + 8 * cw, y0 + 16 * cw + 36, 'Q2 →', size=9, anchor='middle', fill=INK2, italic=True)
    s.text(x0 - 22, y0 + 8 * cw, 'Q1', size=9, anchor='end', fill=INK2, italic=True)
    # L strip
    lx, ly = 380, 60
    s.text(lx, ly - 14, f'l_cost by L around the query (L = {q.L})', size=10, italic=True, fill=INK2)
    for k in range(-8, 9):
        L = (q.L + k) & 255
        c = T.l_cost(abs(k))
        x = lx + (k + 8) * 28
        s.rect(x, ly, 28, 22, fill=Q_RED if c == 0 else (F_HI if c <= tau else '#fff'), stroke='#ccc', sw=0.4)
        s.text(x + 14, ly + 15, str(c), size=8.5, anchor='middle', fill='#fff' if c == 0 else INK, mono=True)
        s.text(x + 14, ly - 3, str(L), size=8, anchor='middle', fill=GRAY, mono=True)
    # visiting order
    l, l_c, qs, q_c = T.header_order(q)
    s.text(lx, ly + 50, 'the enumeration (translation of a static cost-sorted table, no sorting per query):', size=10, italic=True, fill=INK2)
    s.text(lx, ly + 68, 'L:  ' + ', '.join(f'{v}({c})' for v, c in list(zip(l, l_c))[:9]) + ', …', size=9.5, mono=True)
    s.text(lx, ly + 86, 'Q:  ' + ', '.join(f'{v:02x}({c})' for v, c in list(zip(qs, q_c))[:9]) + ', …', size=9.5, mono=True)
    s.text(lx, ly + 112, f'With τ = {tau}: the L loop stops after L ± 2 (cost 24; L ± 3 costs 36), and inside each L', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 126, 'the Q loop stops as soon as l_cost + q_cost exceeds τ. Cells are visited in', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 140, 'non-decreasing header cost: the cheapest neighbourhood first, so τ shrinks early.', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 164, 'Before any hit, τ = max_distance (144); after k hits, τ = the k-th best distance.', size=9.5, fill=INK2, italic=True)
    s.text(lx, ly + 178, 'The visiting order depends only on the query; which cells are non-empty, on the set.', size=9.5, fill=INK2, italic=True)
    return s


def run_query():
    """a real query against the real index: a perturbed member"""
    rnd = random.Random(5)
    base = ROWS[rnd.randrange(len(ROWS))]
    codes = base.codes()
    for _ in range(rnd.randint(2, 12)):
        i = rnd.randrange(128); codes[i] = (codes[i] + rnd.choice([1, 3])) & 3
    q = T.Digest.from_parts((base.L + rnd.choice([0, 0, 1, -1])) & 255, base.q1(), base.q2(), base.checksum, codes)
    brute = T.knn_brute(ROWS, q, 10, 144)
    trace = []
    res, stats = T.knn_ivf(IVF, ROWS, q, 10, 144, trace=trace)
    assert brute == res
    # stats over 50 queries
    agg = {'cells': 0, 'lists': 0, 'rows': 0}
    nq = 40
    for _ in range(nq):
        b2 = ROWS[rnd.randrange(len(ROWS))]
        cd = b2.codes()
        for _ in range(rnd.randint(2, 12)):
            i = rnd.randrange(128); cd[i] = (cd[i] + rnd.choice([1, 3])) & 3
        qq = T.Digest.from_parts((b2.L + rnd.choice([0, 0, 1, -1])) & 255, b2.q1(), b2.q2(), b2.checksum, cd)
        r2, st = T.knn_ivf(IVF, ROWS, qq, 10, 144)
        assert r2 == T.knn_brute(ROWS, qq, 10, 144)
        for k in agg: agg[k] += st[k]
    agg = {k: v / nq for k, v in agg.items()}
    return q, base, res, stats, trace, agg


def fig_search_trace(q, trace, res):
    rows = [['#', 'cell', 'L', 'Q1', 'Q2', 'header cost', 'τ before', 'lists', 'bounds evaluated', 'lists scanned', 'rows scanned', 'τ after']]
    hi = set()
    shown = []
    # first 14 visited cells, then the ones where tau changed, then the last
    changes = [i for i, t in enumerate(trace) if t['tau_out'] != t['tau_in']]
    idx = sorted(set(list(range(min(12, len(trace)))) + changes[:10] + [len(trace) - 1]))
    last = -1
    for i in idx:
        if i != last + 1:
            rows.append(['…'] + [''] * 11)
        t = trace[i]
        c = t['cell']
        rows.append([str(i), f'{c:04x}', str(c >> 8), str((c >> 4) & 15), str(c & 15), str(t['ch']), str(t['tau_in']), str(t['lists']), str(t['bounded']), str(t['scanned_lists']), str(t['rows']), str(t['tau_out'])])
        if t['tau_out'] != t['tau_in']:
            hi.add(len(rows) - 1)
        last = i
    return table_svg(rows, [30, 50, 36, 36, 36, 90, 70, 50, 110, 90, 90, 70], mono_cols=(1,), align=['end'] * 12, size=10, hi_rows=tuple(hi))


def fig_rows_scanned(agg):
    W, H = 900, 215
    s = SVG(W, H)
    data = [
        ('brute force, this file (49 997 rows)', 49997, INK),
        ('cell index only (1M, from the benchmarks)', 18900, S_BLUE),
        (f'TIVF, this file (mean of 40 queries)', agg['rows'], Q_RED),
        ('TIVF (1M, from the benchmarks)', 4850, Q_RED),
        ('brute force (1M, from the benchmarks)', 1000000, INK),
    ]
    data.sort(key=lambda t: -t[1])
    x0, y0, rh = 300, 20, 28
    xmin, xmax = 3, 6.2
    for i, (name, v, col) in enumerate(data):
        y = y0 + i * rh + 14
        s.text(x0 - 8, y + 4, name, size=10, anchor='end', fill=INK2)
        x = x0 + (math.log10(v) - xmin) / (xmax - xmin) * 500
        s.line(x0, y, x, y, stroke=LIGHT, sw=1)
        s.dot(x, y, r=4.5, fill=col)
        s.text(x + 8, y + 4, f'{v:,.0f}' if v >= 10 else f'{v:.1f}', size=9.5, mono=True)
    yax = y0 + len(data) * rh + 10
    s.line(x0, yax, x0 + 500, yax, stroke=INK2, sw=0.8)
    for e in range(3, 7):
        x = x0 + (e - xmin) / (xmax - xmin) * 500
        s.line(x, yax, x, yax + 4, stroke=INK2, sw=0.8)
        s.text(x, yax + 15, f'10{"³⁴⁵⁶"[e - 3]}', size=9, anchor='middle', fill=INK2)
    s.text(x0 + 500, yax + 30, 'rows whose distance is computed, per query (log scale)', size=9.5, anchor='end', fill=INK2, italic=True)
    return s


def fig_knn_api():
    W, H = 900, 150
    s = SVG(W, H)
    boxes = [(20, 'sfhash_hashset_tlsh_knn', 'picks INDEX when the file has a TIVF, else BRUTE', F_TYPE),
             (330, 'tlsh_knn_ivf', 'header order + list bounds + heap', F_HI),
             (330, 'tlsh_knn_brute', 'every row, same heap, same ties', F_HASH),
             (640, 'identical results', 'nearest first, ties by ascending row index; ≤ k rows with distance ≤ max_distance', F_NUM)]
    s.rect(20, 40, 260, 44, fill=F_TYPE, stroke=INK, sw=0.7, rx=3)
    s.text(150, 58, 'sfhash_hashset_tlsh_knn', size=10.5, anchor='middle', mono=True)
    s.text(150, 74, 'INDEX if the file has a TIVF, else BRUTE', size=9, anchor='middle', fill=INK2, italic=True)
    s.rect(330, 10, 260, 44, fill=F_HI, stroke=INK, sw=0.7, rx=3)
    s.text(460, 28, 'tlsh_knn_ivf', size=10.5, anchor='middle', mono=True)
    s.text(460, 44, 'header order + list bounds + heap', size=9, anchor='middle', fill=INK2, italic=True)
    s.rect(330, 74, 260, 44, fill=F_HASH, stroke=INK, sw=0.7, rx=3)
    s.text(460, 92, 'tlsh_knn_brute', size=10.5, anchor='middle', mono=True)
    s.text(460, 108, 'every row; the same heap and tie rule', size=9, anchor='middle', fill=INK2, italic=True)
    s.rect(640, 40, 250, 44, fill=F_NUM, stroke=INK, sw=0.7, rx=3)
    s.text(765, 58, 'the same answer', size=10.5, anchor='middle')
    s.text(765, 74, 'nearest first, ties by row index', size=9, anchor='middle', fill=INK2, italic=True)
    s.line(280, 55, 328, 34, stroke=INK2, sw=0.8, arrow=True)
    s.line(280, 70, 328, 94, stroke=INK2, sw=0.8, arrow=True)
    s.line(590, 34, 638, 55, stroke=INK2, sw=0.8, arrow=True)
    s.line(590, 94, 638, 70, stroke=INK2, sw=0.8, arrow=True)
    s.text(20, 140, 'sfhash_hashset_tlsh_knn_with selects a strategy explicitly; bench/vs_knn_eval checks the two agree on every query (exit status 3 on a mismatch).', size=9.5, italic=True, fill=INK2)
    return s


def build():
    body = []
    B = body.append
    q, base, res, stats, trace, agg = run_query()
    onec, best_id, best_r2, stored_r2 = fig_one_center()
    assert best_r2 == stored_r2

    B(f'''<p>TLSH is a similarity digest: two files that differ a little get digests that differ a little, and the TLSH <em>distance</em> between digests, a weighted sum of 128 bucket differences and a few header terms, scores how alike the files are. The question an hset must answer for TLSH is not "is this digest in the set" but "which rows are <em>near</em> this digest", and a sorted array does not help with that. This page builds, in order: the digest and its distance; a <em>lower-bound embedding</em> into Euclidean space; the <em>cell index</em> that makes the header part of the distance exact; the <em>TIVF index</em> that bounds the body part per list of rows; and the search that puts them together to answer k-nearest-neighbour queries exactly, touching a few thousand rows instead of millions.{sn('Everything numeric on this page is computed by the generator from the real 49 997-row TLSH set in <code>test/inc_master.hset</code> (its HDAT and TIVF payloads are copied into the build directory) with a Python re-implementation of the library\'s kernel and search, which it checks against brute force on every query it runs.')}</p>''')
    B('<ul class="toc">' + ''.join(f'<li><span class="n">{n}</span><a href="#{a}">{t}</a></li>' for n, t, a in [
        (1, 'The digest', 'the-digest'), (2, 'The distance', 'the-distance'), (3, 'Three popcounts', 'three-popcounts'),
        (4, 'The embedding', 'the-embedding'), (5, 'Cells: the header made exact', 'cells-the-header-made-exact'),
        (6, 'The TIVF index', 'the-tivf-index'), (7, 'Building the lists', 'building-the-lists'),
        (8, 'The search', 'the-search'), (9, 'A real query, traced', 'a-real-query-traced')]) + '</ul>')

    B(h2(1, 'The digest'))
    B('''<p>A TLSH digest has a three-byte header and a 32-byte body. The header is L, a logarithmic measure of the input length; Q1 and Q2, two quartile ratios packed in one byte; and a one-byte checksum. The body is 128 <em>buckets</em>, each holding a two-bit code (0–3) that says in which quartile that bucket's count fell. The familiar 70-character hex string is a transport encoding that swaps the nibbles of the header bytes and writes the body backwards; libhasher unpacks it once into the 36-byte canonical row of Figure 1, which is what the file stores.</p>''')
    B(fig(fig_hex_to_row(), 'From the hex form to the canonical row. The header bytes have their nibbles swapped back; the body bytes are reversed and their 2-bit codes are split into a high-bit plane and a low-bit plane.', 'wide'))
    B(fig(fig_planes(), 'The two bit planes, for the first sixteen buckets of the same digest. Bucket <i>i</i> contributes bit <i>i</i> of each plane; byte <i>i</i>/8, bit <i>i</i> mod 8.', 'wide'))

    B(h2(2, 'The distance'))
    B('''<p>The reference TLSH distance is a sum of independent terms. L contributes 0, 1 or 12k for a circular difference of k; Q1 and Q2 each contribute 0, 1 or 12(k − 1); the checksum contributes 1 when it differs; and each of the 128 buckets contributes 0, 1, 2 or 6 for a code difference of 0, 1, 2 or 3. Scores up to about 30 mean near-identical inputs, and above 100 or so the digests carry no similarity information at all.</p>''')
    B(fig(fig_costs(), 'The cost terms. Left and middle: the header terms as functions of the circular difference. Right: the body cost of one bucket for codes a and b.', 'wide'))

    B(h2(3, 'Three popcounts'))
    B('''<p>Summing 128 table lookups per pair is what the reference implementation does, at about 9.5 ns per row. The bit planes turn the body cost into bit arithmetic. With X the XOR of the low planes, Y the XOR of the high planes and S the mask of buckets where the first digest's two bits agree (codes 0 or 3), the per-bucket cost is exactly</p>
<pre>popcount(X ⊕ Y) + popcount(Y) + 5 · popcount(X ∧ Y ∧ S)</pre>
<p>as the sixteen cases of Figure 4 verify. The first term counts buckets whose codes differ by an odd amount, the second those whose high bit differs, and the third picks out the one expensive case, a 0 against a 3, which the first two terms have already charged 1 for.</p>''')
    B(fig(fig_kernel_table(), 'All sixteen code pairs. The last two columns agree on every row; the highlighted rows are the (0, 3) and (3, 0) cases that the third term lifts from 1 to 6.', 'wide'))
    B('''<p>Per query the kernel holds the query's planes and S in registers, so a row costs two 16-byte loads, three vector XOR/AND operations, three byte-wise popcounts and one horizontal sum. On arm64 NEON that is 0.55 ns per row, seventeen times the reference; on x86 the same expression runs on two 64-bit halves with the POPCNT instruction.</p>''')
    B(fig(fig_simd(), f'The NEON evaluation for the test digest against row 12 345 of the real set. Each of the sixteen lanes counts bits in its own byte; the final instruction adds the lanes.', 'wide'))

    B(h2(4, 'The embedding'))
    B('''<p>Pruning needs geometry: a way to say "no row in this group can be close" without visiting the rows. TLSH distance is not a Euclidean metric, but it can be <em>bounded below</em> by one. The embedding φ maps a digest to 264 float coordinates such that the squared Euclidean distance between two embeddings never exceeds their TLSH distance. Each cost term gets its own orthogonal block of coordinates, so the bound is the sum of per-term bounds, and each term is bounded by the tightest placement that the term's cost function allows.</p>''')
    B(fig(fig_staircase(), 'The body block. Each bucket is a 2-D block and its four codes are placed on a staircase; the squared distances 1, 1, 1, 2, 2, 5 sit under the TLSH costs 1, 1, 1, 2, 2, 6. Coordinates are in {−1, 0, 1}, so these distances are integers and the same three popcounts compute them (with 4 in place of 5).', 'wide'))
    B(fig(fig_vector_layout(), 'The 264 coordinates of φ. The body takes the first 256; then L, the two quartile ratios on a 16-gon each, and three checksum bits.', 'wide'))
    B(fig(fig_qgon(), 'Q1 and Q2 are circular (mod 16), so each is placed on a regular 16-gon whose edge is exactly 1, the TLSH cost of adjacent values. Chords grow much more slowly than TLSH\'s 12(k − 1), so the bound is loose but valid for every k.', 'wide'))
    B(fig(fig_lbound(), 'L is placed linearly. Its squared distance k² stays under TLSH\'s 12k only up to k = 12, which is where the L term alone reaches 144, so the full embedding\'s guarantee is stated for diff ≤ 144.', 'wide'))
    B('''<p>The guarantee is easy to check empirically, and the generator does so on pairs built from the real rows:</p>''')
    B(fig(fig_bound_scatter(), 'TLSH distance against squared embedding distance for 600 (row, mutated row) pairs. Below the diagonal everywhere within the guaranteed range; the embedding typically captures about three quarters of the distance.', 'wide'))
    B('''<p>The file does not store the float matrix of every row's φ (an early TVEC chunk did, and was removed): whoever needs it computes it from the rows with <code>sfhash_tlsh_embed</code>, about 0.6 µs per digest. The index below never needs it: it works on digests, with the integer body part of the embedding only.</p>''')

    B(h2(5, 'Cells: the header made exact'))
    B(f'''<p>The first two bytes of the canonical row, L and Q, are also the leading bytes of the sort key, so all rows with the same (L, Q1, Q2) are one contiguous run: a <em>cell</em>, one of 65 536, located by the 0x7400 hint. This has a consequence the embedding alone could not give. Within a cell the header part of the distance to a query is a constant, computed exactly once from three circular differences; only the checksum term (0 or 1) and the body vary from row to row. The header does not need to be embedded, bounded or approximated at all. It also removes the 144 cap: the L coordinate was the only reason for it.{sn('The first design grouped lists by L alone, with 264-dimensional float centroids. It was slower than the plain cell index (777 µs against 16 µs per query at 1M rows) and valid only up to distance 144. Grouping by cell made the header exact, cut the query to 44 µs, and the medoid-plus-integer-radius representation of the next section cut it to 26 µs; the NEON kernel and list size 32 brought it to 8 µs.')}</p>''')
    B(fig(fig_cells_heatmap(), 'The occupied cells of the real set, L down the side and the 256 Q bytes across. A real corpus concentrates in a few dozen L values and spreads over Q.', 'wide'))

    B(h2(6, 'The TIVF index'))
    B('''<p>Inside a cell the body still has to be searched. TIVF partitions each cell's rows into <em>lists</em> of about 32 rows that are close in body-embedding space, and summarises every list by two numbers the search can use without touching the rows: a <em>medoid</em>, a digest central to the list, and <em>radius2</em>, the largest squared body-embedding distance from that medoid to any member. The on-disk structure is the two-level CSR of the <a href="index.html#tlsh-hash-sections">format page</a>: cells → lists → row ids. The contract between writer and reader is only this: every member of a list lies within radius2 of its medoid. Any partition that keeps it gives an exact search; a good partition gives a fast one.</p>''')
    B(fig(fig_list_bound(), 'Why a medoid and a radius suffice. The query\'s distance to the medoid, minus the radius, is a floor on its distance to every member; if the floor plus the cell\'s header cost cannot beat the current k-th best, the list is skipped unread.', 'wide'))
    B(fig(fig_index_stats(), 'The real index: 5 909 lists over 49 997 rows in 5 437 cells. Most cells hold fewer than 32 rows and are a single list; the large cells are split into lists near the target size. Radii are squared embedding distances; a radius2 of 100 means the farthest member is 10 units from the medoid.', 'wide'))

    B(h2(7, 'Building the lists'))
    B('''<p>The default builder, BISECT, uses integer arithmetic only, so the index bytes are identical on every platform for the same rows. A cell of more than 4 096 rows is first split coarsely: two far-apart members are chosen as pivots and every row goes to the nearer one, recursively, until every node is at most 4 096 rows. Each node is then clustered flat by k-means into ⌈s/32⌉ lists over centroids that are exact integer sums.</p>''')
    B(fig(fig_bisect_tree(), 'The shape of a BISECT build for one large cell. Leaves are clustered independently; the lists are emitted in depth-first order so a later format version could add per-subtree bounds without re-clustering.', 'wide'))
    B(fig(fig_pivot_split(), 'The coarse split. Farthest-point pivots cost O(m) kernel calls and separate the node along its widest extent; the median fallback guarantees progress even when every body in the node is identical.', 'wide'))
    B(fig(fig_int_kmeans(), 'The flat clustering. Lloyd\'s rounds with integer centroids; the nearest centroid is decided by cross-multiplying two rational squared distances in 64 bits, with the static bound on node size making overflow impossible.', 'wide'))
    B('''<p>Finally each list gets its medoid: the exact <em>1-center</em>, the member whose maximum distance to the other members is smallest. That minimises radius2 among members and so minimises how far the list's bound can be from the truth.</p>''')
    B(fig(onec, f'The 1-center of a real list: the pairwise squared body-embedding distances of the 14 members of list 0 of cell 0x1186, with each row\'s maximum. Row {best_id} has the smallest maximum, {best_r2}, and that is exactly the medoid and radius2 the file stores for this list.', 'wide'))
    B(f'''<p>The alternative builder, KMEANS, runs ordinary float k-means++ over a whole cell and takes as medoid the member nearest each centroid; it produces lists of the same quality at ten to twenty times the build time, and its bytes depend on the compiler's float arithmetic. Build time is dominated by the largest cells: at 1M synthetic rows BISECT builds the index in 136 ms against 1.5 s, at 4M in 1.3 s against 26 s.{sn('Rejected along the way, by rows scanned per query at 1M: pure recursive bisection down to list size (13 533 rows, a hard two-way split cuts families across the boundary), flat k-medoids (11 627; a single row is a poor centre in 256 dimensions), and coalescing small lists in a fresh build (it pairs unrelated families into wide lists). BISECT with flat integer k-means scans 4 659 rows, k-means 4 848.')}</p>''')

    B(h2(8, 'The search'))
    B('''<p>Given a query q, k and a maximum distance, the search keeps a bounded max-heap of the k best (distance, row) pairs found so far, ordered so that the worst of them is on top; τ, the largest distance still worth finding, starts at max_distance and drops to the top's distance once the heap is full. Three nested prunings cut the work.</p>
<ol>
<li><em>Cells in header-cost order.</em> L values are visited as L, L±1, L±2, …, and for each, Q bytes in the order of a static table sorted by q_cost(k1) + q_cost(k2), translated to the query. Both loops stop as soon as their cost alone exceeds τ. No sorting happens per query.</li>
<li><em>Lists by their bound.</em> In a visited cell with several lists, one kernel call per medoid gives each list's floor b; lists with ch + b ≤ τ are scanned in increasing b, and the scan stops at the first that no longer passes, since τ only shrinks. A cell with a single list is scanned contiguously (its ids are the cell's own row range), and a list of fewer than four rows is scanned without evaluating its bound.</li>
<li><em>Rows.</em> A scanned row costs a checksum compare and one kernel evaluation; rows with distance ≤ τ go into the heap.</li>
</ol>''')
    B(fig(fig_header_order(q, 30), f'The header-cost landscape around the traced query (L = {q.L}, Q1 = {q.q1()}, Q2 = {q.q2()}), with the cells a search would consider at τ = 30 shaded. The red cell is the query\'s own.', 'wide'))
    B(fig(fig_knn_api(), 'Both strategies produce the same list. The brute-force scan uses the same heap and the same tie rule (ascending row index), so every test can assert equality.', 'wide'))

    B(h2(9, 'A real query, traced'))
    hexq = T.to_hex(q)
    B(f'''<p>The generator takes a row of the real set, mutates a few bucket codes and runs the search for k = 10 within distance 144, against the index and by brute force. The query digest is <code>{hexq[:24]}…</code>; its nearest rows are {", ".join(f"row {i} at distance {d}" for d, i in res[:3])}. The index visited {stats['cells']} cells, evaluated {stats['lists']} list bounds and computed {stats['rows']:,} row distances, out of {len(ROWS):,}, and returned the same ten rows as brute force.</p>''')
    B(fig(fig_search_trace(q, trace, res), 'The visited cells of the traced query in visiting order (the first twelve, every cell where τ changed, and the last). Highlighted rows tightened τ. Note how the header cost climbs while τ falls until the loops meet.', 'wide'))
    B(fig(fig_rows_scanned(agg), f'Rows whose distance is computed per query: brute force, the cell index alone, and the TIVF index, on this 50k-row file (mean over 40 queries: {agg["cells"]:.0f} cells, {agg["lists"]:.0f} bounds, {agg["rows"]:,.0f} rows) and on the 1M-row benchmark corpus.', 'wide'))
    B('''<p>On the 1M-row corpus the index answers a query in about 8 µs on an Apple M-series core against 566 µs for the kernel brute force and 9.5 ms for the reference implementation; on the VM\'s Xeon with 200 queries per set, 0.65 ms for member queries and 3.8 ms for uniformly random digests against 8.2 and 8.6 ms brute force. Random digests are far from everything, so τ stays large and pruning is weak; that is the regime where the bound\'s looseness shows.</p>''')
    return page('tlsh.html', 'TLSH, embedding and index', 'From a 36-byte similarity digest to a Euclidean lower bound, and from the bound to an exact nearest-neighbour index that reads a few thousand rows per query.', ''.join(body))
