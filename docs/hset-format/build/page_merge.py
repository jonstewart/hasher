"""merge.html: set operations by merging."""
import json, math, os, random
from svg import *
from common import *
import tlshlib as T

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, 'data', 'fixtures.json')))

DROP = '×'

# ---------------------------------------------------------------------------
# a worked two-pointer merge on short keys
# ---------------------------------------------------------------------------
LEFT = ['0b', '1c', '1c', '2f', '4a', '63', '7d', '9e']
RIGHT = ['1c', '2f', '38', '63', '63', '80', 'c4']


def merge_rows(op, L, R):
    """set semantics, as hset_merge.cpp merge_rows without record maps; returns (out, lmap, rmap, steps)"""
    lmap = [DROP] * len(L); rmap = [DROP] * len(R)
    out = []
    steps = []
    i = j = 0
    emit_left_only = op != 'intersect'; emit_right_only = op == 'union'; emit_both = op != 'difference'
    def skip_run(A, k):
        v = A[k]; k += 1
        while k < len(A) and A[k] == v: k += 1
        return k
    while i < len(L) or j < len(R):
        if i < len(L) and j < len(R):
            c = (L[i] > R[j]) - (L[i] < R[j])
        else:
            c = -1 if i < len(L) else 1
        li, rj = i, j
        if c < 0:
            emitted = emit_left_only
            if emitted: lmap[i] = len(out); out.append(('L', i, L[i]))
            i = skip_run(L, i)
        elif c > 0:
            emitted = emit_right_only
            if emitted: rmap[j] = len(out); out.append(('R', j, R[j]))
            j = skip_run(R, j)
        else:
            emitted = emit_both
            if emitted: lmap[i] = len(out); out.append(('L', i, L[i]))
            i = skip_run(L, i); j = skip_run(R, j)
        steps.append((li, rj, c, emitted, i, j))
    return out, lmap, rmap, steps


def fig_two_pointer(op):
    out, lmap, rmap, steps = merge_rows(op, LEFT, RIGHT)
    W, H = 900, 300
    s = SVG(W, H)
    bw, bh = 40, 24
    x0 = 70
    def row(y, label, vals, fills, maps=None, color=INK):
        s.text(x0 - 8, y + 16, label, size=10, anchor='end', fill=INK2, italic=True)
        for k, v in enumerate(vals):
            s.rect(x0 + k * bw, y, bw - 2, bh, fill=fills[k], stroke=INK, sw=0.5)
            s.text(x0 + k * bw + (bw - 2) / 2, y + 16, v, size=10.5, anchor='middle', mono=True)
            if maps is not None:
                s.text(x0 + k * bw + (bw - 2) / 2, y + bh + 12, str(maps[k]), size=9, anchor='middle', mono=True, fill=Q_RED if maps[k] == DROP else color)
    yl, yr, yo = 30, 110, 200
    lf = [F_HASH if lmap[k] != DROP else F_PAD for k in range(len(LEFT))]
    rf = ['#f3e6cf' if rmap[k] != DROP else F_PAD for k in range(len(RIGHT))]
    row(yl, 'left rows', LEFT, lf, lmap, G_GREEN)
    s.text(x0 + len(LEFT) * bw + 6, yl + 16, 'left (sorted; 1c twice: a duplicate)', size=9.5, fill=INK2, italic=True)
    s.text(x0 - 8, yl + bh + 12, 'lmap', size=9, anchor='end', fill=INK2, italic=True)
    row(yr, 'right rows', RIGHT, rf, rmap, O_ORANGE)
    s.text(x0 + len(RIGHT) * bw + 6, yr + 16, 'right (sorted; 63 twice)', size=9.5, fill=INK2, italic=True)
    s.text(x0 - 8, yr + bh + 12, 'rmap', size=9, anchor='end', fill=INK2, italic=True)
    of = [F_HASH if side == 'L' else '#f3e6cf' for side, k, v in out]
    row(yo, 'output rows', [v for side, k, v in out], of)
    for k, (side, idx, v) in enumerate(out):
        s.text(x0 + k * bw + (bw - 2) / 2, yo - 6, str(k), size=8.5, anchor='middle', fill=GRAY)
        if side == 'L':
            s.line(x0 + idx * bw + (bw - 2) / 2, yl + bh + 16, x0 + k * bw + (bw - 2) / 2, yo - 12, stroke=G_GREEN, sw=0.6, opacity=0.6)
        else:
            s.line(x0 + idx * bw + (bw - 2) / 2, yr + bh + 16, x0 + k * bw + (bw - 2) / 2, yo - 12, stroke=O_ORANGE, sw=0.6, opacity=0.6)
    s.text(x0 + max(len(out), 1) * bw + 6, yo + 16, {'union': 'union: every distinct value once', 'intersect': 'intersection: values on both sides, the left copy', 'difference': 'difference: left values not on the right'}[op], size=9.5, fill=INK2, italic=True)
    s.text(x0, yo + 50, f'{len(out)} output rows; lmap and rmap give each input row its output position or × (dropped).', size=9.5, fill=INK2, italic=True)
    s.text(x0, yo + 64, 'Equal runs on one side collapse: a hash-sets-only file never holds a duplicate. Both maps are increasing over the kept rows.', size=9.5, fill=INK2, italic=True)
    return s


def fig_merge_trace():
    out, lmap, rmap, steps = merge_rows('union', LEFT, RIGHT)
    rows = [['step', 'i', 'L[i]', 'j', 'R[j]', 'compare', 'emit', 'then i', 'then j']]
    for k, (i, j, c, em, ni, nj) in enumerate(steps):
        rows.append([str(k), str(i), LEFT[i] if i < len(LEFT) else '—', str(j), RIGHT[j] if j < len(RIGHT) else '—', {-1: 'L < R', 0: 'L = R', 1: 'L > R'}[c] if (i < len(LEFT) and j < len(RIGHT)) else ('left only' if i < len(LEFT) else 'right only'), ('left' if c <= 0 else 'right') if em else '—', str(ni), str(nj)])
    return table_svg(rows, [40, 30, 50, 30, 50, 80, 50, 50, 50], mono_cols=(2, 4), align=['end'] * 9, size=10)


def fig_op_rules():
    W, H = 900, 150
    s = SVG(W, H)
    ops = [('union', 'yes', 'yes', 'yes'), ('intersection', 'no', 'yes', 'no'), ('difference (left − right)', 'yes', 'no', 'no')]
    cols = ['operation', 'left only', 'on both sides', 'right only']
    x0, y0 = 20, 30
    cw = [210, 150, 150, 150]
    x = x0
    for k, c in enumerate(cols):
        s.text(x + 6, y0, c, size=10, fill=INK2, italic=True); x += cw[k]
    s.line(x0, y0 + 6, x0 + sum(cw), y0 + 6, stroke=INK2, sw=0.6)
    for r, (name, a, b, c) in enumerate(ops):
        y = y0 + 16 + r * 28
        s.text(x0 + 6, y + 16, name, size=10.5)
        for k, v in enumerate((a, b, c)):
            xx = x0 + cw[0] + sum(cw[1:1 + k])
            s.rect(xx + 6, y, cw[1 + k] - 12, 24, fill=F_HASH if v == 'yes' else F_PAD, stroke=INK, sw=0.5)
            s.text(xx + cw[1 + k] / 2, y + 16, 'emit' if v == 'yes' else 'drop', size=10, anchor='middle', fill=INK if v == 'yes' else GRAY)
    s.text(x0, y0 + 16 + 3 * 28 + 18, 'A hash type present on one side only is merged against an empty run: union and difference copy it, intersection empties it.', size=9.5, fill=INK2, italic=True)
    return s


def fig_pipeline():
    """inputs -> row maps -> each derived structure"""
    W, H = 920, 330
    s = SVG(W, H)
    def box(x, y, w, h, title, sub, fill):
        s.rect(x, y, w, h, fill=fill, stroke=INK, sw=0.7, rx=3)
        s.text(x + w / 2, y + 17, title, size=10.5, anchor='middle', mono=True)
        if sub: s.text(x + w / 2, y + 31, sub, size=8.5, anchor='middle', fill=INK2, italic=True)
    # left and right inputs
    box(20, 20, 130, 40, 'left HDAT', 'sorted rows', F_HASH)
    box(20, 70, 130, 40, 'right HDAT', 'sorted rows', '#f3e6cf')
    box(200, 45, 150, 40, 'merge_rows', 'two pointers, O(n)', F_HI)
    s.line(150, 40, 198, 58, stroke=INK2, sw=0.8, arrow=True)
    s.line(150, 90, 198, 72, stroke=INK2, sw=0.8, arrow=True)
    box(400, 45, 110, 40, 'lmap, rmap', 'old row → new row or ×', F_NUM)
    s.line(350, 65, 398, 65, stroke=INK2, sw=0.8, arrow=True)
    # outputs
    outs = [
        (580, 20, 'HDAT', 'rows copied to their mapped positions', F_HASH),
        (580, 72, 'HINT 0x6208 / 0x7400', 'recomputed over the written rows: a pass, or a prefix sum per cell', F_NUM),
        (580, 124, 'RIDX', 'row → record, remapped through the record map', '#e6e9d7'),
        (580, 176, 'TIVF', 'lists carried per cell with ids remapped, then coalesced (merge_tlsh_ivf)', '#f0dcc8'),
    ]
    for (x, y, t, sub, fill) in outs:
        s.rect(x, y, 320, 44, fill=fill, stroke=INK, sw=0.7, rx=3)
        s.text(x + 8, y + 17, t, size=10.5, mono=True)
        s.text(x + 8, y + 32, sub, size=8.5, fill=INK2, italic=True)
        s.line(510, 65, x - 2, y + 22, stroke=INK2, sw=0.7, arrow=True)
    # records
    box(20, 230, 130, 40, 'left RDAT', 'records', '#f1e9ef')
    box(20, 280, 130, 40, 'right RDAT', 'records', '#f1e9ef')
    box(200, 255, 150, 40, 'merge_records', 'widen, sort, two pointers', F_HI)
    s.line(150, 250, 198, 268, stroke=INK2, sw=0.8, arrow=True)
    s.line(150, 300, 198, 282, stroke=INK2, sw=0.8, arrow=True)
    box(400, 255, 110, 40, 'record maps', 'old record → new or ×', F_NUM)
    s.line(350, 275, 398, 275, stroke=INK2, sw=0.8, arrow=True)
    s.line(455, 255, 455, 87, stroke=INK2, sw=0.8, arrow=True, dash='3,3')
    s.text(448, 170, 'with records, the row merge', size=8.5, fill=INK2, italic=True, anchor='end')
    s.text(448, 182, 'follows the records\' fates (§3)', size=8.5, fill=INK2, italic=True, anchor='end')
    s.line(510, 275, 578, 146, stroke=INK2, sw=0.7, arrow=True, dash='3,3')
    s.text(20, 130, 'no sort, no re-clustering:', size=10, italic=True, fill=INK2)
    s.text(20, 146, 'every output chunk is a pass', size=10, italic=True, fill=INK2)
    s.text(20, 162, 'over the inputs driven by the', size=10, italic=True, fill=INK2)
    s.text(20, 178, 'two maps.', size=10, italic=True, fill=INK2)
    return s


def fig_records_widen():
    W, H = 900, 250
    s = SVG(W, H)
    x0 = 20
    def rec(x, y, fields, title, scale=1.0):
        s.text(x, y - 6, title, size=9.5, italic=True, fill=INK2)
        xx = x
        for (name, ln, present, fill) in fields:
            w = 10 + ln * 3.2 * scale
            s.rect(xx, y, 10, 22, fill=F_HI if present else F_PAD, stroke=INK, sw=0.5)
            s.text(xx + 5, y + 15, '1' if present else '0', size=8.5, anchor='middle', mono=True)
            s.rect(xx + 10, y, w - 10, 22, fill=fill if present else F_PAD, stroke=INK, sw=0.5)
            s.text(xx + 10 + (w - 10) / 2, y + 15, name if present else '0…0', size=9.5, anchor='middle', mono=not present, fill=INK if present else GRAY)
            xx += w + 2
        return xx
    rec(x0, 30, [('md5', 16, True, F_HASH), ('sha1', 20, True, '#e3ead9')], 'left record (fields md5, sha1): 38 bytes')
    rec(x0, 80, [('sha1', 20, True, '#e3ead9'), ('tlsh', 36, True, '#d6e2d6')], 'right record (fields sha1, tlsh): 58 bytes')
    s.text(x0, 130, 'output fields = left\'s fields, then right\'s extras: md5, sha1, tlsh', size=10, italic=True, fill=INK2)
    rec(x0, 160, [('md5', 16, True, F_HASH), ('sha1', 20, True, '#e3ead9'), ('tlsh', 36, False, '#d6e2d6')], 'left record widened: tlsh absent (presence 0, zero value)')
    rec(x0, 210, [('md5', 16, False, F_HASH), ('sha1', 20, True, '#e3ead9'), ('tlsh', 36, True, '#d6e2d6')], 'right record widened: md5 absent; its field order changed, so the right side is re-sorted before the merge')
    s.text(520, 45, 'Widened records are compared as whole byte strings,', size=9.5, italic=True, fill=INK2)
    s.text(520, 59, 'so identical records collapse (the left copy stands);', size=9.5, italic=True, fill=INK2)
    s.text(520, 73, 'two records that agree on md5 but differ elsewhere', size=9.5, italic=True, fill=INK2)
    s.text(520, 87, 'are different records, and both keep their rows.', size=9.5, italic=True, fill=INK2)
    return s


def fig_rows_follow_records():
    W, H = 900, 240
    s = SVG(W, H)
    x0, y0 = 40, 40
    rw = 54
    # records with fates
    recs = ['r0', 'r1', 'r2', 'r3', 'r4']
    fate = ['0', '×', '1', '2', '×']
    s.text(x0, y0 - 14, 'left records and their fates after merge_records (intersection: r1 and r4 have no partner on the right)', size=10, italic=True, fill=INK2)
    for k, (r, f) in enumerate(zip(recs, fate)):
        s.rect(x0 + k * rw, y0, rw - 4, 24, fill='#f1e9ef' if f != DROP else F_PAD, stroke=INK, sw=0.5)
        s.text(x0 + k * rw + (rw - 4) / 2, y0 + 16, r, size=10, anchor='middle', mono=True)
        s.text(x0 + k * rw + (rw - 4) / 2, y0 + 38, f'→ {f}', size=9.5, anchor='middle', mono=True, fill=Q_RED if f == DROP else G_GREEN)
    # sha1 rows of the left side with RIDX
    y1 = 120
    rows = [('s0', 'r3'), ('s1', 'r1'), ('s2', 'r0'), ('s3', 'r4'), ('s4', 'r2')]
    s.text(x0, y1 - 14, 'left sha1 rows in their own order, each with its RIDX entry; a row is kept iff its record is', size=10, italic=True, fill=INK2)
    out = 0
    for k, (sr, rr) in enumerate(rows):
        f = fate[int(rr[1])]
        keep = f != DROP
        s.rect(x0 + k * rw, y1, rw - 4, 24, fill='#e3ead9' if keep else F_PAD, stroke=INK, sw=0.5)
        s.text(x0 + k * rw + (rw - 4) / 2, y1 + 16, sr, size=10, anchor='middle', mono=True)
        s.text(x0 + k * rw + (rw - 4) / 2, y1 + 38, f'RIDX {rr}', size=8.5, anchor='middle', mono=True, fill=INK2)
        s.text(x0 + k * rw + (rw - 4) / 2, y1 + 54, (f'kept, new RIDX {f}' if keep else 'dropped'), size=8.5, anchor='middle', fill=G_GREEN if keep else Q_RED, italic=True)
        s.line(x0 + k * rw + (rw - 4) / 2, y1 - 2, x0 + int(rr[1]) * rw + (rw - 4) / 2, y0 + 46, stroke=LIGHT, sw=0.6)
    s.text(x0, y1 + 84, 'The kept rows are written in their existing order (still sorted), and each new RIDX entry is the record map applied to the old one.', size=9.5, italic=True, fill=INK2)
    s.text(x0, y1 + 98, 'Two equal digests belonging to two kept records stay two rows, each pointing at its own record, exactly as the builder writes them.', size=9.5, italic=True, fill=INK2)
    return s


def fig_tivf_gather():
    """per cell: a's lists then b's, ids remapped, dropped ids removed, radius recomputed for shrunk lists"""
    W, H = 900, 330
    s = SVG(W, H)
    x0 = 20
    def lst(x, y, ids, medoid, r2, fill, title, shrunk=False, newr=None):
        s.text(x, y - 6, title, size=9.5, italic=True, fill=INK2)
        s.rect(x, y, 40, 22, fill=F_HASH, stroke=INK, sw=0.5); s.text(x + 20, y + 15, medoid, size=9, anchor='middle', mono=True)
        s.rect(x + 42, y, 46, 22, fill='#f0dcc8' if not shrunk else F_HI, stroke=INK, sw=0.5); s.text(x + 65, y + 15, f'r²={r2}' if newr is None else f'r²={newr}', size=9, anchor='middle', mono=True)
        xx = x + 92
        for i in ids:
            dropped = i.startswith('*')
            s.rect(xx, y, 30, 22, fill=fill if not dropped else F_PAD, stroke=INK, sw=0.5, dash='2,2' if dropped else None)
            s.text(xx + 15, y + 15, i if not dropped else i.strip('*'), size=9, anchor='middle', mono=True, fill=GRAY if dropped else INK)
            if dropped: s.line(xx + 4, y + 4, xx + 26, y + 18, stroke=Q_RED, sw=1)
            xx += 32
        return xx
    s.text(x0, 20, 'one cell, before: the left index has two lists in it, the right index one', size=10, italic=True, fill=INK2)
    lst(x0, 44, ['12', '15', '19', '20'], 'm₁', 83, F_HASH, 'left list 1 (left row ids)')
    lst(x0, 94, ['13', '16', '21'], 'm₂', 40, F_HASH, 'left list 2')
    lst(x0 + 420, 44, ['40', '41', '44', '45', '47'], 'm₃', 97, '#f3e6cf', 'right list 3 (right row ids)')
    s.text(x0, 150, 'after remapping the ids through lmap / rmap (a difference: right rows that matched left rows were dropped on the right, and the left copy kept)', size=10, italic=True, fill=INK2)
    lst(x0, 180, ['70', '73', '77', '78'], 'm₁', 83, F_HASH, 'list 1: all members kept, radius unchanged')
    lst(x0, 230, ['71', '*74*', '79'], 'm₂', 40, F_HASH, 'list 2: a member dropped → radius2 recomputed exactly about m₂ (kept as medoid even if it is no longer a member)', shrunk=True, newr=31)
    lst(x0 + 420, 180, ['*40*', '*41*', '80', '*45*', '81'], 'm₃', 97, '#f3e6cf', 'list 3: three members dropped → recomputed', shrunk=True, newr=52)
    s.text(x0, 290, 'The medoid of a list need not be a member: the search only needs every member within radius2 of it, and the format allows any digest with that property.', size=9.5, italic=True, fill=INK2)
    s.text(x0, 304, 'A list that loses every member is omitted. Lists are then emitted in this order, left\'s then right\'s, and a cell\'s lists remain contiguous in the TIVF.', size=9.5, italic=True, fill=INK2)
    return s


def fig_coalesce():
    """circles: small lists paired by smallest union radius"""
    W, H = 900, 330
    s = SVG(W, H)
    rnd = random.Random(8)
    # four small lists as discs with members; pair (A, B) chosen
    lists = [((190, 150), 36, S_BLUE, 'A', 5), ((275, 120), 28, S_BLUE, 'B', 4), ((400, 200), 32, O_ORANGE, 'C', 6), ((200, 250), 24, O_ORANGE, 'D', 3)]
    for (cx, cy), r, col, name, n in lists:
        s.circle(cx, cy, r, fill=col, opacity=0.12, stroke=col, sw=0.8)
        for _ in range(n):
            a = rnd.uniform(0, 2 * math.pi); d = r * math.sqrt(rnd.uniform(0.1, 1))
            s.dot(cx + d * math.cos(a), cy + d * math.sin(a), r=2.2, fill=col)
        s.dot(cx, cy, r=3.5, fill=INK)
        s.text(cx + r + 4, cy + 4, f'{name}: {n} rows', size=9.5, fill=INK2, italic=True)
    # candidate union A∪B about medoid of A
    (ax, ay), ar = lists[0][0], lists[0][1]
    (bx, by), br = lists[1][0], lists[1][1]
    R = math.hypot(bx - ax, by - ay) + br
    s.circle(ax, ay, R, fill='none', stroke=Q_RED, sw=1.2, dash='5,3')
    s.text(ax, ay - R - 6, 'A ∪ B about m_A: the smallest union radius', size=9.5, fill=Q_RED, italic=True, anchor='middle')
    s.text(20, 318, 'Schematic. Lists of fewer than C/2 = 32 rows are candidates; the pair with the smallest exact union radius (about one of the two medoids) is merged first.', size=9.5, italic=True, fill=INK2)
    # right: the algorithm as a list
    x0 = 480
    lines = [
        'while the cell has ≥ 2 lists of < C/2 rows:',
        '  for every candidate pair (i, j):',
        '    r_i = max distance from m_i over i ∪ j   (kernel)',
        '    r_j = max distance from m_j over i ∪ j',
        '    radius(i ∪ j) = min(r_i, r_j)',
        '  take the pair with the smallest radius',
        '  replace it by one list: that medoid, that radius,',
        '    the sorted union of the ids (a linear merge)',
        '  if the new list has ≥ C/2 rows it leaves the pool',
        '',
        'C = 64 by default (SFHASH_HSET_COALESCE_DEFAULT);',
        'C = 0 disables coalescing and lists only accumulate.',
        '',
        'Candidate pairs sit in a heap with lazy invalidation:',
        'a cell with s small lists costs O(s² log s) bookkeeping',
        'plus s × (rows in small lists) kernel calls.',
    ]
    y = 40
    for t in lines:
        s.text(x0, y, t, size=10, mono=t.startswith((' ', 'while')), fill=INK if t.startswith((' ', 'while')) else INK2, italic=not t.startswith((' ', 'while')))
        y += 16
    return s


def fig_invariant():
    """packing picture: after coalescing, at most one list per cell under C/2 -> lists <= 2m/C + 1"""
    W, H = 900, 200
    s = SVG(W, H)
    x0, y0 = 20, 50
    scale = 2.6
    C = 64
    sizes = [71, 40, 33, 58, 36, 45, 19]
    x = x0
    s.text(x0, y0 - 24, 'the rows of one cell (m = 302) after a merge, grouped by list; the dashed mark on each list is C/2 = 32 rows', size=10, italic=True, fill=INK2)
    for k, sz in enumerate(sizes):
        w = sz * scale
        s.rect(x, y0, w, 30, fill=F_HASH if sz >= C / 2 else F_HI, stroke=INK, sw=0.6)
        s.text(x + w / 2, y0 + 19, str(sz), size=10, anchor='middle', mono=True)
        if sz >= C / 2:
            s.line(x + (C / 2) * scale, y0, x + (C / 2) * scale, y0 + 30, stroke=INK2, sw=0.8, dash='3,2')
        x += w + 3
    s.brace(x0, x - 3, y0 + 36, 'm rows', size=9.5)
    s.text(x0, y0 + 80, 'At most one list (the pink one) is below C/2, so (L − 1) · C/2 ≤ m, i.e. L ≤ 2m/C + 1.', size=10, italic=True, fill=INK2)
    s.text(x0, y0 + 96, 'With C = 2T = 64 that is L ≤ m/32 + 1: at most one list more than the ⌈m/T⌉ a fresh build would make, after any number of merges in any order.', size=10, italic=True, fill=INK2)
    s.text(x0, y0 + 112, 'Each list costs 48 bytes (medoid, radius2, list_start), so a merged index is at most 48 B × (non-empty cells) ≤ 3 MiB larger than a rebuilt one,', size=10, italic=True, fill=INK2)
    s.text(x0, y0 + 128, 'and a query evaluates at most one list bound more per visited cell. Rows scanned have no such bound and are measured instead.', size=10, italic=True, fill=INK2)
    return s


def fig_sweep():
    """BISECT hourly sweep, T = 32: lists and rows scanned vs C"""
    W, H = 900, 300
    s = SVG(W, H)
    Cs = [0, 32, 64, 128]
    lists_m = [146, 54, 40, 25]; lists_r = 50
    knn_m = [45.6, 32.3, 29.6, 34.2]; knn_r = 28.9
    rows_m = [15.1, 15.9, 16.9, 23.3]; rows_r = 12.4
    def panel(x, title, ys, yr, ylim, unit):
        p = Plot(s, x, 40, 220, 180, (-0.5, 3.5), ylim, xticks=[0, 1, 2, 3], xfmt=lambda v: str(Cs[int(v)]), xlabel='coalescing threshold C')
        s.text(x, 24, title, size=10, italic=True, fill=INK2)
        for k, v in enumerate(ys):
            s.rect(p.X(k - 0.3), p.Y(v), p.X(k + 0.3) - p.X(k - 0.3), p.Y(0) - p.Y(v), fill=O_ORANGE if k != 2 else Q_RED, opacity=0.85)
            s.text(p.X(k), p.Y(v) - 4, f'{v}{unit}', size=8.5, anchor='middle')
        p.hline(yr, stroke=S_BLUE, dash='4,3', sw=1)
        s.text(p.X(3.45), p.Y(yr) - 4, f'rebuilt: {yr}{unit}', size=8.5, fill=S_BLUE, italic=True, anchor='end')
    panel(50, 'lists (thousands)', lists_m, lists_r, (0, 160), 'K')
    panel(350, 'query time (µs)', knn_m, knn_r, (0, 50), '')
    panel(650, 'rows scanned per query (thousands)', rows_m, rows_r, (0, 26), 'K')
    s.text(50, 270, 'BISECT, 1M-row master absorbing 24 hourly batches of 18 000 rows, T = 32 (docs/BENCHMARKS.md §7, second round). Red: the default C = 64. Blue dashes: one from-scratch rebuild of the final rows.', size=9.5, italic=True, fill=INK2)
    s.text(50, 284, 'Without coalescing (C = 0) lists triple and queries slow 1.5×; C = 2T minimises the merged index\'s query time; larger C trades bounds for 40–70% more rows scanned.', size=9.5, italic=True, fill=INK2)
    return s


def build():
    body = []
    B = body.append
    B(f'''<p>A master hash set absorbs new rows every hour, an analyst wants the intersection of two collections, a corpus minus its known-good subset. Each of these is a set operation on whole files, and each output must be a complete, valid hset: sorted rows, hints, records, and for TLSH the index. The naive route rebuilds everything from the union of the inputs: a sort and a clustering. hset instead <em>merges</em>: a single two-pointer pass over the two sorted inputs decides every row's fate, and every other chunk is carried through that decision by a <em>row map</em>. Nothing is re-sorted or re-clustered. The hard part is the TIVF index, whose lists must stay correct and must not multiply.{sn('An hourly union of 18 000 rows into a 1M-row master takes about 42 ms with the index carried through, against 440 ms for a rebuild with the integer builder and 3.3 s with the float one; the daily 432 000-row batch takes 100–150 ms against 2.5 s. Numbers from the incremental-merge sweep in <code>docs/TLSH_EMBEDDING.md</code>, section 5.')}</p>''')
    B('<ul class="toc">' + ''.join(f'<li><span class="n">{n}</span><a href="#{a}">{t}</a></li>' for n, t, a in [
        (1, 'Two pointers', 'two-pointers'), (2, 'Everything else follows the map', 'everything-else-follows-the-map'),
        (3, 'Records', 'records'), (4, 'Merging the TIVF lists', 'merging-the-tivf-lists'),
        (5, 'Coalescing', 'coalescing'), (6, 'What it costs, what it keeps', 'what-it-costs-what-it-keeps')]) + '</ul>')

    B(h2(1, 'Two pointers'))
    B('''<p>Both inputs are sorted, so the classic merge applies: one cursor per input, compare the rows at the cursors, emit the smaller (or, when equal, the left one) and advance. The operation decides what is emitted: union emits everything, intersection only values present on both sides, difference only left values with no equal on the right. Equal runs within one input are skipped as a unit, so a hash-sets-only output never contains a duplicate. The pass costs one comparison per input row and produces, as a side effect, the two maps that drive everything else: for each input row, its output position, or "dropped".</p>''')
    B(fig(fig_op_rules(), 'The emission rules of the three operations, applied to each distinct value.', 'wide'))
    B(fig(fig_two_pointer('union'), 'A union of two short sorted inputs. The maps below each input give the output row of every kept input row; the second 1c on the left and the second 63 on the right are duplicates and are dropped, as is every right row that has a left equal.', 'wide'))
    B(fig(fig_merge_trace(), 'The same union, step by step. Each step compares the two cursors, emits at most one row, and advances past the whole run of equal values on the side(s) it consumed.', 'wide'))
    B(fig(fig_two_pointer('intersect'), 'The intersection of the same inputs: only values on both sides, the left copy kept.', 'wide'))
    B(fig(fig_two_pointer('difference'), 'The difference (left minus right).', 'wide'))

    B(h2(2, 'Everything else follows the map'))
    B('''<p>The output file has the same chunks as a built file, and each one is produced from the inputs through the maps without any global computation over the rows.</p>''')
    B(fig(fig_pipeline(), 'The merge pipeline. The two row maps are the only coupling between the row merge and the derived chunks; each derived chunk is one pass.', 'wide'))
    B('''<ul>
<li><em>HDAT</em>: every kept input row is copied to its mapped position. The output is sorted because the merge emitted in order.</li>
<li><em>HINT</em>: the hints depend only on the written rows, so they are recomputed from the output HDAT: the per-block deviation bounds in one pass, the TLSH cell index as a count per cell and a prefix sum.</li>
<li><em>RIDX</em>: each kept row's record index is pushed through the record map of §3.</li>
<li><em>TIVF</em>: the subject of §4 and §5. When one input has no index and the output wants one, the merged rows are clustered from scratch instead.</li>
</ul>
<p>Whether the output gets the optional TLSH index is a choice: explicitly, or by inheritance, which writes it if and only if every input that has a TLSH section has one. Under inheritance an index is always merged, never rebuilt.</p>''')

    B(h2(3, 'Records'))
    B('''<p>When both inputs carry a record table, the operation is applied to the <em>records</em>, and the rows follow. Records are first widened to a common layout: the left input's fields in their order, then any fields only the right has; an absent field is a zero presence byte and a zero value. A side whose field order changed by the widening is re-sorted. The widened records are then merged by the same two-pointer rule, comparing whole records, and identical records collapse to the left copy. For intersection and difference only left records can be emitted, so the right record map is all "dropped".</p>''')
    B(fig(fig_records_widen(), 'Widening two record layouts to their union. Because a record is compared as a whole, the merge is a record-level set operation, not a per-field one.', 'wide'))
    B(fig(fig_rows_follow_records(), 'Rows follow their records. For an intersection, records without a partner are dropped, and so is every row that points at them; surviving rows keep their relative order and get their RIDX remapped.', 'wide'))
    B('''<p>Then the hash sections are merged under the records' decisions: a row is emitted if and only if its record was. Two equal rows that belong to two different kept records stay two rows (that is how the builder writes them, and each still points at its own record), while a hash-sets-only output of a record-level operation writes each distinct row once. When only one input has records, or neither, the output is a hash-sets-only file and the rows are merged as sets. A records-only input can only be merged with another records-only input.</p>''')

    B(h2(4, 'Merging the TIVF lists'))
    B('''<p>The index is where rebuilding would be expensive and where merging has to be careful. The TIVF contract is per list: every member lies within radius2 of the medoid. The row maps let the lists be carried across the merge cell by cell, because a row's cell (its first two bytes) is the same in the output as in the input, and because both maps are increasing over the kept rows, so a list's ids stay ascending after remapping.</p>
<p>For each cell the merge gathers the left input's lists, then the right's, and remaps every id. Dropped ids are removed; a list that loses all its members disappears. A list that loses <em>some</em> members has its radius recomputed exactly over the survivors, about its old medoid, which stays its medoid whether or not it is still a member. A list that lost nothing keeps its medoid and radius untouched, since a radius depends only on the list's members. Exactness is preserved at every step: the search never relies on the medoid being a member, only on the radius bound.</p>''')
    B(fig(fig_tivf_gather(), 'One cell during the gather step of a difference. Ids are remapped; struck-out ids were dropped; shrunk lists get exact new radii about their old medoids.', 'wide'))

    B(h2(5, 'Coalescing'))
    B('''<p>Concatenation alone has a flaw: lists accumulate. A batch of 18 000 rows spreads over thousands of cells, adding a tiny list to each; after a day of hourly merges a cell holds dozens of fragments where a fresh build would have one list, and a query pays a bound evaluation for each. The merge therefore <em>coalesces</em> small lists. With threshold C (64 by default, twice the fresh build's target list size), while a cell has two lists of fewer than C/2 rows each, the pair whose union has the smallest exact radius about one of the two medoids becomes one list: that medoid, that radius, the sorted union of the ids. A pair always sums to fewer than C rows, and the loop ends with at most one list under C/2 per cell.</p>''')
    B(fig(fig_coalesce(), 'Coalescing in one cell. Small lists are paired greedily by the radius of their union; the kernel computes each candidate radius exactly, so the merged list satisfies the contract.', 'wide'))
    B(fig(fig_invariant(), 'The invariant and what it buys: with at most one list per cell under C/2, the number of lists in a cell of m rows is at most 2m/C + 1, which bounds the storage and the per-query bound evaluations relative to a rebuild, independently of how many merges the index has been through.', 'wide'))
    B('''<p>What the invariant does not bound is <em>rows scanned</em>: a coalesced list has the radius of a pair that a fresh clustering might have kept apart, so its bound is looser and more of its rows may be visited. That is measured rather than proven, and the sweep below is the measurement.</p>''')

    B(h2(6, 'What it costs, what it keeps'))
    B(fig(fig_sweep(), 'The coalescing threshold sweep. Left: the merged index has fewer lists than a rebuild for any C > 0 (the invariant packs cells tighter than ⌈m/T⌉). Middle: query time is minimised at C = 2T, within 3% of the rebuilt index. Right: the price, more rows scanned per query, grows with C.', 'wide'))
    B(f'''<p>A merged index is never incorrect; it can only be slower than a fresh one, and the sweep bounds how much: after 24 hourly merges the index answers in 29.6 µs against 28.9 µs rebuilt, scanning 16 900 rows against 12 400. The hard case is a batch that is a large fraction of the master: after seven daily batches of 432 000 rows the merged index scans 1.8× the rows of a rebuild and answers in 1.3× the time, still two orders of magnitude under brute force. When rows scanned matter, a rebuild (any merge with an explicit index option against an input without an index) restores the fresh profile and the incremental merges resume from it.{sn('The layout of the output is that of a built file: HDAT chunks on 4096-byte boundaries, an FTOC listing exactly the chunks written, and the SHA-256 computed last over everything from offset 40.')}</p>''')
    B(table(['scenario (BISECT, T = 32, C = 64)', 'merges', 'rebuild', 'lists merged / rebuilt', 'kNN merged / rebuilt', 'rows per query merged / rebuilt'],
            [('24 hourly batches of 18 000 into 1M', '995 ms', '440 ms', '40 094 / 50 381', '29.6 / 28.9 µs', '16 855 / 12 386'),
             ('7 daily batches of 432 000 into 1M', '782 ms', '2 525 ms', '93 946 / 131 274', '127.6 / 94.7 µs', '56 676 / 31 668')], numeric=(1, 2, 3, 4, 5)))
    B('''<p class="note">A single hourly merge costs about 42 ms, ten times less than a rebuild; the 24 of them together cost twice a rebuild, so a daily rebuild with hourly merges between is a reasonable regime. The merge is single-threaded and dominated by copying the rows and hashing the file.</p>''')
    return page('merge.html', 'Set operations', 'Union, intersection and difference of whole files by one merge pass, with the hints, the records and the TIVF index carried through a row map instead of rebuilt.', ''.join(body))
