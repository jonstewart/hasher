"""index.html: the hset file format."""
import json, os, struct
from svg import *
from common import *

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, 'data', 'fixtures.json')))

HASH_TYPES = [
    (0, 'md5', 16), (1, 'sha1', 20), (2, 'sha2_224', 28), (3, 'sha2_256', 32), (4, 'sha2_384', 48),
    (5, 'sha2_512', 64), (6, 'sha3_224', 28), (7, 'sha3_256', 32), (8, 'sha3_384', 48), (9, 'sha3_512', 64),
    (10, 'blake3', 32), (11, 'fuzzy (ssdeep)', None), (12, 'entropy', None), (13, 'sizes', 8),
    (14, 'quick_md5', None), (15, 'tlsh', 36),
]

CHUNK_FILL = {
    'FTOC': F_TYPE, 'FHDR': F_TYPE, 'RHDR': '#e9dfe6', 'RDAT': '#f1e9ef', 'HH': '#d9e4ea', 'HINT': F_NUM,
    'HDAT': F_HASH, 'RIDX': '#e6e9d7', 'TIVF': '#f0dcc8', 'FEND': F_TYPE, 'pad': F_PAD,
}

def chunk_fill(ty):
    return CHUNK_FILL.get(ty if not ty.startswith('HH') else 'HH', F_DATA)

def chunk_name(ty):
    if ty.startswith('HH'):
        bit = (ord(ty[2]) << 8) | ord(ty[3])
        return f'HH({HASH_TYPES[bit][1]})'
    return ty


# ---------------------------------------------------------------------------
# Figure: a whole file to scale
# ---------------------------------------------------------------------------
def fig_file_strip():
    rec = FX['md5_sha1']
    toc = rec['toc']
    size = rec['size']
    W = 980
    x0, strip_w = 60, 880
    y_strip = 150
    sh = 34
    s = SVG(W, 255)
    scale = strip_w / size
    # chunk extents: [offset, next offset)
    exts = []
    for i, (off, ty) in enumerate(toc):
        nxt = toc[i+1][0] if i + 1 < len(toc) else size
        exts.append((off, nxt, ty))
    # payload lengths from the file
    lens = {40: 156, 208: 44, 264: 47, 323: 12920, 13255: 21, 13288: 4098, 20480: 5440, 25932: 2720, 28664: 22, 28698: 4098, 36864: 6800, 43676: 2720, 46408: 0}
    # page grid
    for p in range(0, size + 1, 4096):
        x = x0 + p * scale
        s.line(x, y_strip - 6, x, y_strip + sh + 6, stroke=RULE, sw=0.6, dash='2,2')
        s.text(x, y_strip + sh + 18, f'{p // 1024}K' if p else '0', size=8.5, anchor='middle', fill=GRAY)
    s.text(x0 + strip_w, y_strip + sh + 32, f'byte offset (file size {size:,} bytes; dashed lines every 4096 bytes)', size=9, anchor='end', fill=INK2, italic=True)
    # chunks
    small = []
    for (a, b, ty) in exts:
        x = x0 + a * scale
        w = (b - a) * scale
        real_end = a + 12 + lens[a]
        wr = (real_end - a) * scale
        s.rect(x, y_strip, max(wr, 0.8), sh, fill=chunk_fill(ty), stroke=INK, sw=0.6)
        if b > real_end + 1:  # padding
            s.rect(x0 + real_end * scale, y_strip, (b - real_end) * scale, sh, fill=F_PAD, stroke=INK, sw=0.4, dash='2,2')
        if wr > 60:
            s.text(x + wr / 2, y_strip + 14, chunk_name(ty), size=10, anchor='middle', mono=True)
            s.text(x + wr / 2, y_strip + 27, f'{lens[a]:,} B', size=8.5, anchor='middle', fill=INK2)
        else:
            small.append((x + wr / 2, ty, lens[a], a))
    # leaders for small chunks, fanned above with a minimum spacing
    small.insert(0, (x0 + 20 * scale, 'magic', 40, 0))
    labels = []
    minsep = 72
    tx = -1000
    for (cx, ty, ln, a) in small:
        tx = max(cx, tx + minsep, 50)
        labels.append((cx, tx, ty, ln, a))
    # right-align the last label into the canvas
    over = labels[-1][1] + 36 - W
    if over > 0:
        labels = [(cx, tx - over, ty, ln, a) for (cx, tx, ty, ln, a) in labels]
    for (cx, tx, ty, ln, a) in labels:
        ly = y_strip - 40
        s.path(f'M{fmt(cx)},{fmt(y_strip)} L{fmt(cx)},{fmt(y_strip - 14)} L{fmt(tx)},{fmt(ly + 10)}', stroke=INK2, sw=0.5)
        name = 'magic + hash' if ty == 'magic' else chunk_name(ty)
        s.text(tx, ly - 2, name, size=9.5, anchor='middle', mono=True)
        s.text(tx, ly + 8, f'{ln:,} B @{a}', size=8, anchor='middle', fill=GRAY)
    # magic + hash sliver
    s.rect(x0, y_strip, 40 * scale, sh, fill=F_HI, stroke=INK, sw=0.6)
    # section braces below
    secs = [(13255, 28664, 'md5 hash section'), (28664, 46408, 'sha1 hash section'), (264, 13255, 'record table')]
    for (a, b, lab) in secs:
        s.brace(x0 + a * scale, x0 + b * scale, y_strip + sh + 44, lab, size=9.5, up=True)
    return s


# ---------------------------------------------------------------------------
# Figure: the chunk frame
# ---------------------------------------------------------------------------
def fig_chunk_frame():
    return bytefield([
        {'name': 'type', 'size': 4, 'type': '4 ASCII bytes', 'fill': F_TYPE, 'value': '"HDAT"'},
        {'name': 'length', 'size': 8, 'type': 'u64 little-endian', 'fill': F_NUM, 'value': '0x3394 = 13 204'},
        {'name': 'payload', 'size': None, 'type': 'length bytes', 'fill': F_DATA, 'units': 14, 'trunc': True, 'size_label': 'length B'},
    ], unit=24)


def fig_preamble():
    g = bytes.fromhex(FX['good']['head'])
    spans = [
        (0, 8, F_HI, 'magic "SetOHash"'),
        (8, 32, F_HASH, 'SHA-256 of bytes [40, end of file)'),
        (40, 4, F_TYPE, 'FTOC chunk type'),
        (44, 8, F_NUM, 'FTOC payload length: 0x48 = 72 = 6 entries × 12'),
        (52, 72, F_DATA, 'FTOC payload: 6 entries of (u64 offset LE, u32 type BE)'),
        (124, 36, F_PAD, 'unused: the FTOC reserved room for 9 entries'),
        (160, 4, F_TYPE, 'FHDR chunk type'),
    ]
    return hexgrid(g[:0xa4], spans, cols=16)


def fig_ftoc_entries():
    g = bytes.fromhex(FX['good']['head'])
    pl = g[52:52+72]
    rows = [['#', 'bytes (offset LE · type BE)', 'offset', 'type', 'what the reader finds there']]
    whats = ['the table itself', 'file header', 'sha1 hash set header', '8-bit block bounds', '665 × 20-byte rows', 'end']
    for i in range(6):
        e = pl[i*12:(i+1)*12]
        off = struct.unpack_from('<Q', e)[0]
        ty = e[8:12]
        tys = ''.join(chr(c) if 32 <= c < 127 else '\\x%02x' % c for c in ty)
        rows.append([str(i), e[:8].hex(' ') + ' · ' + e[8:].hex(' '), f'{off}', tys, whats[i]])
    return table_svg(rows, [24, 290, 60, 90, 200], mono_cols=(1, 3), align=['end', 'start', 'end', 'start', 'start'], size=10)


def fig_fhdr():
    g = bytes.fromhex(FX['good']['head'])
    a = 160
    spans = [
        (a, 4, F_TYPE, 'type "FHDR"'), (a+4, 8, F_NUM, 'payload length 59'),
        (a+12, 8, F_NUM, 'version = 2 (u64 LE)'),
        (a+20, 2, F_NUM, 'name length 9 (u16 LE)'), (a+22, 9, F_TYPE, 'name "Test Name"'),
        (a+31, 2, F_NUM, 'timestamp length 20'), (a+33, 20, F_TYPE, 'timestamp, ISO-8601 UTC'),
        (a+53, 2, F_NUM, 'description length 16'), (a+55, 16, F_TYPE, 'description'),
    ]
    return hexgrid(g[a:a+71], spans, cols=16, start=a)


def fig_pstring():
    return bytefield([
        {'name': 'len', 'size': 2, 'type': 'u16 LE', 'fill': F_NUM},
        {'name': 'bytes', 'size': None, 'type': 'len bytes, UTF-8, no terminator', 'fill': F_TYPE, 'units': 9, 'trunc': True, 'size_label': 'len B'},
    ], unit=24)


def fig_fhdr_fields():
    return bytefield([
        {'name': 'version', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'value': '2'},
        {'name': 'name', 'size': None, 'type': 'pstring', 'fill': F_TYPE, 'units': 5},
        {'name': 'timestamp', 'size': None, 'type': 'pstring', 'fill': F_TYPE, 'units': 5},
        {'name': 'description', 'size': None, 'type': 'pstring', 'fill': F_TYPE, 'units': 5},
    ], unit=24)


# ---------------------------------------------------------------------------
# Figure: the chunk grammar as an automaton
# ---------------------------------------------------------------------------
def fig_grammar():
    W, H = 900, 250
    s = SVG(W, H)
    # node positions
    ya, yb = 70, 180
    nodes = {
        'FTOC': (60, ya), 'FHDR': (180, ya), 'RHDR': (300, ya), 'RDAT': (420, ya),
        'HHnn': (560, ya), 'HINT': (680, ya), 'HDAT': (800, ya),
        'RIDX': (800, yb), 'TIVF': (560, yb), 'FEND': (300, yb),
    }
    r = 26
    def node(name, dashed=False, fill='#fff'):
        x, y = nodes[name]
        s.circle(x, y, r, fill=chunk_fill(name if name != 'HHnn' else 'HH'), stroke=INK, sw=1, dash='3,3' if dashed else None)
        s.text(x, y + 4, name, size=11, anchor='middle', mono=True)
    def edge(a, b, bend=0, label=None, dashed=False, color=INK, lab_dy=-6):
        (x1, y1), (x2, y2) = nodes[a], nodes[b]
        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy)
        ux, uy = dx / L, dy / L
        # shorten to the circle edges
        sx, sy = x1 + ux * r, y1 + uy * r
        ex, ey = x2 - ux * (r + 3), y2 - uy * (r + 3)
        if bend == 0:
            s.line(sx, sy, ex, ey, stroke=color, sw=1, arrow=True, dash='4,3' if dashed else None)
            mx, my = (sx + ex) / 2, (sy + ey) / 2
        else:
            # quadratic bezier with control point offset perpendicular
            px, py = -uy, ux
            cx, cy = (x1 + x2) / 2 + px * bend, (y1 + y2) / 2 + py * bend
            # recompute endpoints toward control point
            def toward(x, y, tx, ty):
                d = math.hypot(tx - x, ty - y); return x + (tx - x) / d * r, y + (ty - y) / d * r
            sx, sy = toward(x1, y1, cx, cy)
            ex, ey = toward(x2, y2, cx, cy)
            ex, ey = ex + (cx - ex) / math.hypot(cx-ex, cy-ey) * 3, ey + (cy - ey) / math.hypot(cx-ex, cy-ey) * 3
            s.path(f'M{fmt(sx)},{fmt(sy)} Q{fmt(cx)},{fmt(cy)} {fmt(ex)},{fmt(ey)}', stroke=color, sw=1, arrow=True, dash='4,3' if dashed else None)
            mx, my = 0.25 * sx + 0.5 * cx + 0.25 * ex, 0.25 * sy + 0.5 * cy + 0.25 * ey
        if label:
            s.text(mx, my + lab_dy, label, size=9, anchor='middle', fill=INK2, italic=True)
    # start marker
    s.line(10, ya, nodes['FTOC'][0] - r - 3, ya, stroke=INK, sw=1, arrow=True)
    s.text(8, ya - 10, 'byte 40', size=9, fill=INK2, italic=True)
    edge('FTOC', 'FHDR')
    edge('FHDR', 'RHDR', label='with records')
    edge('RHDR', 'RDAT')
    edge('RDAT', 'HHnn')
    edge('FHDR', 'HHnn', bend=-55, label='hash sets only')
    edge('HHnn', 'HINT')
    edge('HINT', 'HDAT')
    edge('HHnn', 'HDAT', bend=-50, label='"sizes" has no HINT', dashed=True)
    edge('HDAT', 'RIDX')
    s.text(nodes['HDAT'][0] + 10, (ya + yb) / 2 + 3, 'with records', size=9, fill=INK2, italic=True)
    edge('RIDX', 'TIVF', label='TLSH only', dashed=True, lab_dy=14)
    edge('HDAT', 'TIVF', bend=40, dashed=True)
    # back to HHnn: next section
    edge('TIVF', 'HHnn')
    s.text(nodes['HHnn'][0] - 10, (ya + yb) / 2 + 3, 'next hash set', size=9, fill=INK2, italic=True, anchor='end')
    edge('RIDX', 'HHnn', bend=30, dashed=False, color=GRAY)
    edge('HDAT', 'HHnn', bend=48, color=GRAY)
    # to FEND
    edge('TIVF', 'FEND')
    edge('RDAT', 'FEND', bend=-40, label='records only', lab_dy=14)
    # end marker
    x, y = nodes['FEND']
    s.circle(x, y, r + 4, fill='none', stroke=INK, sw=0.8)
    for n in nodes:
        node(n, dashed=n == 'TIVF')
    s.text(W - 10, H - 8, 'solid: every file · dashed: TLSH hash sets only · gray: shortcuts when a section has no later chunks', size=9, anchor='end', fill=INK2, italic=True)
    return s


# ---------------------------------------------------------------------------
# Hash section figures
# ---------------------------------------------------------------------------
def fig_hhnn():
    g = bytes.fromhex(FX['good']['head'])
    a = 231
    spans = [
        (a, 2, F_TYPE, 'type bytes "HH"'), (a+2, 2, F_HI, 'nn = 0x0001 big-endian: hash type bit 1 = sha1'),
        (a+4, 8, F_NUM, 'payload length 22'),
        (a+12, 2, F_NUM, 'name length 4'), (a+14, 4, F_TYPE, 'name "sha1"'),
        (a+18, 8, F_NUM, 'hash length = 20 (u64 LE)'),
        (a+26, 8, F_NUM, 'hash count = 0x299 = 665 (u64 LE)'),
    ]
    return hexgrid(g[a:a+34], spans, cols=17, start=a)


def fig_hhnn_fields():
    return bytefield([
        {'name': '"HH"', 'size': 2, 'type': 'ASCII', 'fill': F_TYPE, 'units': 3},
        {'name': 'nn', 'size': 2, 'type': 'u16 BE', 'fill': F_HI, 'units': 3},
        {'name': 'length', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
        {'name': 'name', 'size': None, 'type': 'pstring', 'fill': F_TYPE, 'units': 4},
        {'name': 'hash length', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
        {'name': 'hash count', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
    ], unit=24)


def fig_hint_block():
    """HINT 0x6208 layout and the real first blocks of good.hset."""
    pl = bytes.fromhex(FX['good']['hint_payload_head'])
    s = bytefield([
        {'name': 'hint type', 'size': 2, 'type': 'u16 BE = 0x6208', 'fill': F_HI, 'units': 4},
        {'name': 'min₀', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
        {'name': 'max₀', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
        {'name': 'min₁', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
        {'name': 'max₁', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
        {'name': '…', 'size': 8 * 2 * 253, 'type': '253 more blocks', 'fill': F_NUM, 'units': 5, 'trunc': True, 'size_label': '4048 B'},
        {'name': 'min₂₅₅', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
        {'name': 'max₂₅₅', 'size': 8, 'type': 'i64 LE', 'fill': F_NUM, 'units': 3},
    ], unit=24)
    return s


def fig_hint_block_bytes():
    pl = bytes.fromhex(FX['good']['hint_payload_head'])
    rows = [['block (leading byte)', 'min bytes (LE)', 'max bytes (LE)', 'min', 'max', 'window about e']]
    for b in range(6):
        mn = struct.unpack_from('<q', pl, 2 + 16 * b)[0]
        mx = struct.unpack_from('<q', pl, 2 + 16 * b + 8)[0]
        mnb = pl[2 + 16*b: 2 + 16*b + 8].hex(' ')
        mxb = pl[2 + 16*b + 8: 2 + 16*b + 16].hex(' ')
        if mn > mx:
            rows.append([f'0x{b:02x}', mnb, mxb, 'INT64_MAX', 'INT64_MIN', 'empty block: certain miss'])
        else:
            rows.append([f'0x{b:02x}', mnb, mxb, str(mn), str(mx), f'[e{mn:+d}, e{mx+1:+d})'])
    return table_svg(rows, [120, 190, 190, 80, 80, 170], mono_cols=(0, 1, 2), align=['start', 'start', 'start', 'end', 'end', 'start'], size=10)


def fig_hdat():
    """HDAT: sorted fixed-width rows, with the first real rows of good.hset."""
    rows_hex = FX['good']['hdat_first_rows']
    W = 900
    s = SVG(W, 245)
    x0, y0 = 20, 20
    # the stack of rows
    n = 665
    rh = 2.2
    stack_h = 150
    s.rect(x0, y0, 90, stack_h, fill=F_HASH, stroke=INK, sw=0.8)
    for i in range(1, 24):
        s.line(x0, y0 + i * stack_h / 24, x0 + 90, y0 + i * stack_h / 24, stroke='#fff', sw=0.6)
    s.text(x0 + 45, y0 + stack_h + 16, '665 rows × 20 B', size=9.5, anchor='middle', fill=INK2, italic=True)
    s.text(x0 + 45, y0 - 6, 'HDAT payload', size=10, anchor='middle', mono=True)
    s.vbrace(y0, y0 + stack_h, x0 + 100, 'sorted bytewise, ascending', size=9.5)
    # lens on first rows
    lx = 330
    s.path(f'M{x0+90},{y0} L{lx},{y0} M{x0+90},{y0 + 6*stack_h/24} L{lx},{y0 + 6*24}', stroke=GRAY, sw=0.6, dash='2,2')
    rowsb = bytes.fromhex(rows_hex)
    for i in range(6):
        row = rowsb[i*20:(i+1)*20]
        y = y0 + i * 24
        s.text(lx - 6, y + 15, f'row {i}', size=9, anchor='end', fill=INK2, italic=True)
        for j in range(20):
            x = lx + j * 24
            s.rect(x, y, 24, 22, fill=F_HI if j < 1 else (F_NUM if j < 8 else F_HASH), stroke='#fff', sw=0.6)
            s.text(x + 12, y + 15, '%02x' % row[j], size=9.5, anchor='middle', mono=True)
    s.brace(lx, lx + 24, y0 + 6*24 + 6, None, size=9)
    s.text(lx + 12, y0 + 6*24 + 34, 'byte 0: the hint block', size=9, anchor='start', fill=INK2, italic=True)
    s.line(lx + 12, y0 + 6*24 + 12, lx + 12, y0 + 6*24 + 24, stroke=INK2, sw=0.5)
    s.brace(lx + 24, lx + 8*24, y0 + 6*24 + 6, 'bytes 1–7 (with byte 0: the primary key)', size=9)
    s.brace(lx + 8*24, lx + 20*24, y0 + 6*24 + 6, 'bytes 8–19: compared only on a primary-key tie', size=9)
    s.text(lx, y0 - 6, 'the first six rows of test/good.hset (SHA-1)', size=10, italic=True, fill=INK2)
    return s


def fig_alignment():
    W = 900
    s = SVG(W, 100)
    x0 = 190
    scale = 0.075  # px per byte -> 4096 B = 307 px
    y = 40
    def page_marks():
        for p in range(0, 3):
            x = x0 + p * 4096 * scale
            s.line(x, y - 14, x, y + 40, stroke=RULE, sw=0.8, dash='2,2')
            s.text(x, y - 18, f'{p * 4096}' if p else 'page boundary 0', size=8.5, anchor='middle', fill=GRAY)
    page_marks()
    # row 1: HDAT chunk header starts at page boundary
    yy = y
    s.rect(x0 - 120, yy, 120, 26, fill=F_PAD, stroke=INK, sw=0.6, dash='2,2')
    s.text(x0 - 60, yy + 17, 'zero padding', size=9, anchor='middle', fill=INK2, italic=True)
    s.rect(x0, yy, 12 * scale * 12, 26, fill=F_TYPE, stroke=INK, sw=0.6)
    s.text(x0 + 12*scale*12/2, yy + 17, 'HDAT hdr 12 B', size=8.5, anchor='middle')
    s.rect(x0 + 12 * scale * 12, yy, 560, 26, fill=F_HASH, stroke=INK, sw=0.6)
    s.text(x0 + 12*scale*12 + 280, yy + 17, 'rows (the payload starts 12 bytes into the page)', size=9.5, anchor='middle')
    s.text(x0 - 120, yy - 6, 'HDAT: the chunk header sits on a 4096-byte boundary', size=10, italic=True, fill=INK2)
    return s


def fig_ridx():
    """RIDX: row -> record, with the real permutation from md5_sha1_a-b.hset."""
    rec = FX['md5_sha1']
    md5_rows = bytes.fromhex(rec['hdat_first'][0])
    sha_rows = bytes.fromhex(rec['hdat_first'][1])
    ridx_md5 = rec['ridx_first'][0][:8]
    ridx_sha = rec['ridx_first'][1][:8]
    recs = [bytes.fromhex(h) for h in rec['records_first']]
    W = 960
    s = SVG(W, 300)
    rh = 26
    y0 = 40
    # columns: md5 rows | ridx | records | ridx | sha1 rows
    xm, xr1, xrec, xr2, xs = 20, 200, 300, 700, 790
    s.text(xm, y0 - 14, 'md5 HDAT rows (sorted)', size=10, italic=True, fill=INK2)
    s.text(xr1, y0 - 14, 'md5 RIDX', size=10, italic=True, fill=INK2)
    s.text(xrec, y0 - 14, 'RDAT records (sorted by their bytes)', size=10, italic=True, fill=INK2)
    s.text(xr2, y0 - 14, 'sha1 RIDX', size=10, italic=True, fill=INK2)
    s.text(xs, y0 - 14, 'sha1 HDAT rows (sorted)', size=10, italic=True, fill=INK2)
    for i in range(8):
        y = y0 + i * rh
        m = md5_rows[i*16:(i+1)*16]
        s.rect(xm, y, 160, rh - 4, fill=F_HASH, stroke=INK, sw=0.5)
        s.text(xm + 4, y + 15, m[:6].hex() + '…', size=9.5, mono=True)
        s.text(xm - 4, y + 15, str(i), size=8.5, anchor='end', fill=GRAY)
        s.rect(xr1, y, 60, rh - 4, fill='#e6e9d7', stroke=INK, sw=0.5)
        s.text(xr1 + 30, y + 15, str(ridx_md5[i]), size=10, anchor='middle', mono=True)
        r = recs[i]
        s.rect(xrec, y, 290, rh - 4, fill='#f1e9ef', stroke=INK, sw=0.5)
        s.rect(xrec, y, 10, rh - 4, fill=F_HI, stroke=INK, sw=0.5)
        s.text(xrec + 5, y + 15, '1', size=8, anchor='middle', mono=True)
        s.text(xrec + 14, y + 15, r[1:7].hex() + '…', size=9.5, mono=True)
        s.rect(xrec + 145, y, 10, rh - 4, fill=F_HI, stroke=INK, sw=0.5)
        s.text(xrec + 150, y + 15, '1', size=8, anchor='middle', mono=True)
        s.text(xrec + 159, y + 15, r[18:24].hex() + '…', size=9.5, mono=True)
        s.text(xrec - 4, y + 15, str(i), size=8.5, anchor='end', fill=GRAY)
        s.rect(xr2, y, 60, rh - 4, fill='#e6e9d7', stroke=INK, sw=0.5)
        s.text(xr2 + 30, y + 15, str(ridx_sha[i]), size=10, anchor='middle', mono=True)
        sh = sha_rows[i*20:(i+1)*20]
        s.rect(xs, y, 150, rh - 4, fill=F_HASH, stroke=INK, sw=0.5)
        s.text(xs + 4, y + 15, sh[:6].hex() + '…', size=9.5, mono=True)
        s.text(xs - 4, y + 15, str(i), size=8.5, anchor='end', fill=GRAY)
        # arrows md5 row -> record (identity)
        s.line(xr1 + 60, y + 11, xrec - 3, y + 11, stroke=G_GREEN, sw=0.8, arrow=True)
        # arrows sha1 row -> record index (off the drawn part mostly)
        tgt = ridx_sha[i]
        if tgt < 8:
            s.line(xr2, y + 11, xrec + 293, y0 + tgt * rh + 11, stroke=O_ORANGE, sw=0.8, arrow=True)
        else:
            s.line(xr2, y + 11, xr2 - 24, y + 11, stroke=O_ORANGE, sw=0.8, arrow=False)
            s.text(xr2 - 28, y + 14, f'record {tgt}', size=8.5, anchor='end', fill=O_ORANGE, italic=True)
    s.text(xm, y0 + 8 * rh + 18, 'md5 is the first record field, so the records are already in md5 order and the md5 RIDX is the identity.', size=9.5, italic=True, fill=INK2)
    s.text(xm, y0 + 8 * rh + 32, 'The sha1 rows are in sha1 order, a different permutation of the same 340 records: their RIDX scatters.', size=9.5, italic=True, fill=INK2)
    return s


def fig_rhdr():
    rec = FX['md5_sha1']
    pl = bytes.fromhex(rec['rhdr'])
    a = 264 + 12
    spans = [
        (a, 8, F_NUM, 'record length = 38 (u64 LE): 1+16 for md5, 1+20 for sha1'),
        (a+8, 8, F_NUM, 'record count = 0x154 = 340'),
        (a+16, 2, F_HI, 'field type: log₂(SFHASH_MD5) = 0 (u16 LE)'), (a+18, 2, F_NUM, 'name length 3'), (a+20, 3, F_TYPE, '"md5"'), (a+23, 8, F_NUM, 'field length 16'),
        (a+31, 2, F_HI, 'field type 1 = sha1'), (a+33, 2, F_NUM, 'name length 4'), (a+35, 4, F_TYPE, '"sha1"'), (a+39, 8, F_NUM, 'field length 20'),
    ]
    return hexgrid(pl, spans, cols=16, start=a)


def fig_rhdr_fields():
    return bytefield([
        {'name': 'record length', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
        {'name': 'record count', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
        {'name': 'type', 'size': 2, 'type': 'u16 LE', 'fill': F_HI, 'units': 2},
        {'name': 'name', 'size': None, 'type': 'pstring', 'fill': F_TYPE, 'units': 3},
        {'name': 'length', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 3},
        {'name': '… one descriptor per field …', 'size': None, 'type': 'to the end of the payload', 'fill': F_DATA, 'units': 7, 'trunc': True},
    ], unit=24)


def fig_record():
    rec = FX['md5_sha1']
    r = bytes.fromhex(rec['records_first'][0])
    spans = [
        (0, 1, F_HI, 'presence byte of md5: 1 = present'), (1, 16, F_HASH, 'md5 value, 16 bytes'),
        (17, 1, F_HI, 'presence byte of sha1'), (18, 20, F_HASH, 'sha1 value, 20 bytes'),
    ]
    return hexgrid(r, spans, cols=19, start=0, show_ascii=False)


def fig_record_fields():
    return bytefield([
        {'name': 'p', 'size': 1, 'type': '0/1', 'fill': F_HI, 'units': 1.2},
        {'name': 'field 0 value', 'size': 16, 'type': 'length₀ bytes', 'fill': F_HASH, 'units': 5},
        {'name': 'p', 'size': 1, 'type': '0/1', 'fill': F_HI, 'units': 1.2},
        {'name': 'field 1 value', 'size': 20, 'type': 'length₁ bytes', 'fill': F_HASH, 'units': 6},
        {'name': '… more fields …', 'size': None, 'type': 'presence + value each, in RHDR order', 'fill': F_DATA, 'units': 8, 'trunc': True},
    ], unit=24)


def fig_tlsh_row():
    s = bytefield([
        {'name': 'L', 'size': 1, 'type': 'log length', 'fill': F_HI, 'units': 3},
        {'name': 'Q', 'size': 1, 'type': 'Q1≪4 | Q2', 'fill': F_HI2, 'units': 3},
        {'name': 'plane_hi', 'size': 16, 'type': 'bit i = high bit of bucket i', 'fill': F_HASH, 'units': 8},
        {'name': 'plane_lo', 'size': 16, 'type': 'bit i = low bit of bucket i', 'fill': '#d6e2d6', 'units': 8},
        {'name': 'chk', 'size': 1, 'type': 'checksum', 'fill': F_NUM, 'units': 3},
        {'name': '0', 'size': 1, 'type': 'reserved', 'fill': F_PAD, 'units': 3},
    ], unit=24)
    return s


def fig_cell_hint():
    return bytefield([
        {'name': 'hint type', 'size': 2, 'type': 'u16 BE = 0x7400', 'fill': F_HI, 'units': 4},
        {'name': 'offset[0] = 0', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 4},
        {'name': 'offset[1]', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 3},
        {'name': 'offset[2]', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 3},
        {'name': '… 65 537 offsets in all, one per (L, Q) cell plus the end …', 'size': 8 * 65533, 'type': 'non-decreasing', 'fill': F_NUM, 'units': 13, 'trunc': True, 'size_label': '524 264 B'},
        {'name': 'offset[65536] = n', 'size': 8, 'type': 'u64 LE', 'fill': F_NUM, 'units': 5},
    ], unit=24)


def fig_cells_csr():
    """cells as runs of the sorted HDAT with the offset array pointing at run starts."""
    W = 900
    s = SVG(W, 225)
    x0, y0 = 40, 40
    # HDAT strip: 40 rows, colored by cell
    n = 40
    rw = 20
    cells = [(0x1186, 0, 9), (0x1187, 9, 12), (0x1189, 12, 21), (0x118a, 21, 33), (0x118c, 33, 40)]
    fills = ['#e3ead9', '#dbe6ee', '#f3e6cf', '#e9dfe6', '#ece6d4']
    for ci, (c, a, b) in enumerate(cells):
        for i in range(a, b):
            s.rect(x0 + i * rw, y0 + 60, rw, 30, fill=fills[ci], stroke=INK, sw=0.5)
        s.text(x0 + (a + b) / 2 * rw, y0 + 60 + 19, f'cell {c:04x}', size=9, anchor='middle', mono=True)
    s.text(x0 + n * rw + 10, y0 + 60 + 19, 'HDAT rows', size=10, italic=True, fill=INK2)
    for i in range(0, n + 1, 5):
        s.text(x0 + i * rw, y0 + 60 + 44, str(i), size=8.5, anchor='middle', fill=GRAY)
    # offsets array above
    s.text(x0, y0 - 14, 'offset[c] for the cells 0x1185 … 0x118d', size=10, italic=True, fill=INK2)
    ids = list(range(0x1185, 0x118e))
    offs = {0x1185: 0, 0x1186: 0, 0x1187: 9, 0x1188: 12, 0x1189: 12, 0x118a: 21, 0x118b: 33, 0x118c: 33, 0x118d: 40}
    bw = 62
    for k, c in enumerate(ids):
        x = x0 + k * bw
        s.rect(x, y0, bw, 24, fill=F_NUM, stroke=INK, sw=0.6)
        s.text(x + bw / 2, y0 + 16, str(offs[c]), size=10, anchor='middle', mono=True)
        s.text(x + bw / 2, y0 - 3, f'{c:04x}', size=8.5, anchor='middle', fill=GRAY, mono=True)
        # arrow to the row boundary
        s.line(x + bw / 2, y0 + 24, x0 + offs[c] * rw, y0 + 58, stroke=S_BLUE, sw=0.7, arrow=True)
    s.text(x0, y0 + 60 + 62, 'The rows are sorted, so a cell (same L and Q, the first two bytes) is one contiguous run: the rows of cell c are [offset[c], offset[c+1]).', size=10, italic=True, fill=INK2)
    s.text(x0, y0 + 60 + 76, 'An empty cell (0x1188, 0x118b) repeats the next start, so its run is empty.', size=10, italic=True, fill=INK2)
    return s


def fig_tivf():
    s = bytefield([
        {'name': 'version', 'size': 2, 'type': 'u16 = 3', 'fill': F_NUM, 'units': 2},
        {'name': 'flags', 'size': 2, 'type': 'u16 = 0', 'fill': F_NUM, 'units': 2},
        {'name': 'dims', 'size': 4, 'type': 'u32 = 256', 'fill': F_NUM, 'units': 3},
        {'name': 'lists', 'size': 4, 'type': 'u32 = C', 'fill': F_HI, 'units': 3},
        {'name': 'reserved', 'size': 4, 'type': 'u32 = 0', 'fill': F_PAD, 'units': 3},
        {'name': 'n', 'size': 8, 'type': 'u64 = hash count', 'fill': F_NUM, 'units': 4},
        {'name': 'reserved', 'size': 8, 'type': 'u64 = 0', 'fill': F_PAD, 'units': 3},
        {'name': 'cell_lists', 'size': 4 * 65537, 'type': 'u32[65537]', 'fill': F_NUM, 'units': 5, 'trunc': True, 'size_label': '262 148 B'},
        {'name': 'medoids', 'size': None, 'type': '36 B digest × C', 'fill': F_HASH, 'units': 4, 'trunc': True, 'size_label': '36·C B'},
        {'name': 'radius2', 'size': None, 'type': 'u32 × C', 'fill': '#f0dcc8', 'units': 3, 'trunc': True, 'size_label': '4·C B'},
        {'name': 'list_start', 'size': None, 'type': 'u64 × (C+1)', 'fill': F_NUM, 'units': 4, 'trunc': True, 'size_label': '8·(C+1) B'},
        {'name': 'ids', 'size': None, 'type': 'u32 × n (row ids)', 'fill': '#e6e9d7', 'units': 5, 'trunc': True, 'size_label': '4·n B'},
    ], unit=22, max_units=5)
    return s


def fig_tivf_csr():
    """Two-level CSR: cells -> lists -> ids -> rows, drawn with the real two-list cell of inc_master."""
    d = FX['inc_master']['two_list_cell']
    c = d['cell']
    W = 900
    s = SVG(W, 300)
    x0 = 30
    # level 0: cell_lists
    y0 = 36
    s.text(x0, y0 - 14, f'cell_lists: the lists of cell c are [cell_lists[c], cell_lists[c+1])', size=10, italic=True, fill=INK2)
    cells = [c - 1, c, c + 1, c + 2]
    # we do not know neighbours' list counts; draw c as [L0, L0+2)
    L0 = 1000  # illustrative base list number
    vals = [L0, L0, L0 + 2, L0 + 2]
    bw = 90
    for k, cc in enumerate(cells):
        x = x0 + k * bw
        s.rect(x, y0, bw, 24, fill=F_NUM, stroke=INK, sw=0.6)
        s.text(x + bw / 2, y0 + 16, str(vals[k]), size=10, anchor='middle', mono=True)
        s.text(x + bw / 2, y0 - 3, f'c = 0x{cc:04x}', size=8.5, anchor='middle', fill=GRAY, mono=True)
    s.text(x0 + 4 * bw + 8, y0 + 16, '…', size=12)
    # level 1: lists (medoid, radius2, list_start)
    y1 = 110
    lx = x0 + 60
    lw = 300
    s.text(x0, y1 - 14, 'per list: medoid digest (36 B), radius2 (u32), list_start (u64) — three parallel arrays', size=10, italic=True, fill=INK2)
    starts = [20000, 20000 + d['lists'][0]['size'], 20000 + d['rows']]
    for k, lst in enumerate(d['lists']):
        x = lx + k * (lw + 20)
        s.rect(x, y1, lw, 44, fill='#f0dcc8', stroke=INK, sw=0.6)
        s.text(x + 6, y1 + 15, f'list {L0 + k}', size=9.5, italic=True, fill=INK2)
        s.text(x + 6, y1 + 34, 'medoid ' + lst['medoid'][:16] + '…', size=9.5, mono=True)
        s.text(x + lw - 6, y1 + 15, f"radius2 = {lst['radius2']}", size=9.5, anchor='end', mono=True)
        s.text(x + lw - 6, y1 + 34, f'list_start = {starts[k]}', size=9.5, anchor='end', mono=True)
        # arrows from cell_lists[c] / [c+1]
    s.line(x0 + 1.5 * bw, y0 + 24, lx + 10, y1 - 2, stroke=S_BLUE, sw=0.7, arrow=True)
    s.line(x0 + 2.5 * bw, y0 + 24, lx + 2 * (lw + 20) - 10, y1 - 2, stroke=S_BLUE, sw=0.7, arrow=True)
    s.text(lx + 2 * (lw + 20) + 4, y1 + 28, f'list_start[{L0+2}] = {starts[2]}', size=9, fill=INK2, italic=True)
    # level 2: ids
    y2 = 200
    s.text(x0, y2 - 14, 'ids: HDAT row indexes, ascending within each list; list l owns ids[list_start[l], list_start[l+1])', size=10, italic=True, fill=INK2)
    iw = 25
    allids = d['lists'][0]['ids'] + d['lists'][1]['ids']
    n0 = len(d['lists'][0]['ids'])
    for k, i in enumerate(allids):
        x = x0 + k * iw
        s.rect(x, y2, iw, 22, fill='#e6e9d7' if k < n0 else '#d9e8d2', stroke=INK, sw=0.5)
        s.text(x + iw / 2, y2 + 15, str(i), size=8.5, anchor='middle', mono=True)
    s.line(lx + 20, y1 + 44, x0 + 2, y2 - 2, stroke=O_ORANGE, sw=0.7, arrow=True)
    s.line(lx + lw + 40, y1 + 44, x0 + n0 * iw + 2, y2 - 2, stroke=O_ORANGE, sw=0.7, arrow=True)
    s.brace(x0, x0 + n0 * iw, y2 + 30, f'list {L0}: {n0} rows', size=9)
    s.brace(x0 + n0 * iw, x0 + len(allids) * iw, y2 + 30, f'list {L0+1}: {len(allids) - n0} rows', size=9)
    s.text(x0, y2 + 72, f'Real cell 0x{c:04x} (L = {c >> 8}, Q1 = {(c & 255) >> 4}, Q2 = {c & 15}) of test/inc_master.hset: {d["rows"]} rows, 2 lists; the ids are the cell\'s own rows {min(allids)}–{max(allids)}, interleaved between the lists.', size=9.5, italic=True, fill=INK2)
    return s


def fig_three_kinds():
    W = 900
    s = SVG(W, 150)
    kinds = [
        ('records + hash sets (the builder default)', ['FTOC', 'FHDR', 'RHDR', 'RDAT', 'HH(md5)', 'HINT', 'HDAT', 'RIDX', 'HH(tlsh)', 'HINT', 'HDAT', 'RIDX', 'TIVF', 'FEND']),
        ('hash sets only (write_records = false, or a merge of inputs without records)', ['FTOC', 'FHDR', 'HH(md5)', 'HINT', 'HDAT', 'HH(tlsh)', 'HINT', 'HDAT', 'TIVF', 'FEND']),
        ('records only (write_hashsets = false)', ['FTOC', 'FHDR', 'RHDR', 'RDAT', 'FEND']),
    ]
    y = 22
    for title, seq in kinds:
        s.text(20, y - 6, title, size=10, italic=True, fill=INK2)
        x = 20
        for ch in seq:
            w = 52 if not ch.startswith('HH(') else 62
            s.rect(x, y, w, 22, fill=chunk_fill('HH' if ch.startswith('HH') else ch), stroke=INK, sw=0.5)
            s.text(x + w / 2, y + 15, ch, size=8.5, anchor='middle', mono=True)
            x += w + 3
        y += 48
    return s


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------
def build():
    toc_good = FX['good']['toc']
    body = []
    B = body.append

    B('''<p>An <em class="term">hset</em> is a file of hashes made for one question asked millions of times: <em>is this digest in the set?</em> Its answer to that question is a sorted array of fixed-width rows, memory-mapped and searched in place, with small precomputed <em>hints</em> that let a lookup touch only a handful of cache lines. Around that array the file carries optional <em>records</em> (the other fields hashed alongside each row), and for TLSH similarity digests one more structure: an <em>inverted-file index</em> for exact nearest-neighbour search.</p>
<p>This page is about the bytes. Three companion pages explain the algorithms the bytes serve.</p>
<div class="cards">
<div class="card"><h3><a href="lookup.html">Exact lookup</a></h3><p>Why a sorted array of random hashes is nearly a straight line, how the file records the line's error per block, and how a lookup turns that into a window of a few cache lines.</p></div>
<div class="card"><h3><a href="tlsh.html">TLSH, embedding and index</a></h3><p>How a 36-byte TLSH digest becomes a point in 264 dimensions whose Euclidean distance never exceeds the TLSH distance, and how that bound drives the TIVF index.</p></div>
<div class="card"><h3><a href="merge.html">Set operations</a></h3><p>Union, intersection and difference by a two-pointer merge of the rows, with every derived structure, the TIVF lists included, carried through a row map instead of rebuilt.</p></div>
</div>''')

    B('<ul class="toc">' + ''.join(f'<li><span class="n">{n}</span><a href="#{a}">{t}</a></li>' for n, t, a in [
        (1, 'One file, seen whole', 'one-file-seen-whole'), (2, 'Chunks and the preamble', 'chunks-and-the-preamble'), (3, 'The table of contents', 'the-table-of-contents'),
        (4, 'The file header', 'the-file-header'), (5, 'The chunk grammar', 'the-chunk-grammar'), (6, 'A hash section', 'a-hash-section'),
        (7, 'Records', 'records'), (8, 'TLSH hash sections', 'tlsh-hash-sections'), (9, 'Alignment and integrity', 'alignment-and-integrity'),
        (10, 'Reference tables', 'reference-tables')]) + '</ul>')

    # 1
    B(h2(1, 'One file, seen whole'))
    B(f'''<p>Figure 1 draws a real file to scale: <code>test/md5_sha1_a-b.hset</code>, {FX['md5_sha1']['size']:,} bytes holding {FX['md5_sha1']['record_count']} records, each with an MD5 and a SHA-1. Everything after the first 40 bytes is a sequence of <em>chunks</em>, and the first chunk is a table of contents that locates all the others. Two things dominate the picture: the record table (one 38-byte record per file hashed) and, per hash type, a <em>section</em> of four chunks: a header, a 4 KiB hint, the sorted rows, and an index back into the records.{sn('The hash sections start on 4096-byte boundaries, so every section is preceded by zero padding (dotted). The padding is what makes the hints look large here: the 4 098-byte HINT and the 3.6 KiB of padding after it together fill the gap to the next page.')}</p>''')
    B(fig(fig_file_strip(), 'A records-and-hash-sets file to scale. Every box is a chunk; dotted boxes are zero padding to the next 4096-byte boundary. The two HDAT chunks hold the 340 sorted MD5 rows and the 340 sorted SHA-1 rows; each RIDX maps those rows back to their records.', 'wide'))

    # 2
    B(h2(2, 'Chunks and the preamble'))
    B(f'''<p>Every chunk has the same twelve-byte frame: a four-byte type that reads as ASCII, then a little-endian 64-bit payload length, then the payload. Nothing else in the file is self-describing; the frame is what lets a reader skip what it does not understand, and what lets <code>hschunks.py</code> hash each payload separately.{sn('All integers in the file are little-endian with two deliberate exceptions: chunk types, and the 16-bit hint type at the start of a HINT payload, are big-endian so that they read as text in a hex dump (<code>FTOC</code>, <code>HH\\x00\\x01</code>, <code>b\\x08</code>).')}</p>''')
    B(fig(fig_chunk_frame(), 'The chunk frame. The type is four bytes compared as a big-endian 32-bit integer; <code>HDAT</code> is 0x48444154.', 'col'))
    B('''<p>Before the first chunk come 40 bytes: the magic string <code>SetOHash</code> and a SHA-256. The digest covers every byte from offset 40 to the end of the file, so it authenticates the table of contents, the headers, the rows and the hints together; the merge and build code compute it last, after every other byte is in place. Figure 3 is the real head of <code>test/good.hset</code>, a hash-sets-only file with one SHA-1 section.</p>''')
    B(fig(fig_preamble(), 'The first 164 bytes of <code>test/good.hset</code>. After the magic and the SHA-256, the FTOC chunk at offset 40 lists six (offset, type) entries; the 36 zero bytes after its payload are room the writer reserved for chunks the file might have had, and the FHDR chunk starts at the offset the FTOC says: 160.', 'wide'))

    # 3
    B(h2(3, 'The table of contents'))
    B('''<p>The FTOC payload is a flat array of twelve-byte entries, one per chunk in file order, FTOC itself included and FEND last. Each entry is the chunk's absolute byte offset (u64, little-endian) followed by its type (u32, big-endian, the same bytes as the chunk's own type field). A reader decodes the FTOC, then visits every listed offset in turn and checks that the type it finds there matches; the sequence of types must satisfy the grammar of §5.</p>''')
    B(fig(fig_ftoc_entries(), 'The six FTOC entries of <code>test/good.hset</code>, decoded. The HH entry carries the hash type in its last two bytes.', 'wide'))
    B('''<p>The FTOC is written first but its contents are only known once the layout is final, so the builder sizes it from the number of fields when the output is opened and reserves room for every chunk a field <em>might</em> produce (a TLSH field may add a TIVF). The chunk is then written shorter than the reservation, and the gap before FHDR is zero.</p>''')

    # 4
    B(h2(4, 'The file header'))
    B('''<p>FHDR holds the format version and three strings. Strings throughout the file are <em>pstrings</em>: a 16-bit little-endian length followed by that many bytes, without a terminator.</p>''')
    B(fig(fig_pstring(), 'A pstring.', 'col'))
    B(fig(fig_fhdr_fields(), 'The FHDR payload: version, then the set\'s name, its creation timestamp and its description.', 'col'))
    B(fig(fig_fhdr(), 'The FHDR chunk of <code>test/good.hset</code>: version 2, name "Test Name", a UTC timestamp, description "Test Description".', 'wide'))

    # 5
    B(h2(5, 'The chunk grammar'))
    B('''<p>The decoder is a small state machine driven by the FTOC. After FHDR comes an optional record table (RHDR then RDAT), then any number of hash sections, then FEND, the last entry: an FTOC that lists anything after FEND is rejected. A hash section is a run of chunks that all belong to the HH header that opens it: a HINT (every hash type except <code>sizes</code>), the HDAT rows, and then only when the file has records a RIDX, and only for TLSH an optional TIVF, always in that order. A TIVF after a non-TLSH section is a hard error, and so is a TVEC anywhere: that chunk once stored the embedding of every row and is no longer part of the format.</p>''')
    B(fig(fig_grammar(), 'The legal chunk sequences. Reading starts at byte 40 with FTOC; each arrow is "the next chunk may be"; the doubled circle is the end of the file.', 'wide'))

    # 6
    B(h2(6, 'A hash section'))
    B('''<p>A section opens with an <code>HHnn</code> chunk. The type field spells <code>H</code>, <code>H</code> and then a big-endian 16-bit number: the position of the hash algorithm's bit in the <code>SFHASH_HashAlgorithm</code> enum (MD5 is bit 0, SHA-1 bit 1, TLSH bit 15), so a reader recovers the algorithm as <code>1 &lt;&lt; nn</code>. The payload names the field, gives the row width and the row count.</p>''')
    B(fig(fig_hhnn_fields(), 'The HHnn chunk: the hash type lives in the chunk type itself.', 'col'))
    B(fig(fig_hhnn(), 'The HH chunk of <code>test/good.hset</code>: type bit 1 (SHA-1), field name "sha1", 20-byte rows, 665 of them.', 'wide'))

    B(h3('HINT: the lookup hint'))
    B('''<p>Next comes HINT, a payload that starts with a big-endian 16-bit <em>hint type</em> and continues with data that type defines. Two hint types exist. Every cryptographic hash section carries type <code>0x6208</code>, the <em>8-bit block bounds</em>: for each of the 256 possible leading bytes, the smallest and largest signed deviation of any stored row from its predicted position. <a href="lookup.html">The exact-lookup page</a> explains what that prediction is and why the bounds make lookups fast; here it is enough that the payload is 2 + 256 × 16 = 4 098 bytes, always, whatever the set size.</p>''')
    B(fig(fig_hint_block(), 'The 0x6208 HINT payload: 256 pairs of signed 64-bit integers indexed by the leading byte of a hash.', 'wide'))
    B(fig(fig_hint_block_bytes(), 'The first six blocks of <code>test/good.hset</code>\'s hint. Block 0x05 has no stored hash; its sentinel pair (INT64_MAX, INT64_MIN) makes any lookup of a hash starting with 0x05 a miss without touching the rows.', 'wide'))
    B('''<p>TLSH sections carry hint type <code>0x7400</code> instead, the <em>cell index</em> of §8. The <code>sizes</code> field (8-byte file sizes, not uniformly distributed) carries no HINT at all and is searched by plain binary search.</p>''')

    B(h3('HDAT: the rows'))
    B('''<p>HDAT is the heart of the file: <em>hash count</em> rows of <em>hash length</em> bytes each, sorted in ascending bytewise order, nothing between them. The chunk is placed so that its 12-byte header sits on a 4096-byte boundary. Rows are unique in a hash-sets-only file; in a file with records two different records may carry the same digest, and then the digest appears twice, each copy pointing at its own record through RIDX.</p>''')
    B(fig(fig_hdat(), 'The HDAT chunk of <code>test/good.hset</code>. The leading byte selects the hint block; the first eight bytes, read as one big-endian integer, are the <em>primary key</em> the binary search compares; the rest is only consulted when two primary keys tie.', 'wide'))

    B(h3('RIDX: rows to records'))
    B('''<p>When the file has a record table, each HDAT is followed by RIDX: one little-endian u64 per row, the index of the record the row came from. The rows of a section are sorted by their own value, the records by their full bytes; the two orders agree only for the first record field, so RIDX is in general a permutation. <code>sfhash_hashset_record_for_hash</code> is a single array read: <code>rdat + RIDX[row] × record_length</code>.</p>''')
    B(fig(fig_ridx(), 'The first eight rows of each section of <code>test/md5_sha1_a-b.hset</code> and their RIDX entries. Green: the md5 rows map to records 0–7 in order. Orange: the sha1 rows, sorted by SHA-1, point all over the 340 records.', 'wide'))

    # 7
    B(h2(7, 'Records'))
    B('''<p>A record is everything that was hashed about one input: its MD5, its SHA-1, its size, its TLSH, whichever fields the set was built with. RHDR declares the fields; RDAT is the fixed-width record table. Field order is the order given when the builder was opened, and it fixes the record layout: each field is a <em>presence byte</em> (0 or 1) followed by the field's value, zero-filled when absent. A TLSH column of <code>TNULL</code>, or any empty column, is written absent and contributes no row to its hash section.</p>''')
    B(fig(fig_rhdr_fields(), 'The RHDR payload: the record width, the record count, then a descriptor per field with its type bit, name and value length.', 'wide'))
    B(fig(fig_rhdr(), 'The RHDR chunk of <code>test/md5_sha1_a-b.hset</code>: 38-byte records, 340 of them, two fields.', 'wide'))
    B(fig(fig_record_fields(), 'One record. The presence byte precedes every value, so the sort key of a record begins with "is the first field present".', 'wide'))
    B(fig(fig_record(), 'Record 0 of <code>test/md5_sha1_a-b.hset</code>: both fields present.', 'wide'))
    B('''<p>Records are sorted by their full bytes and deduplicated before writing, so identical inputs collapse to one record, and the record count in RHDR is the number of distinct records. Because the presence byte comes first within each field, all records lacking their first field sort before all records that have it.</p>''')

    # 8
    B(h2(8, 'TLSH hash sections'))
    B('''<p>A TLSH section stores rows of 36 bytes: the canonical digest below rather than the 70-character hex form. The byte order was chosen so that the ordinary bytewise sort used for every other hash type yields the canonical TLSH order <em>L, Q1, Q2, body, checksum</em>. The two body planes keep the high bits and the low bits of the 128 two-bit bucket codes apart, which is what makes the distance kernel on the <a href="tlsh.html">TLSH page</a> three popcounts instead of 32 table lookups. The all-zero row is <code>TNULL</code> and never appears.</p>''')
    B(fig(fig_tlsh_row(), 'The 36-byte canonical TLSH row. Bit <i>i</i> of a plane lives in byte <i>i</i>/8 at bit position <i>i</i> mod 8.', 'wide'))
    B(h3('HINT 0x7400: the cell index'))
    B('''<p>The first two bytes of a row, L and Q, define its <em>cell</em>: c = L ≪ 8 | Q, one of 65 536. Because rows are sorted and these are the leading bytes, every cell is a contiguous run of HDAT. The hint stores where each run starts.</p>''')
    B(fig(fig_cell_hint(), 'The 0x7400 HINT payload: 65 537 little-endian offsets. The hint data begins 12 bytes into the chunk and the offsets 14 bytes in, so the array is not 8-byte aligned in the file; the reader copies it when it needs alignment.', 'wide'))
    B(fig(fig_cells_csr(), 'Compressed-sparse-row addressing: cell c owns rows [offset[c], offset[c+1]). A lookup computes c from the digest, then binary-searches only that run.', 'wide'))
    B(h3('No stored embedding'))
    B('''<p>The 264-dimensional float32 embedding of the <a href="tlsh.html">TLSH page</a> is not in the file. An early version stored it for every row in a TVEC chunk after RIDX, page-aligned for numpy and faiss; at 1 056 bytes per row, about thirty times the digest, it was most of a TLSH file, and the index below never read it. TVEC was removed before TLSH support was released: no writer emits it and a reader rejects a file that has one. Whoever needs the matrix computes it from the rows with <code>sfhash_tlsh_embed</code>.</p>''')
    B(h3('TIVF: the inverted-file index'))
    B('''<p>Last in a TLSH section comes TIVF, the index that makes exact nearest-neighbour search fast. Structurally it is a two-level CSR: cells point at ranges of <em>lists</em>, lists point at ranges of row ids. Each list carries a <em>medoid</em> (a 36-byte digest, the list's centre) and <em>radius2</em>, the largest squared body-embedding distance from the medoid to any member. Those two values are the whole of what the search relies on: how the rows were partitioned into lists is the writer's business, and <a href="tlsh.html#the-tivf-index">the TLSH page</a> describes libhasher's two builders.</p>''')
    B(fig(fig_tivf(), 'The TIVF payload (version 3). The five arrays follow the header back to back; <code>list_start</code> is only 4-byte aligned in general.', 'wide'))
    B(fig(fig_tivf_csr(), 'The two indirections, drawn with a real cell of <code>test/inc_master.hset</code>. A reader validates the header, the lengths and the two offset arrays at load time; the ids it trusts.', 'wide'))

    # 9
    B(h2(9, 'Alignment and integrity'))
    B('''<p>One alignment rule shapes the file: every HDAT chunk starts on a 4096-byte boundary, so the rows of each section begin 12 bytes into a page and a section's pages are its own. Zero bytes fill the gaps, and the FTOC never lists them.</p>''')
    B(fig(fig_alignment(), 'The alignment rule: HDAT aligns its chunk header.', 'wide'))
    B('''<p>Integrity rests on the SHA-256 at offset 8, computed over [40, end). A reader additionally checks: the magic; that every FTOC entry's offset holds a chunk of the listed type; that the chunk sequence obeys the grammar; that each HDAT is exactly count × length bytes, each RIDX count × 8, RDAT record_count × record_length; the hint type, the 0x7400 offsets (first 0, last n, non-decreasing); and the TIVF header, its total length and its two offset arrays. It does not read the TIVF ids or verify the sort order at load time; both would touch every page of the file.</p>''')
    B(fig(fig_three_kinds(), 'The three shapes of file the builder and the merge produce.', 'wide'))

    # 10
    B(h2(10, 'Reference tables'))
    B(h3('Chunk types'))
    chunks = [
        ('FTOC', '0x46544F43', 'table of contents', '12 B per chunk'),
        ('FHDR', '0x46484452', 'version, name, timestamp, description', 'variable'),
        ('RHDR', '0x52484452', 'record width, count, field descriptors', 'variable'),
        ('RDAT', '0x52444154', 'the record table', 'count × record length'),
        ('HHnn', '0x4848nnnn', 'hash section header; nn = log₂(type bit), big-endian', 'variable'),
        ('HINT', '0x48494E54', 'u16 BE hint type, then 0x6208 block bounds or 0x7400 cell offsets', '4 098 or 524 298'),
        ('HDAT', '0x48444154', 'sorted rows', 'count × length'),
        ('RIDX', '0x52494458', 'row → record index', 'count × 8'),
        ('TVEC', '0x54564543', 'removed: once the TLSH embedding matrix; rejected', '—'),
        ('TIVF', '0x54495646', 'TLSH inverted-file index', '32 + 262 148 + 48 C + 8 + 4 n'),
        ('FEND', '0x46454E44', 'end marker', '0'),
        ('FLTR', '0x464C5452', 'binary fuse filter; defined, never written', '—'),
    ]
    B(table(['type', 'value', 'payload', 'payload bytes'], chunks, mono=(0, 1)))
    B(h3('Hash types'))
    rows = []
    for bit, name, ln in HASH_TYPES:
        rows.append((f'{bit}', name, f'1 ≪ {bit} = 0x{1 << bit:04x}', str(ln) if ln else '—', 'HH\\x00\\x%02x' % bit if ln else 'no hash section',
                     '0x7400 cell index' if name == 'tlsh' else ('none' if name == 'sizes' else ('0x6208 block bounds' if ln else '—'))))
    B(table(['nn', 'field name', 'enum value', 'row bytes', 'chunk type', 'HINT'], rows, numeric=(0, 3), mono=(1, 2, 4)))
    B('''<p class="note">The lookup code is instantiated for row lengths 4, 8, 16, 20, 28, 32, 36, 48 and 64; a file with another hash length is rejected.</p>''')
    return page('index.html', 'The hset file', 'A sorted array, its hints, the records behind it, and the TLSH index that rides along, byte by byte.', ''.join(body))
