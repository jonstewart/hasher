"""A faithful pure-Python model of libhasher's TLSH digest, distance, body
embedding, header order and TIVF search, used to compute the figures."""
import math, struct, heapq

def swap_nibbles(b): return ((b << 4) | (b >> 4)) & 0xff

class Digest:
    __slots__ = ('L', 'Q', 'hi', 'lo', 'checksum', 'raw')
    def __init__(self, row):
        self.raw = bytes(row)
        self.L, self.Q = row[0], row[1]
        self.hi = int.from_bytes(row[2:18], 'little')
        self.lo = int.from_bytes(row[18:34], 'little')
        self.checksum = row[34]
    def q1(self): return self.Q >> 4
    def q2(self): return self.Q & 15
    def bucket(self, i): return (((self.hi >> i) & 1) << 1) | ((self.lo >> i) & 1)
    def codes(self): return [self.bucket(i) for i in range(128)]
    def cell(self): return (self.L << 8) | self.Q
    @staticmethod
    def from_parts(L, q1, q2, checksum, codes):
        hi = lo = 0
        for i, c in enumerate(codes):
            hi |= ((c >> 1) & 1) << i
            lo |= (c & 1) << i
        row = bytes([L, (q1 << 4) | q2]) + hi.to_bytes(16, 'little') + lo.to_bytes(16, 'little') + bytes([checksum, 0])
        return Digest(row)

def from_hex(h):
    if h.startswith('T1'): h = h[2:]
    raw = bytes.fromhex(h)
    checksum = swap_nibbles(raw[0]); L = swap_nibbles(raw[1])
    q1, q2 = raw[2] >> 4, raw[2] & 15
    codes = []
    for i in range(32):
        cb = raw[3 + 31 - i]
        for j in range(4):
            codes.append((cb >> (2 * j)) & 3)
    return Digest.from_parts(L, q1, q2, checksum, codes), raw

def to_hex(d):
    raw = bytearray(35)
    raw[0] = swap_nibbles(d.checksum); raw[1] = swap_nibbles(d.L); raw[2] = d.Q
    for i in range(32):
        cb = 0
        for j in range(4):
            cb |= d.bucket(4 * i + j) << (2 * j)
        raw[3 + 31 - i] = cb
    return 'T1' + raw.hex().upper()

def l_cost(k): return 0 if k == 0 else (1 if k == 1 else 12 * k)
def q_cost(k): return k if k <= 1 else 12 * (k - 1)
def mod_diff(x, y, r):
    d = abs(x - y); return min(d, r - d)
BODY_COST = [0, 1, 2, 6]

M128 = (1 << 128) - 1
def body_terms(a, b):
    X = a.lo ^ b.lo; Y = a.hi ^ b.hi; S = ~(a.lo ^ a.hi) & M128
    return (X ^ Y).bit_count(), Y.bit_count(), (X & Y & S).bit_count()
def body_diff(a, b):
    t1, t2, t3 = body_terms(a, b); return t1 + t2 + 5 * t3
def emb_body2(a, b):
    t1, t2, t3 = body_terms(a, b); return t1 + t2 + 4 * t3
def header_diff(a, b, include_length=True):
    d = int(a.checksum != b.checksum)
    if include_length: d += l_cost(mod_diff(a.L, b.L, 256))
    d += q_cost(mod_diff(a.q1(), b.q1(), 16)) + q_cost(mod_diff(a.q2(), b.q2(), 16))
    return d
def diff(a, b, include_length=True): return header_diff(a, b, include_length) + body_diff(a, b)

# full embedding
Q_RADIUS = 1 / (2 * math.sin(math.pi / 16))
QX = [Q_RADIUS * math.cos(2 * math.pi * q / 16) for q in range(16)]
QY = [Q_RADIUS * math.sin(2 * math.pi * q / 16) for q in range(16)]
BODY_PT = [(1, 0), (0, 0), (0, 1), (-1, 1)]
def embed(d):
    v = []
    for i in range(128):
        v.extend(BODY_PT[d.bucket(i)])
    v.append(float(d.L))
    v += [QX[d.q1()], QY[d.q1()], QX[d.q2()], QY[d.q2()]]
    s3 = 1 / math.sqrt(3)
    v += [s3 if d.checksum & 1 else 0.0, s3 if d.checksum & 2 else 0.0, s3 if d.checksum & 4 else 0.0]
    return v
def embed_dist2(a, b, include_length=True):
    va, vb = embed(a), embed(b)
    s = sum((x - y) ** 2 for x, y in zip(va, vb))
    if not include_length: s -= (va[256] - vb[256]) ** 2
    return s

# header order
def qpairs():
    pairs = [(k1, k2) for k1 in range(9) for k2 in range(9)]
    pairs.sort(key=lambda p: q_cost(p[0]) + q_cost(p[1]))  # stable
    return pairs
QPAIRS = qpairs()

def header_order(q, include_length=True):
    l, l_c = [], []
    if include_length:
        l.append(q.L); l_c.append(0)
        for k in range(1, 129):
            c = l_cost(k)
            l.append((q.L + k) & 255); l_c.append(c)
            if k != 128:
                l.append((q.L - k) & 255); l_c.append(c)
    else:
        l = list(range(256)); l_c = [0] * 256
    qs, q_c = [], []
    q1, q2 = q.q1(), q.q2()
    for k1, k2 in QPAIRS:
        c = q_cost(k1) + q_cost(k2)
        a1, b1 = (q1 + k1) & 15, (q1 - k1) & 15
        a2, b2 = (q2 + k2) & 15, (q2 - k2) & 15
        qs.append((a1 << 4) | a2); q_c.append(c)
        if b2 != a2: qs.append((a1 << 4) | b2); q_c.append(c)
        if b1 != a1:
            qs.append((b1 << 4) | a2); q_c.append(c)
            if b2 != a2: qs.append((b1 << 4) | b2); q_c.append(c)
    return l, l_c, qs, q_c

# TIVF
class Ivf:
    def __init__(self, payload):
        ver, fl, dims, lists, res, n, res2 = struct.unpack_from('<HHIIIQQ', payload, 0)
        cur = 32
        self.lists, self.n = lists, n
        self.cell_lists = struct.unpack_from('<%dI' % 65537, payload, cur); cur += 65537 * 4
        self.medoids = [Digest(payload[cur + 36 * l: cur + 36 * (l + 1)]) for l in range(lists)]; cur += 36 * lists
        self.radius2 = struct.unpack_from('<%dI' % lists, payload, cur); cur += 4 * lists
        self.list_start = struct.unpack_from('<%dQ' % (lists + 1), payload, cur); cur += 8 * (lists + 1)
        self.ids = struct.unpack_from('<%dI' % n, payload, cur)

def load_rows(payload):
    return [Digest(payload[i:i + 36]) for i in range(0, len(payload), 36)]

def list_bound(d2, r2):
    b = math.sqrt(d2) - math.sqrt(r2)
    return max(0.0, b * b - 1e-2) if b > 0 else 0.0

MIN_BOUNDED_LIST = 4

class Knn:
    """bounded max-heap on (distance, index); python heapq is a min-heap so negate"""
    def __init__(self, k, max_distance):
        self.k = k; self.heap = []; self.tau = max_distance
    def consider(self, d, i):
        key = (-d, -i)
        if len(self.heap) < self.k:
            heapq.heappush(self.heap, key)
        elif (d, i) < (-self.heap[0][0], -self.heap[0][1]):
            heapq.heapreplace(self.heap, key)
        else:
            return
        if len(self.heap) == self.k:
            self.tau = -self.heap[0][0]
    def result(self):
        return sorted((-d, -i) for d, i in self.heap)

def knn_brute(rows, q, k, max_distance, include_length=True):
    kn = Knn(k, max_distance)
    for i, r in enumerate(rows):
        hd = header_diff(q, r, include_length)
        if hd > kn.tau: continue
        d = hd + body_diff(q, r)
        if d <= kn.tau: kn.consider(d, i)
    return kn.result()

def knn_ivf(ivf, rows, q, k, max_distance, include_length=True, trace=None):
    """returns (matches, stats); trace, if a list, receives one entry per visited cell"""
    l, l_c, qs, q_c = header_order(q, include_length)
    kn = Knn(k, max_distance)
    stats = {'cells': 0, 'lists': 0, 'rows': 0}
    for li in range(256):
        cl = l_c[li]
        if cl > kn.tau: break
        for qi in range(256):
            ch = cl + q_c[qi]
            if ch > kn.tau: break
            c = (l[li] << 8) | qs[qi]
            fl, el = ivf.cell_lists[c], ivf.cell_lists[c + 1]
            if fl == el: continue
            stats['cells'] += 1
            t = {'cell': c, 'ch': ch, 'tau_in': kn.tau, 'lists': el - fl, 'bounded': 0, 'scanned_lists': 0, 'rows': 0, 'bounds': []}
            if el - fl == 1:
                lb, le = ivf.list_start[fl], ivf.list_start[el]
                count = le - lb
                if count < MIN_BOUNDED_LIST:
                    scan = True
                else:
                    b2 = list_bound(emb_body2(q, ivf.medoids[fl]), ivf.radius2[fl])
                    t['bounded'] = 1; stats['lists'] += 1; t['bounds'].append((b2, count))
                    scan = ch + b2 <= kn.tau
                if scan:
                    first = ivf.ids[lb]
                    t['scanned_lists'] = 1; t['rows'] = count; stats['rows'] += count
                    for i in range(first, first + count):
                        r = rows[i]
                        d = ch + int(r.checksum != q.checksum) + body_diff(q, r)
                        if d <= kn.tau: kn.consider(d, i)
            else:
                cands = []
                stats['lists'] += el - fl; t['bounded'] = el - fl
                for ll in range(fl, el):
                    b2 = list_bound(emb_body2(q, ivf.medoids[ll]), ivf.radius2[ll])
                    t['bounds'].append((b2, ivf.list_start[ll + 1] - ivf.list_start[ll]))
                    if ch + b2 <= kn.tau: cands.append((b2, ll))
                cands.sort()
                for b2, ll in cands:
                    if ch + b2 > kn.tau: break
                    t['scanned_lists'] += 1
                    for p in range(ivf.list_start[ll], ivf.list_start[ll + 1]):
                        i = ivf.ids[p]; r = rows[i]
                        t['rows'] += 1; stats['rows'] += 1
                        d = ch + int(r.checksum != q.checksum) + body_diff(q, r)
                        if d <= kn.tau: kn.consider(d, i)
            t['tau_out'] = kn.tau
            if trace is not None: trace.append(t)
    return kn.result(), stats
