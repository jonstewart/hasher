#!/usr/bin/python3

# TLSH hash sets: the pure-Python chunk walker (hasher.hsvectors), the kNN
# bindings and the embeddings computed from the rows, against an hset built
# by the mkhashset binary from the sibling build tree.

import hashlib
import os
import random
import subprocess
import tempfile
import unittest

import hasher
from hasher import hsvectors

try:
    import numpy as np
except ImportError:
    np = None

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
MKHASHSET = os.path.join(REPO, 'src', 'mkhashset', 'mkhashset')
REFERENCE = os.path.join(
    REPO, 'vendors', 'tlsh', 'Testing', 'exp', 'example_data.128.1.len.out_EXP'
)

FAMILIES = 40
VARIANTS = 8


def reference_digests():
    """The 80 'T1...' digests of the vendored TLSH test suite."""
    with open(REFERENCE) as f:
        return [line.split()[0] for line in f if line.strip()]


def tlsh_of(buf):
    with hasher.Hasher(hasher.TLSH) as h:
        h.update(buf)
        return bytes(h.get_hashes().tlsh)


def synthetic_digests(rng):
    """Families of near-duplicate inputs hashed through libhasher, so the
    fixture has close neighbours: a base of random bytes and variants with a
    few percent of the bytes replaced."""
    digests = []
    for _ in range(FAMILIES):
        base = bytearray(rng.randbytes(rng.randrange(512, 3072)))
        for _ in range(VARIANTS):
            buf = bytearray(base)
            for _ in range(max(1, len(buf) // 50)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            d = tlsh_of(bytes(buf))
            if not hasher.tlsh_is_null(d):
                digests.append(d)
    return digests


def brute_knn(rows, q, k, max_distance, include_length):
    """Reference kNN: every row's TLSH distance, nearest first, ties by index."""
    hits = []
    for i, r in enumerate(rows):
        d = hasher.tlsh_diff(q, r, include_length)
        if 0 <= d <= max_distance:
            hits.append((i, d))
    hits.sort(key=lambda h: (h[1], h[0]))
    return hits[:k]


@unittest.skipUnless(
    os.path.exists(MKHASHSET),
    f'{MKHASHSET} not built; run make first'
)
class TestTlshHashset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = random.Random(20251021)

        cls.ref = [hasher.tlsh_from_hex(h) for h in reference_digests()]
        cls.digests = cls.ref + synthetic_digests(rng)
        # a digest not in the set, and perturbed copies of members
        cls.queries = [cls.digests[0], cls.digests[-1], cls.digests[len(cls.digests) // 2]]
        cls.queries += [tlsh_of(rng.randbytes(2048)) for _ in range(3)]

        cls.tmpdir = tempfile.TemporaryDirectory(prefix='hasher-tlsh-')
        txt = cls.txt_path = os.path.join(cls.tmpdir.name, 'md5_tlsh.txt')
        cls.hset_path = os.path.join(cls.tmpdir.name, 'md5_tlsh.hset')
        with open(txt, 'w') as f:
            for d in cls.digests:
                hx = hasher.tlsh_to_hex(d)
                f.write(f'{hashlib.md5(hx.encode()).hexdigest()} {hx}\n')

        subprocess.run(
            [MKHASHSET, 'tlsh test', 'md5 and tlsh with an index',
             'md5', 'tlsh', 'true', 'true', txt, cls.hset_path],
            check=True, cwd=cls.tmpdir.name, capture_output=True
        )

        # the rows are the sorted digests (records keep duplicates)
        cls.rows = sorted(cls.digests)
        cls.hset = hasher.HSet.open(cls.hset_path)
        cls.tidx = cls.hset.index_for_type(hasher.TLSH)

    @classmethod
    def tearDownClass(cls):
        cls.hset.destroy()
        cls.tmpdir.cleanup()

    # hsvectors: chunk walker

    def test_toc_order(self):
        toc = hsvectors.read_toc(self.hset_path)
        types = [e.type for e in toc]
        self.assertEqual('FTOC', types[0])
        self.assertEqual('FEND', types[-1])
        self.assertEqual(40, toc[0].offset)

        tlsh_hhdr = 'HH\x00\x0f'
        self.assertIn(tlsh_hhdr, types)
        self.assertEqual(hasher.TLSH, hsvectors.hhdr_hash_type(tlsh_hhdr))
        self.assertEqual('HHDR(tlsh)', hsvectors.chunk_name(tlsh_hhdr))
        i = types.index(tlsh_hhdr)
        self.assertEqual(['HINT', 'HDAT', 'RIDX', 'TIVF', 'FEND'], types[i + 1:])

        # chunk headers agree with the FTOC
        with open(self.hset_path, 'rb') as f:
            data = f.read()
        for e in toc:
            self.assertEqual(e.type, data[e.offset:e.offset + 4].decode('latin-1'))
            self.assertEqual(e.length, int.from_bytes(data[e.offset + 4:e.offset + 12], 'little'))
        self.assertEqual(toc, hsvectors.read_toc(data))

    def test_sections(self):
        secs = hsvectors.tlsh_sections(self.hset_path)
        self.assertEqual(1, len(secs))
        sec = secs[0]
        self.assertEqual(('hhdr', 'hint', 'hdat', 'ridx', 'tivf'), hsvectors.TlshSection._fields)
        self.assertEqual(len(self.rows) * 36, sec.hdat.length)
        self.assertEqual(len(self.rows) * 8, sec.ridx.length)
        self.assertIsNotNone(sec.tivf)

        iv = hsvectors.tivf_header(self.hset_path)
        self.assertEqual(3, iv.version)
        self.assertEqual(256, iv.dims)
        self.assertEqual(len(self.rows), iv.n)
        self.assertGreater(iv.lists, 0)

    def test_tvec_chunk_is_rejected(self):
        # TVEC (the stored embedding, removed from the format) is not an
        # allowed chunk: retype the TIVF chunk, in the FTOC and its header
        with open(self.hset_path, 'rb') as f:
            data = bytearray(f.read())
        toc = hsvectors.read_toc(bytes(data))
        i = [e.type for e in toc].index('TIVF')
        data[52 + 12 * i + 8:52 + 12 * i + 12] = b'TVEC'
        data[toc[i].offset:toc[i].offset + 4] = b'TVEC'
        self.assertEqual('TVEC', hsvectors.read_toc(bytes(data))[i].type)
        with self.assertRaisesRegex(ValueError, 'TVEC'):
            hsvectors.tlsh_sections(bytes(data))

    def test_hset_tlsh_options_3_means_index(self):
        # bit 1 of HSET_TLSH_OPTIONS is reserved and ignored
        out = os.path.join(self.tmpdir.name, 'opt3.hset')
        subprocess.run(
            [MKHASHSET, 'tlsh test', 'md5 and tlsh with an index',
             'md5', 'tlsh', 'true', 'true', self.txt_path, out],
            check=True, cwd=self.tmpdir.name, capture_output=True,
            env=dict(os.environ, HSET_TLSH_OPTIONS='3')
        )
        want = [(e.type, e.length) for e in hsvectors.read_toc(self.hset_path)]
        self.assertEqual(want, [(e.type, e.length) for e in hsvectors.read_toc(out)])

    def test_not_an_hset(self):
        with self.assertRaises(ValueError):
            hsvectors.read_toc(b'SetOHasX' + bytes(64))
        with self.assertRaises(ValueError):
            hsvectors.read_toc(b'short')

    def test_rows_pure_python(self):
        digests = hsvectors.tlsh_digest_rows(self.hset_path)
        self.assertEqual(self.rows, digests)
        for r, d in enumerate(digests):
            self.assertEqual(d, self.hset.hash(self.tidx, r))

        ridx = hsvectors.tlsh_record_index_rows(self.hset_path)
        self.assertEqual(len(digests), len(ridx))
        self.assertEqual(set(range(len(digests))), set(ridx))

    def test_chunk_sha256(self):
        # the HDAT payload is the rows the test wrote, in canonical order
        hdat = hsvectors.tlsh_sections(self.hset_path)[0].hdat
        want = hashlib.sha256(b''.join(self.rows)).hexdigest()
        self.assertEqual(want, hsvectors.chunk_sha256(self.hset_path, hdat))
        # small blocks and a buffer give the same digest
        self.assertEqual(want, hsvectors.chunk_sha256(self.hset_path, hdat, block_size=7))
        with open(self.hset_path, 'rb') as f:
            data = f.read()
        self.assertEqual(want, hsvectors.chunk_sha256(data, hdat))
        # every chunk's digest is that of its payload
        for e in hsvectors.read_toc(data):
            payload = data[e.offset + 12:e.offset + 12 + e.length]
            self.assertEqual(hashlib.sha256(payload).hexdigest(), hsvectors.chunk_sha256(data, e))

    def test_tlsh_hex(self):
        for d in self.rows:
            hx = hsvectors.tlsh_hex(d)
            self.assertEqual(hasher.tlsh_to_hex(d), hx)
            self.assertEqual(d, hasher.tlsh_from_hex(hx))
            self.assertEqual(d, hsvectors.tlsh_from_hex(hx))
        self.assertEqual('TNULL', hsvectors.tlsh_hex(bytes(36)))
        self.assertEqual(bytes(36), hsvectors.tlsh_from_hex('TNULL'))
        with self.assertRaises(ValueError):
            hsvectors.tlsh_hex(bytes(35))

    @unittest.skipIf(np is None, 'numpy not installed')
    def test_numpy_loaders(self):
        D = hsvectors.load_tlsh_digests(self.hset_path)
        R = hsvectors.load_tlsh_record_index(self.hset_path)
        n = len(self.rows)
        self.assertEqual((n, 36), D.shape)
        self.assertFalse(D.flags.writeable)
        self.assertEqual((n,), R.shape)
        self.assertEqual(np.uint64, R.dtype)

        for r in range(n):
            self.assertEqual(self.rows[r], bytes(D[r]))

        # the same from a buffer
        with open(self.hset_path, 'rb') as f:
            buf = f.read()
        self.assertTrue(np.array_equal(D, hsvectors.load_tlsh_digests(buf)))

    @unittest.skipIf(np is None, 'numpy not installed')
    def test_tlsh_embeddings(self):
        # computed from the rows: row r is tlsh_embed of row r
        n = len(self.rows)
        X = self.hset.tlsh_embeddings(self.tidx)
        self.assertEqual((n, 264), X.shape)
        self.assertEqual(np.float32, X.dtype)
        for r in range(n):
            self.assertEqual(hasher.tlsh_embed(self.rows[r]), X[r].tolist())
        self.assertTrue(np.array_equal(X, self.hset.tlsh_embeddings()))
        self.assertTrue(np.array_equal(X, self.hset.hashset(self.tidx).tlsh_embeddings()))
        with self.assertRaises(ValueError):
            self.hset.tlsh_embeddings(0)  # the md5 hash set

        # the embedding is a lower bound on the TLSH distance within 144
        q = X[0]
        d2 = ((X - q) ** 2).sum(axis=1)
        for r in range(n):
            td = hasher.tlsh_diff(self.rows[0], self.rows[r])
            if td <= 144:
                self.assertLessEqual(d2[r], td + 1e-3)

    # bindings

    def test_open_and_count(self):
        self.assertGreaterEqual(self.tidx, 0)
        self.assertEqual(len(self.rows), self.hset.count(self.tidx))
        self.assertEqual(0, self.hset.index_for_type(hasher.MD5))
        self.assertEqual(16, len(self.hset.hash(0, 0)))
        self.assertEqual(-1, self.hset.index_for_type(hasher.SHA1))
        hs = self.hset.hashset(self.tidx)
        self.assertEqual(36, hs.hash_length())
        self.assertEqual(self.rows[0], hs.hash(0))
        self.assertIn(self.rows[5], hs)
        with self.assertRaises(IndexError):
            hs.hash(len(self.rows))

    def test_strategies(self):
        both = hasher.TLSH_KNN_BRUTE | hasher.TLSH_KNN_INDEX
        self.assertEqual(both, self.hset.tlsh_knn_strategies(self.tidx))
        self.assertEqual(both, self.hset.tlsh_knn_strategies())
        self.assertEqual(both, self.hset.hashset(self.tidx).tlsh_knn_strategies())
        self.assertEqual(0, self.hset.tlsh_knn_strategies(0))

    def test_knn_matches_brute_force(self):
        hs = self.hset.hashset(self.tidx)
        for q in self.queries:
            for include_length in (True, False):
                for k, maxd in ((10, 144), (3, 1000), (50, 60)):
                    exp = brute_knn(self.rows, q, k, maxd, include_length)
                    self.assertEqual(
                        exp, self.hset.tlsh_knn(q, k, maxd, include_length),
                        (hasher.tlsh_to_hex(q), k, maxd, include_length)
                    )
                    for strategy in (hasher.TLSH_KNN_BRUTE, hasher.TLSH_KNN_INDEX):
                        self.assertEqual(
                            exp, hs.tlsh_knn(q, k, maxd, include_length, strategy),
                            (hasher.tlsh_to_hex(q), k, maxd, include_length, strategy)
                        )

    def test_knn_has_hits(self):
        # a member is its own nearest neighbour, and its family is close
        hits = self.hset.tlsh_knn(self.rows[100], k=5)
        self.assertEqual(self.rows[100], self.hset.hash(self.tidx, hits[0][0]))
        self.assertEqual(0, hits[0][1])
        self.assertGreater(len(hits), 1)
        self.assertEqual([h[1] for h in hits], sorted(h[1] for h in hits))

    def test_knn_edge_cases(self):
        self.assertEqual([], self.hset.tlsh_knn(self.rows[0], k=0))
        self.assertEqual([], self.hset.tlsh_knn(bytes(36)))
        self.assertEqual([], self.hset.tlsh_knn(self.rows[0], tidx=0))
        self.assertEqual([], self.hset.tlsh_knn(self.rows[0], strategy=4))
        with self.assertRaises(ValueError):
            self.hset.tlsh_knn(bytes(35))

    def test_embed(self):
        v = hasher.tlsh_embed(self.rows[0])
        self.assertEqual(264, len(v))
        self.assertEqual(float(self.rows[0][0]), v[hasher.TLSH_EMBEDDING_L_DIM])
        self.assertEqual(0.0, hasher.tlsh_embed_dist2(v, v))
        w = hasher.tlsh_embed(self.rows[1])
        self.assertLessEqual(
            hasher.tlsh_embed_dist2(v, w, False),
            hasher.tlsh_diff(self.rows[0], self.rows[1], False)
        )

    def test_load_from_buffer(self):
        with open(self.hset_path, 'rb') as f:
            buf = f.read()
        with hasher.HSet.load(buf) as hset:
            self.assertEqual(len(self.rows), hset.count(hset.index_for_type(hasher.TLSH)))
            self.assertEqual(
                self.hset.tlsh_knn(self.queries[0]), hset.tlsh_knn(self.queries[0])
            )


if __name__ == "__main__":
    unittest.main()
