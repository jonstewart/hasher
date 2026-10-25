#!/usr/bin/env python3
"""header_split: split the TLSH distances of a vs_knn_eval run's results into
the header part (L, Q1, Q2) and the body + checksum part, through libhasher.

For a query digest q and a result row r (36-byte canonical rows: byte 0 is L,
byte 1 the Q1/Q2 nibbles, then the body planes and the checksum):

    header = tlsh_diff(q, r[:2] + q[2:])   L and Q terms only
    length = tlsh_diff(q, r[:1] + q[1:])   L term only
    rest   = tlsh_diff(q, q[:2] + r[2:])   body and checksum terms only
    full   = tlsh_diff(q, r)        (the CSV's full_dist)

TLSH's distance is a sum of these terms, so header + rest = full, and full
must equal the run's tlsh_dist; vs_report checks both. Rows are classified
per query: TP = an embed result with tlsh_dist <= d_k, FP = an embed result
with tlsh_dist > d_k, MISS = a brute result not among embed's results.

Run by vs_report.py as a subprocess (it needs libhasher on LD_LIBRARY_PATH
and the repo's python/ package):

    LD_LIBRARY_PATH=src/lib/.libs python3 -I bench/vs_report/header_split.py \\
        --hset vs.hset --knn KNN_DIR --out header_split.csv
"""

import argparse
import csv
import mmap
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--hset', required=True)
    ap.add_argument('--knn', required=True, help='vs_knn_eval output directory (queries.csv, results.csv)')
    ap.add_argument('--out', required=True, help='CSV to write')
    ap.add_argument('--repo', default=os.path.normpath(os.path.join(HERE, '..', '..')))
    ap.add_argument('--section', type=int, default=0, help='TLSH hash set index in the hset')
    ap.add_argument('--include-length', choices=('true', 'false'), default='true',
                    help='as the kNN run (run.json params.include_length)')
    args = ap.parse_args()
    sys.path.insert(0, os.path.join(args.repo, 'python'))
    import hasher
    from hasher import hsvectors as hv

    sec = hv.tlsh_sections(args.hset)[args.section]
    base = sec.hdat.offset + hv.CHUNK_HEADER_LENGTH
    nrows = sec.hdat.length // hv.TLSH_DIGEST_LENGTH
    W = hv.TLSH_DIGEST_LENGTH

    queries = {}
    with open(os.path.join(args.knn, 'queries.csv'), newline='') as f:
        for d in csv.DictReader(f):
            queries[(d['qset'], int(d['qid']))] = (hasher.tlsh_from_hex(d['digest']), int(d['d_k']))
    res = {}
    with open(os.path.join(args.knn, 'results.csv'), newline='') as f:
        for d in csv.DictReader(f):
            if d['method'] in ('brute', 'embed'):
                res.setdefault((d['qset'], int(d['qid'])), {'brute': [], 'embed': []})[d['method']].append(
                    (int(d['rank']), int(d['row_idx']), int(d['tlsh_dist'])))

    length = args.include_length == 'true'

    def diff(a, b, _):
        return hasher.tlsh_diff(a, b, length)
    n = 0
    with open(args.hset, 'rb') as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm, \
            open(args.out, 'w', newline='') as out:
        w = csv.writer(out)
        w.writerow(['qset', 'qid', 'cat', 'rank', 'row_idx', 'tlsh_dist', 'full_dist', 'header', 'length', 'rest'])

        def emit(key, cat, rank, row, dist, q):
            if not 0 <= row < nrows:
                sys.exit(f'header_split: row {row} out of range ({nrows} rows)')
            r = mm[base + W * row: base + W * (row + 1)]
            w.writerow([key[0], key[1], cat, rank, row, dist, diff(q, r, True),
                        diff(q, r[:2] + q[2:], True), diff(q, r[:1] + q[1:], True),
                        diff(q, q[:2] + r[2:], True)])

        for key in sorted(res):
            q, dk = queries[key]
            m = res[key]
            erows = {row for _, row, _ in m['embed']}
            for rank, row, dist in m['embed']:
                emit(key, 'TP' if dist <= dk else 'FP', rank, row, dist, q)
                n += 1
            for rank, row, dist in m['brute']:
                if row not in erows:
                    emit(key, 'MISS', rank, row, dist, q)
                    n += 1
    print(f'header_split: {n:,} rows from {len(res):,} queries to {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
