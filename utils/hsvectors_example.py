#!/usr/bin/python3

"""
Nearest neighbours and clustering over the TLSH vectors stored in an hset.

A TLSH hash set written with vectors (the default, see mkhashset) carries a
TVEC chunk: the n x 264 float32 lower-bound embedding of every digest, page
aligned so numpy can memory-map it straight out of the file. For digests a
and b with TLSH distance <= 144, ||phi(a) - phi(b)||^2 <= diff(a, b), so
small squared Euclidean distances are a sound filter for small TLSH
distances (docs/TLSH_EMBEDDING.md). Drop column 256 to ignore the length
term, as tlsh_diff(..., include_length=False) does.

Only numpy is required:

    python3 utils/hsvectors_example.py corpus.hset [ROW]

ROW is the query row (default 0). With scikit-learn installed the script also
fits sklearn.neighbors.NearestNeighbors and clusters the matrix with HDBSCAN
(the hdbscan package if present, else sklearn.cluster.HDBSCAN).

Build a small hset to try it on:

    awk '{print $1}' vendors/tlsh/Testing/exp/example_data.128.1.len.out_EXP \\
      | while read t; do echo "$(printf %s "$t" | md5sum | cut -c1-32) $t"; done > md5_tlsh.txt
    src/mkhashset/mkhashset 'example' 'tlsh reference digests' md5 tlsh true true \\
      md5_tlsh.txt example.hset
"""

import os
import sys
import warnings

try:
    from hasher import hsvectors
except ImportError:
    # libhasher is not installed; hsvectors.py itself needs only Python
    import importlib.util
    _path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         '..', 'python', 'hasher', 'hsvectors.py')
    _spec = importlib.util.spec_from_file_location('hsvectors', _path)
    hsvectors = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(hsvectors)


def knn_numpy(X, q, k):
    """Exact kNN by brute force: squared Euclidean distance of every row to
    q, k smallest first (ties by row index)."""
    import numpy as np
    d = X - q
    d2 = np.einsum('ij,ij->i', d, d)
    order = np.lexsort((np.arange(len(d2)), d2))[:k]
    return list(zip(order.tolist(), d2[order].tolist()))


def main(path, row=0, k=10):
    try:
        import numpy as np
    except ImportError:
        sys.exit('numpy is required: pip install numpy')

    X = hsvectors.load_tlsh_vectors(path)
    D = hsvectors.load_tlsh_digests(path)
    print(f'{path}: vectors {X.shape} {X.dtype}, digests {D.shape} {D.dtype}')
    ridx = hsvectors.load_tlsh_record_index(path)
    if ridx is not None:
        print(f'record index: {ridx.shape} {ridx.dtype}')

    n = X.shape[0]
    if not 0 <= row < n:
        sys.exit(f'row {row} out of range [0, {n})')

    # (a) exact kNN for one row with numpy
    print(f'\nquery row {row}: {hsvectors.tlsh_hex(bytes(D[row]))}')
    print(f'{k} nearest rows by squared Euclidean distance (a lower bound on the TLSH distance):')
    for i, d2 in knn_numpy(X, X[row], k):
        print(f'  {i:>8}  {d2:8.2f}  {hsvectors.tlsh_hex(bytes(D[i]))}')

    # (b) scikit-learn and HDBSCAN, when available
    try:
        from sklearn.neighbors import NearestNeighbors
    except ImportError:
        print('\nscikit-learn not installed (pip install scikit-learn); skipping NearestNeighbors')
    else:
        nn = NearestNeighbors(n_neighbors=min(k, n)).fit(X)
        dist, idx = nn.kneighbors(X[row:row + 1])
        print(f'\nsklearn NearestNeighbors for row {row}: '
              f'{[(int(i), round(float(d) ** 2, 2)) for i, d in zip(idx[0], dist[0])]}')

    HDBSCAN = None
    try:
        from hdbscan import HDBSCAN
    except ImportError:
        try:
            from sklearn.cluster import HDBSCAN
        except ImportError:
            pass
    if HDBSCAN is None:
        print('\nneither hdbscan nor scikit-learn >= 1.3 installed '
              '(pip install hdbscan or scikit-learn); skipping clustering')
    else:
        min_cluster_size = max(2, min(5, n // 10 or 2))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', FutureWarning)
            labels = HDBSCAN(min_cluster_size=min_cluster_size).fit(X).labels_
        clusters = sorted(set(labels.tolist()) - {-1})
        noise = int((labels == -1).sum())
        print(f'\nHDBSCAN (min_cluster_size={min_cluster_size}): '
              f'{len(clusters)} clusters, {noise} noise rows of {n}')
        for c in clusters[:10]:
            members = np.flatnonzero(labels == c)
            print(f'  cluster {c}: {len(members)} rows, e.g. {members[:5].tolist()}')


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) == 3 else 0)
