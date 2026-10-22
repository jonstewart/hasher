# TLSH lower-bound embedding and similarity sections

This document completes the "TLSH Similarity Sections" spec for libhasher's
hset format: it defines the derived Euclidean embedding (the spec's pending
section 8), the `TVEC` vectors section and the `TIVF` index section, and the
indexed kNN procedure. Sections 1–7 of the spec (canonical digest, exact
distance, cell index, record map) are implemented as described in
`HASHSET_FORMAT` and `include/hasher/tlsh.h`, with two adaptations:

* the 36-byte row is laid out so that bytewise order equals canonical order
  (L, Q1, Q2, body, checksum), so the existing sort/search machinery applies;
* duplicate digests are duplicate rows, each mapped to its record through the
  existing `RIDX` chunk, which plays the role of `TLSH_RECORD_MAP`.

## 1. The embedding

Write `diff(a, b)` for the reference TLSH distance with length included. The
embedding `phi(d)` maps a digest to 264 float32 coordinates such that

    || phi(a) - phi(b) ||^2  <=  diff(a, b)      whenever diff(a, b) <= 144.

Each TLSH cost term is bounded separately by one block of coordinates, and
the blocks are orthogonal, so the squared Euclidean distance is the sum of
the per-term bounds.

### Body (dims 0–255)

Bucket `i` occupies dims `2i, 2i+1`. The four codes map to the corners of a
staircase:

| code | point    |
|------|----------|
| 0    | ( 1, 0)  |
| 1    | ( 0, 0)  |
| 2    | ( 0, 1)  |
| 3    | (-1, 1)  |

Squared distances: adjacent codes 1, two apart 2, and (0, 3) 5, against TLSH
costs 1, 1, 1, 2, 2, 6. This is the tightest possible planar placement:
d(0,3) cannot exceed (1 + sqrt 2)^2 ≈ 5.83 by the triangle inequality through
code 2 while d(1,3) ≤ 2 is required, and 5 is the largest value realizable
with the adjacent distances exactly 1. All coordinates are in {-1, 0, 1}, so
the body contributes integer distances and can be evaluated with popcounts:

    X = lo_a ^ lo_b,  Y = hi_a ^ hi_b,  S = ~(lo_a ^ hi_a)
    body_emb2 = popcount(X ^ Y) + popcount(Y) + 4 popcount(X & Y & S)

(the exact TLSH body is the same expression with 5 in place of 4).

### Length (dim 256)

`phi_L = L` as a float. For a difference `k = |L_a - L_b|` the squared distance
is `k^2`, and TLSH charges 0, 1, 12k for k = 0, 1, ≥2. `k^2 <= 12k` exactly for
`k <= 12`, and `k = 12` is also where the L term alone reaches 144. This is the
best possible: a chain of unit steps forces any Euclidean realization to have
`d(k)^2 <= k^2`, so the linear map is optimal for every pair that matters.

Two caveats. First, pairs with `diff > 144` have no guarantee (and do not need
one: TLSH scores above ~100 carry no similarity information). Second, the L
term in TLSH is a difference mod 256 while the embedding is linear; they
disagree only when one input is in the terabyte range (L ≥ 244) and the other
is tiny. Such pairs are not guaranteed.

### Quartile ratios (dims 257–260)

Q1 and Q2 are circular (mod 16), so each is placed on a regular 16-gon of
radius `R = 1 / (2 sin(pi/16)) ≈ 2.5629`, chosen so that adjacent values are
exactly distance 1 apart (TLSH cost 1). For a circular difference k the
squared chord is `sin^2(pi k/16) / sin^2(pi/16)`:

| k        | 1 | 2    | 3    | 4     | 5     | 6     | 7     | 8     |
|----------|---|------|------|-------|-------|-------|-------|-------|
| chord^2  | 1 | 3.85 | 8.11 | 13.14 | 18.16 | 22.43 | 25.27 | 26.27 |
| TLSH     | 1 | 12   | 24   | 36    | 48    | 60    | 72    | 84    |

### Checksum (dims 261–263)

Bits 0–2 of the checksum, each scaled by `1/sqrt 3`. A differing checksum
costs 1 in TLSH; the embedding contributes `(number of differing low bits)/3
<= 1`, and 0 when the checksums are equal.

### Distance without length

For `include_length = false` the distance is computed over all dims except
256. With the L term gone there is no 144 cap: the bound holds for every pair.

### Tightness

On near pairs from the synthetic family corpus the squared embedding distance
averages about 0.78 of the TLSH distance (see `test/test_tlsh_embedding.cpp`).

## 2. Section TVEC (vectors)

Optional, one per TLSH hash set, following that set's `HDAT`/`RIDX`. Like
every section it is an hset chunk: a 4-byte type `"TVEC"` (0x54564543), a
little-endian u64 payload length, then the payload below. It may only follow
a TLSH hash set; readers reject it elsewhere. Payload:

| offset | type | field    | meaning                                  |
|--------|------|----------|------------------------------------------|
| 0      | u16  | version  | 1                                        |
| 2      | u8   | variant  | 0 (128 buckets, 1-byte checksum)         |
| 3      | u8   | flags    | 0                                        |
| 4      | u32  | dims     | 264                                      |
| 8      | u64  | n        | row count, equals the HDAT hash count    |
| 16     | u32  | dtype    | 1 = float32, little-endian               |
| 20     | u32  | reserved | 0                                        |
| 24     | u64  | reserved | 0                                        |
| 32     | f32  | data     | n × dims, row-major, row r is phi(HDAT row r) |

The chunk is positioned so that `data` begins on a 4096-byte boundary in the
file; `offset(TVEC chunk) + 12 + 32` is page aligned, with zero padding
inserted before the chunk as needed. A consumer can therefore memory-map the
file and hand `numpy.memmap(path, np.float32, offset=..., shape=(n, 264))`
or a `float*` straight to faiss, hnswlib, scikit-learn, HDBSCAN, UMAP, etc.
In C, `sfhash_hashset_tlsh_vectors` returns the pointer.

The writer emits `TVEC` by default for TLSH fields; see
`sfhash_hashset_builder_set_tlsh_options` (`SFHASH_HSET_TLSH_VECTORS`).

## 3. Section TIVF (inverted-file index)

Optional, following `TVEC` (or `HDAT`/`RIDX` when no vectors are stored; the
index does not need the vectors, it embeds digests on the fly). The chunk type
is `"TIVF"` (0x54495646), framed like `TVEC`, and likewise only valid after a
TLSH hash set.

Lists are grouped by header cell, the same (L, Q1, Q2) cells the 0x7400
`HINT` indexes, so the header part of the TLSH distance is exact for every
list and the embedding only has to bound the body. Each cell is split by
k-means over the 256-dim body embedding into about
`ceil(cell_size / target_list_size)` lists (the writer uses a target of 32).
Every list keeps a *medoid*, the member digest nearest the k-means centroid,
and the squared body-embedding radius about it; both are exact integers, and
the bound for a list costs one popcount kernel evaluation.

| offset | type        | field       | meaning                                                   |
|--------|-------------|-------------|-----------------------------------------------------------|
| 0      | u16         | version     | 3                                                         |
| 2      | u16         | flags       | 0                                                         |
| 4      | u32         | dims        | 256                                                       |
| 8      | u32         | lists       | C                                                         |
| 12     | u32         | reserved    | 0                                                         |
| 16     | u64         | n           | row count, equals the HDAT hash count                     |
| 24     | u64         | reserved    | 0                                                         |
| 32     | u32[65537]  | cell_lists  | lists of cell c are [cell_lists[c], cell_lists[c+1])      |
|        | row[C]      | medoids     | one 36-byte canonical digest per list, a member of it     |
|        | u32[C]      | radius2     | max `emb_body2(medoid, member)` over the list             |
|        | u64[C+1]    | list_start  | CSR offsets into ids                                      |
|        | u32[n]      | ids         | HDAT row indexes, ascending within each list              |

`emb_body2(a, b)` is the squared distance between body embeddings,
`popcount(X ^ Y) + popcount(Y) + 4 popcount(X & Y & S)` (section 1). Only the
header, the lengths and the cell/list offsets are validated at load time.

The writer emits `TIVF` by default for TLSH fields
(`SFHASH_HSET_TLSH_INDEX`). `sfhash_hashset_tlsh_knn` uses it when present
and falls back to brute force otherwise; `sfhash_hashset_tlsh_knn_strategies`
reports which is available and `sfhash_hashset_tlsh_knn_with` picks one.

### Merging indexes

Set operations on whole files (`sfhash_hashset_merge`, the builder-shaped
`sfhash_hashset_builder_*_open`, the `hsetop` tool; see HASHSET_FORMAT "Set
operations") do not rebuild the index. The rows of the two inputs are merged
by a two-pointer pass that yields, per input, a map old row -> new row (or
dropped), and `merge_tlsh_ivf` carries the lists through it in three steps
per cell:

1. *Concatenate.* The left input's lists then the right's, ids remapped,
   dropped ids removed, lists that end up empty omitted. Medoids are kept. A
   list that lost members (intersection, difference, or a duplicate row
   collapsed by a union) gets its `radius2` recomputed exactly over the
   remaining members; the others keep theirs. The medoid need not itself be
   a member: the search only needs every member within `radius2` of it, and
   the format allows any digest with that property.
2. *Coalesce*, with threshold C (`coalesce_threshold`; the default is
   2T = 64, where T = `TLSH_IVF_TARGET_LIST_SIZE` = 32 is the k-means target
   of a fresh build). While the cell has two lists of fewer than C/2 members
   each, the pair whose union has the smallest radius is replaced by one
   list: its medoid is whichever of the two medoids gives the smaller
   maximum distance over the union (both computed exactly with the kernel),
   `radius2` that maximum, ids the sorted union (both ascending, a linear
   merge). Only lists below C/2 are candidates, so any pair sums to below C,
   and the loop stops when at most one such list is left. C = 0 disables
   this step.
3. *Emit* the cell's lists in order.

Step 1 is O(lists + ids); step 2 costs, in a cell with s lists below C/2,
s × (rows in those lists) kernel evaluations and O(s² log s) bookkeeping (a
heap of candidate pairs with lazy invalidation), and in practice s is a
handful. No embedding and no k-means are involved, and the result searches
exactly like a fresh index. When one input has no `TIVF` and the output
wants one, the merge builds it from scratch instead.

### Incremental merge: bounds

Notation: T is the target list size of a fresh `build_tlsh_ivf` (32), C the
coalescing threshold, m the rows of a cell and L the lists of that cell in
the merged index. "Fresh" means `build_tlsh_ivf` over the same rows.

**Invariant.** After `merge_tlsh_ivf` with C > 0, at most one list per cell
has fewer than C/2 members. *Proof.* Step 2 loops while two such lists
exist, and a list leaves the candidate set exactly when a coalescing brings
it to C/2 or more; it terminates because every iteration removes one list.
The invariant is established by the merge for any inputs, whether or not
they satisfy it (a fresh k-means build need not, its list sizes are whatever
the clustering gives), so it holds for every merged index.
`tlsh_ivf_check_invariant` tests it. ∎

**Lists per cell.** Under the invariant all lists but at most one have at
least C/2 members (C even; ⌊C/2⌋ in general), so (L − 1) · C/2 ≤ m, i.e.

  L ≤ 2m/C + 1.

A fresh build splits the cell into k = ⌈m/T⌉ clusters and emits the nonempty
ones, so it has at most ⌈m/T⌉ lists; it may have fewer. With C = 2T the
bound reads L ≤ m/T + 1 ≤ ⌈m/T⌉ + 1: **a merged index has at most one list
more per nonempty cell than a fresh build over the same rows**, after any
number of incremental merges, in any order. (Cells with no rows have no
lists in either.) With C = T the bound is L ≤ 2m/T + 1, up to twice the
lists of a fresh build plus one; with C = 0 there is no bound, lists only
accumulate.

**Storage.** A `TIVF` holds 36 bytes of medoid, 4 of `radius2` and 8 of
`list_start` per list, 48 bytes; everything else (header, `cell_lists`,
`ids`) depends only on n. With C = 2T, therefore,

  bytes(merged) − bytes(fresh) ≤ 48 B × (nonempty cells) ≤ 48 B × 65536 = 3 MiB,

independent of n and of the number of merges.

**Query cost.** The search (section 4) evaluates one list bound, a single
kernel evaluation `emb_body2(q, medoid)`, per list of every visited cell and
then scans the lists that pass. The cells visited depend only on q, tau and
the rows, so with C = 2T the merged index costs **at most one bound
evaluation more per visited cell** than a fresh index over the same rows.
The rows scanned have no formal bound: a coalesced list has the radius of a
pair that k-means might have kept apart, so its bound can be looser than a
fresh list's and more of its rows may be scanned. This is what the
incremental-merge measurements of section 5 quantify.

**Exactness.** Unaffected. Every member of every list lies within `radius2`
of its medoid (recomputed exactly for shrunk and coalesced lists, unchanged
for the rest), which is all section 4 needs; the indexed search over a
merged index returns exactly what brute force does, for any max_distance,
with or without the length. (The radii of a merged index are in fact tight:
a fresh build computes them exactly, and every list a merge changes gets an
exact recomputation.)

## 4. Indexed kNN (exact for every distance)

Given query digest q, k and max_distance T:

1. Build the header cost tables for q: `l_cost[L]` (0 when the length is
   excluded) and `q_cost[Q]` over the 256 Q bytes, each enumerated in
   nondecreasing cost (`TlshHeaderOrder`; the order is a translation of a
   static table, no sorting at query time). Let `tau = T` be the largest
   useful distance; it shrinks to the k-th best distance once k hits exist.
2. Visit L values in cost order and, for each, Q bytes in cost order, stopping
   a loop as soon as `ch = l_cost + q_cost` exceeds `tau`. For a cell with one
   list, scan the cell's contiguous rows directly. Otherwise compute for each
   list the body bound `b = max(0, sqrt(emb_body2(q, medoid)) - sqrt(radius2))^2`
   and scan the lists with `ch + b <= tau` in increasing `b`.
3. Scanning a row costs a checksum compare and one body kernel evaluation;
   hits go into a bounded max-heap ordered by (distance, index).

Correctness: a row r in list l satisfies
`sqrt(emb_body2(q, r)) >= sqrt(emb_body2(q, medoid)) - sqrt(radius2)` by the
triangle inequality in embedding space, and `emb_body2(q, r) <= body(q, r)`
for every pair (per bucket 1, 1, 1, 2, 2, 5 against 1, 1, 1, 2, 2, 6). Since the
header cost of every row in the cell is exactly `ch` (plus the 0/1 checksum
term), every row with `diff(q, r) <= tau` lies in a cell with `ch <= tau` and a
list with `ch + b <= tau`. No approximation is involved, so the indexed search
returns exactly what brute force does, for any T, with or without the length.
The 144 cap of section 1 only concerns the L coordinate of the full
embedding, which the index never uses: within a cell L is constant.

## 5. Measurements

See `test/bench_tlsh.cpp` (Catch2) and `rust/tlsh-bench` (Criterion). On an
Apple M-series core with a synthetic family corpus (k = 10, T = 144):

| rows      | reference brute | kernel brute | cell index | IVF (this section) | IVF build |
|-----------|-----------------|--------------|------------|--------------------|-----------|
| 10,000    | 95 us           | 7.0 us       | 3.4 us     | 4.5 us             | 2 ms      |
| 100,000   | 941 us          | 57 us        | 6.8 us     | 8.9 us             | 17 ms     |
| 1,000,000 | 9.5 ms          | 566 us       | 16 us      | 8.3 us             | 1.4 s     |

Per query. "Reference brute" is `Tlsh::totalDiff` over every row; "kernel
brute" is the popcount kernel over every row (about 0.55 ns/row). At 1M rows
the IVF scans about 4,800 rows per query against 18,900 for the cell index
and 1,000,000 for brute force. The Criterion suite (`rust/tlsh-bench`, see its
README) measures the same strategies through the C API over an hset file and
reports the index at 17 us/query at 1M rows against 560 us (kernel brute) and
3.0 ms (one `sfhash_tlsh_diff` FFI call per row).

The optimization rounds, in order of payoff: grouping IVF lists by header
cell instead of by L (exact header pruning, linear build); medoid digests
with integer radii instead of float centroids (list bound = one kernel call);
the NEON body kernel with per-query planes (3x on the scan); list size 32;
parallel per-cell build; contiguous scans for single-list cells; a single
compare per scanned row and prefetch for indirect list scans. Beyond this the
query is dominated by scanning a few thousand rows at ~0.5 ns each plus a few
hundred list bounds; the remaining lever is tighter lists at the cost of
build time and index size.

## 6. Using the vectors from Python

`hasher.hsvectors` (`python/hasher/hsvectors.py`) walks the chunks of an hset
in pure Python, with no dependency on libhasher, and hands the `TVEC` matrix
to numpy as a read-only memory map of the file:

```python
from hasher import hsvectors
X = hsvectors.load_tlsh_vectors('corpus.hset')   # (n, 264) float32 memmap
D = hsvectors.load_tlsh_digests('corpus.hset')   # (n, 36) uint8, row r <-> X[r]
R = hsvectors.load_tlsh_record_index('corpus.hset')  # (n,) uint64 RIDX, or None
```

`X` can go straight into numpy, scikit-learn, faiss, HDBSCAN or UMAP; drop
column 256 (`hasher.TLSH_EMBEDDING_L_DIM`, the length coordinate) for the
`include_length = false` distance. `hsvectors.tlsh_hex(bytes(D[r]))`
renders a row as `"T1..."`, `hsvectors.read_toc(path)` lists every chunk,
and `utils/hschunks.py` prints that table. `utils/hsvectors_example.py` runs
brute-force kNN, `NearestNeighbors` and HDBSCAN over a file.

The C library's view of the same data is `HSet.tlsh_vectors()` in the ctypes
bindings, next to `HSet.tlsh_knn(digest, k, max_distance, include_length,
strategy)`, the exact kNN of section 4:

```python
import hasher
with hasher.HSet.open('corpus.hset') as hset:
    tidx = hset.index_for_type(hasher.TLSH)
    for row, dist in hset.tlsh_knn(hasher.tlsh_from_hex('T1...'), k=5):
        print(dist, hasher.tlsh_to_hex(hset.hash(tidx, row)))
```
