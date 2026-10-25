# TLSH lower-bound embedding and similarity sections

This document completes the "TLSH Similarity Sections" spec for libhasher's
hset format: it defines the derived Euclidean embedding (the spec's pending
section 8), the `TIVF` index section, and the indexed kNN procedure. The
embedding itself is not stored in the file (section 2). Sections 1–7 of the spec (canonical digest, exact
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

## 2. The embedding is computed, not stored

An earlier version of the format had an optional `TVEC` chunk
(0x54564543) after a TLSH hash set's `HDAT`/`RIDX`: a 32-byte header and the
n × 264 float32 matrix of `phi(HDAT row r)`, page aligned in the file so
that it could be memory-mapped and handed to numpy or faiss. It was removed
before TLSH support was released (docs/DESIGN_DECISIONS.md, "No stored TLSH
embedding"): it cost 1,056 bytes per row on disk, about four fifths of a
TLSH-heavy file (9.3 GiB of the 11.7 GiB VirusShare hset), for data any
consumer can compute from the rows, and nothing in the library reads it:
the `TIVF` search embeds digests as it goes. No writer emits `TVEC`, and a
reader rejects a file that has one, as any chunk the format does not allow.
Bit 1 of the TLSH options, which selected it, is reserved and ignored.

To get the embedding, compute it from the rows: `sfhash_tlsh_embed` in C
(`include/hasher/tlsh.h`) for one digest and `sfhash_tlsh_embed_n` for n
contiguous digests (a hash set's rows), `hasher.tlsh_embed` in Python,
and `HSet.tlsh_embeddings()` for the whole n × 264 matrix of a TLSH hash
set (section 6). On one core of a Xeon E5645 `sfhash_tlsh_embed` takes
0.56–0.63 µs per digest (1,000,000 random digests, three runs), so the
9.4 million rows of the VirusShare hset embed in about 6 s on one core;
`bench/vs_knn_eval` does that, on all CPUs, before its timed passes.

## 3. Section TIVF (inverted-file index)

Optional, one per TLSH hash set, following that set's `HDAT`/`RIDX`; the
index embeds digests on the fly. Like every section it is an hset chunk: a
4-byte type `"TIVF"` (0x54495646), a little-endian u64 payload length, then
the payload; it may only follow a TLSH hash set, and readers reject it
elsewhere.

Lists are grouped by header cell, the same (L, Q1, Q2) cells the 0x7400
`HINT` indexes, so the header part of the TLSH distance is exact for every
list and the embedding only has to bound the body. Each cell is split into
lists of about T = `target_list_size` rows (the writer uses T = 32) by
clustering over the 256-dim body embedding. Every list keeps a *medoid* and
the squared body-embedding radius about it; both are exact integers, and the
bound for a list costs one popcount kernel evaluation. How a cell is
partitioned is a quality knob only (rows scanned per query, build time):
the search is exact for any partition in which every member lies within
its list's `radius2` of the medoid.

The default build (`TlshIvfBuild::BISECT`) uses integer arithmetic only:

- *Coarse bisection.* A node (initially the whole cell) of more than
  `TLSH_IVF_BISECT_FLAT_MAX` = 4096 rows is split in two around two
  far-apart member pivots: A, the member farthest from a random member, and
  B, the member farthest from A; each member goes to the nearer pivot (ties
  to A). If one side would get fewer than 1/8 of the rows, the node is
  sorted by (distance to A, row) and cut at the median instead, so every
  split makes progress (a node of identical bodies included). O(m) kernel
  calls per level.
- *Flat k-means.* Each node of s ≤ 4096 rows is clustered into at most
  ⌈s/T⌉ lists by k-means over exact integer centroids: a centroid is the
  int32 coordinate sum S and count n of its members' {-1, 0, 1} body
  embeddings, the squared distance of a row x to it is the rational
  ‖n x − S‖² / n², and two such distances are compared exactly by
  cross-multiplying in 64 bits (`tlsh_ivf_nearer`; a static_assert on
  FLAT_MAX rules out overflow). Seeding is k-means++ with the integer
  kernel, then at most 10 rounds of update and reassignment (ties to the
  smaller centroid index); empty centroids are dropped. A node with fewer
  distinct bodies than ⌈s/T⌉ gets fewer lists, so a node of identical
  bodies is one list.
- *Medoid.* Each list's medoid is its exact 1-center, the member whose
  maximum distance to the other members is smallest, which minimizes
  `radius2` among members.
- *No coalescing.* The lists are exactly the nonempty k-means groups of
  the flat nodes; small lists are not coalesced (only a merge coalesces,
  below), so a fresh index need not satisfy `tlsh_ivf_check_invariant`.
  Coalescing at C = T in the fresh build was tried and rejected: at 4M
  rows it paired unrelated small families into wide lists (76,993 lists
  and 7,501 rows scanned per query against 129,948 and 4,752 without it)
  and cost time quadratic in a cell's small lists.
- *Order.* A cell's lists are emitted in depth-first order of the
  bisection, ids ascending within a list, so the lists of one subtree are contiguous; a later TIVF
  version could add per-subtree bounds without re-clustering.

The clustering work is O(m log m) kernel calls for the splits and ⌈s/T⌉
256-coordinate dot products per row and round in a flat node of s rows;
cells are clustered in parallel, and the result does not depend on the
thread count. The cost per row therefore grows with the cell size until
the cells exceed FLAT_MAX (at most 128 centroids at T = 32), and is
constant after that. On the synthetic corpus, whose ~9,000-9,600 cells
fill linearly with n, the row-weighted mean of min(⌈m/T⌉, 128) is 21.2,
39.8 and 63.5 at 1M, 2M and 4M rows, and the build took 136, 437 and
1,264 ms (3.2x and 2.9x per doubling; KMEANS: 1,481 ms and 25.7 s at 1M
and 4M); section 5.

**Reproducibility.** There is no floating point in the default build;
integer sums do not depend on evaluation order, and every random draw is
`rng() % n` straight from `std::mt19937_64` (whose sequence the C++
standard specifies), never a standard-library distribution. For the same
rows the `TIVF` bytes are therefore meant to be identical on every
platform, compiler and standard library. `test/test_tlsh_ivf_golden.cpp`
checks the SHA-256 of the serialized index of two integer-generated corpora
against recorded values (a mismatch is a reproducibility bug, not a
constant to update), and `utils/hschunks.py` prints each chunk's payload
SHA-256, so two hset files built from the same rows on different machines
can be compared chunk by chunk (whole-file hashes differ by the FHDR
timestamp).

The alternative, `TlshIvfBuild::KMEANS` (`SFHASH_HSET_TLSH_INDEX_KMEANS`),
runs k-means++ and Lloyd iterations in float over each whole cell with
k = ⌈m/T⌉ and takes as medoid the member nearest each centroid; it costs
Θ(m²/T) per cell of m rows, and its bytes depend on the platform's float
arithmetic (its search results do not).

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
   2T = 64, where T = `TLSH_IVF_TARGET_LIST_SIZE` = 32 is the target list
   size of a fresh build). While the cell has two lists of fewer than C/2 members
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
handful. No embedding and no clustering are involved, and the result searches
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
they satisfy it (a fresh build need not, with either method: its list
sizes are whatever the clustering gives), so it holds for every merged
index.
`tlsh_ivf_check_invariant` tests it. ∎

**Lists per cell.** Under the invariant all lists but at most one have at
least C/2 members (C even; ⌊C/2⌋ in general), so (L − 1) · C/2 ≤ m, i.e.

  L ≤ 2m/C + 1.

A fresh KMEANS build splits the cell into k = ⌈m/T⌉ clusters and emits the
nonempty ones, so it has at most ⌈m/T⌉ lists; it may have fewer. (A fresh
BISECT build emits the nonempty groups of ⌈s/T⌉ centroids per flat node,
so at most ⌈m/T⌉ lists in a cell of at most FLAT_MAX rows and at most
Σ ⌈s_i/T⌉, a few more than ⌈m/T⌉, above it; in practice as many as
KMEANS, 36,823 against 36,820 at 1M rows and 129,948 against 129,872 at
4M.) With C = 2T the bound reads L ≤ m/T + 1 ≤ ⌈m/T⌉ + 1:
**a merged index has at most one list more per nonempty cell than ⌈m/T⌉,
the most lists a fresh KMEANS build of the same rows has**, after any
number of incremental merges, in any order. (Cells with no rows have no
lists in either.) With C = T the bound is L ≤ 2m/T + 1, up to twice the
lists of a fresh build plus one; with C = 0 there is no bound, lists only
accumulate.

**Storage.** A `TIVF` holds 36 bytes of medoid, 4 of `radius2` and 8 of
`list_start` per list, 48 bytes; everything else (header, `cell_lists`,
`ids`) depends only on n. With C = 2T, therefore,

  bytes(merged) − bytes(⌈m/T⌉ lists per cell) ≤ 48 B × (nonempty cells) ≤ 48 B × 65536 = 3 MiB,

independent of n and of the number of merges.

**Query cost.** The search (section 4) evaluates one list bound, a single
kernel evaluation `emb_body2(q, medoid)`, per list of every visited cell and
then scans the lists that pass. The cells visited depend only on q, tau and
the rows, so with C = 2T the merged index costs **at most one bound
evaluation more per visited cell** than an index of ⌈m/T⌉ lists per cell
over the same rows.
The rows scanned have no formal bound: a coalesced list has the radius of a
pair that the clustering might have kept apart, so its bound can be looser than a
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
Apple M-series core with a synthetic family corpus (k = 10, T = 144), with
the float KMEANS index build (the default until 2026-10-23):

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

With the default BISECT build (`TLSH_BENCH_BUILD`, 2026-10-23, M5 Pro,
second round, after the fresh build stopped coalescing; a quieter machine
than the first round's but short of memory; `docs/BENCHMARKS.md` §9 has
all of it):

| rows      | method | IVF build | lists   | bounds/query | rows scanned/query | IVF query |
|-----------|--------|-----------|---------|--------------|--------------------|-----------|
| 1,000,000 | BISECT | 136 ms    | 36,823  | 618          | 4,659              | 8.3 us    |
| 1,000,000 | KMEANS | 1,481 ms  | 36,820  | 618          | 4,848              | 8.4 us    |
| 2,000,000 | BISECT | 437 ms    | 67,728  | 866          | 4,557              | 10.1 us   |
| 4,000,000 | BISECT | 1,264 ms  | 129,948 | 1,464        | 4,752              | 14.2 us   |
| 4,000,000 | KMEANS | 25,743 ms | 129,872 | 1,463        | 4,631              | 11.9 us   |

The integer build has k-means' lists at every size and scans 4% fewer
rows at 1M and 2.6% more at 4M, at a tenth to a twentieth of the build
time. Its 4M query time came out 13.5-14.2 us against 11.9 us in the
summary's minimum and 11.3-11.5 against 11.0 us in Catch2's mean, so the
gap is mostly noise. The first BISECT round coalesced small lists in the
fresh build and had 31,668 / 76,993 lists and 5,110 / 7,501 rows scanned
at 1M / 4M; that was rejected (section 3). The intermediate designs (pure
bisection: 13,533 rows scanned at 1M; flat k-medoids: 11,627) and the
BISECT T sweep (T = 16 and 32 within 4%) are in `docs/BENCHMARKS.md` §9.
Through the C API (Criterion, BISECT) the index answers in 17.6 us at 1M
rows and the 1M-row hset builds in 0.43 s instead of 1.45 s.

### Incremental merge

`test/bench_hset_merge` (Catch2; `MERGE_BENCH_N`, `MERGE_BENCH_T`,
`MERGE_BENCH_C`, `MERGE_BENCH_BUILD=bisect|kmeans`) measures the "Incremental merge" scheme of section 3
against a from-scratch rebuild, and `rust/tlsh-bench` (`cargo bench --
hset_incremental_merge`) the default configuration through the C API. The
scenario is VirusShare's rate of ~5 samples/s: a master of N rows absorbs
either 24 hourly batches of 18,000 rows or 7 daily batches of 432,000 rows
by successive unions (`sfhash_hashset_merge`, index carried through and
coalesced). Each batch is half new families from the corpus generator and
half digest-space perturbations of master rows (near-duplicates). Files are
hashsets-only with the index (and, while the format still had it, without
the TVEC matrix of section 2, whose 1 KiB per row of plain I/O would have
hidden the index cost in the merge and the build). The master and the
batches are built with the target list size T under test; C is the
coalescing threshold. "Rebuild" is one from-scratch build of the final rows
through the builder (sort, dedup, parallel index build, file write); the merge is
single-threaded. Queries: k = 10, max_distance = 144, 50 fixed queries, time
per query and rows scanned per query on the merged and on the rebuilt index.
The lists bound of section 3 (merged ≤ rebuilt + nonempty cells) held in
every configuration with C ≥ 2T, as proven, and in all but one of the C = T
runs, where it is not implied (N = 100,000, T = 16); TIVF sizes are the
payloads.

The tables below were measured with the KMEANS build. Apple M5 Pro (15
cores, 48 GiB), N = 1,000,000, 8.5 minutes for the whole sweep. Hourly: 24 × 18,000 rows, final set 1,431,931 rows, 9,704 nonempty
cells.

| T  | C   | 24 merges | rebuild | TIVF merged | TIVF rebuilt | lists merged | lists rebuilt | kNN merged | kNN rebuilt | rows/q merged | rows/q rebuilt |
|----|-----|-----------|---------|-------------|--------------|--------------|---------------|------------|-------------|---------------|----------------|
| 16 | 0   | 1144 ms   | 5288 ms | 14.0 MiB    | 10.0 MiB     | 181,740      | 94,484        | 55.4 us    | 44.7 us     | 13,269        | 10,668         |
| 16 | 16  | 1091 ms   | 5317 ms | 9.8 MiB     | 10.0 MiB     | 88,760       | 94,484        | 41.5 us    | 42.3 us     | 14,666        | 10,668         |
| 16 | 32  | 1115 ms   | 5336 ms | 8.5 MiB     | 10.0 MiB     | 61,065       | 94,484        | 32.0 us    | 41.8 us     | 15,250        | 10,668         |
| 16 | 64  | 1155 ms   | 5352 ms | 7.7 MiB     | 10.0 MiB     | 43,366       | 94,484        | 29.6 us    | 41.6 us     | 16,397        | 10,668         |
| 32 | 0   | 1114 ms   | 3303 ms | 12.4 MiB    | 8.0 MiB      | 146,237      | 50,378        | 43.5 us    | 28.2 us     | 15,148        | 12,586         |
| 32 | 32  | 1070 ms   | 3319 ms | 8.2 MiB     | 8.0 MiB      | 54,526       | 50,378        | 30.9 us    | 26.4 us     | 15,953        | 12,586         |
| **32** | **64** | **1048 ms** | **3318 ms** | **7.6 MiB** | **8.0 MiB** | **40,197** | **50,378** | **29.2 us** | **26.7 us** | **16,916** | **12,586** |
| 32 | 128 | 1047 ms   | 3313 ms | 6.9 MiB     | 8.0 MiB      | 25,196       | 50,378        | 34.0 us    | 26.5 us     | 23,290        | 12,586         |
| 64 | 0   | 1102 ms   | 1469 ms | 11.7 MiB    | 7.0 MiB      | 130,035      | 28,642        | 41.6 us    | 24.6 us     | 19,282        | 15,831         |
| 64 | 64  | 1034 ms   | 1466 ms | 7.3 MiB     | 7.0 MiB      | 34,041       | 28,642        | 31.3 us    | 24.6 us     | 20,102        | 15,831         |
| 64 | 128 | 1032 ms   | 1894 ms | 6.8 MiB     | 7.0 MiB      | 24,039       | 28,642        | 34.2 us    | 24.6 us     | 23,867        | 15,831         |
| 64 | 256 | 1008 ms   | 1465 ms | 6.5 MiB     | 7.0 MiB      | 16,569       | 28,642        | 35.1 us    | 24.4 us     | 26,889        | 15,831         |

Daily: 7 × 432,000 rows, final set 4,023,698 rows, 10,384 nonempty cells.

| T  | C   | 7 merges | rebuild  | TIVF merged | TIVF rebuilt | lists merged | lists rebuilt | kNN merged | kNN rebuilt | rows/q merged | rows/q rebuilt |
|----|-----|----------|----------|-------------|--------------|--------------|---------------|------------|-------------|---------------|----------------|
| 16 | 0   | 815 ms   | 48.5 s   | 29.0 MiB    | 27.3 MiB     | 291,890      | 256,456       | 155.9 us   | 89.1 us     | 38,110        | 18,909         |
| 16 | 16  | 857 ms   | 48.1 s   | 26.2 MiB    | 27.3 MiB     | 231,366      | 256,456       | 147.5 us   | 89.9 us     | 40,605        | 18,909         |
| 16 | 32  | 890 ms   | 47.8 s   | 23.3 MiB    | 27.3 MiB     | 168,000      | 256,456       | 137.4 us   | 90.7 us     | 48,008        | 18,909         |
| 16 | 64  | 1039 ms  | 49.2 s   | 20.4 MiB    | 27.3 MiB     | 104,566      | 256,456       | 125.1 us   | 101.6 us    | 55,564        | 18,909         |
| 32 | 0   | 761 ms   | 24.8 s   | 23.4 MiB    | 21.6 MiB     | 170,885      | 131,172       | 129.3 us   | 88.5 us     | 50,001        | 30,776         |
| 32 | 32  | 767 ms   | 24.6 s   | 21.5 MiB    | 21.6 MiB     | 129,883      | 131,172       | 124.9 us   | 90.6 us     | 52,534        | 30,776         |
| **32** | **64** | **788 ms** | **24.5 s** | **19.9 MiB** | **21.6 MiB** | **94,042** | **131,172** | **120.6 us** | **89.9 us** | **56,972** | **30,776** |
| 32 | 128 | 825 ms   | 24.6 s   | 18.1 MiB    | 21.6 MiB     | 54,986       | 131,172       | 115.4 us   | 88.5 us     | 65,525        | 30,776         |
| 64 | 0   | 721 ms   | 8.4 s    | 20.8 MiB    | 18.7 MiB     | 113,079      | 68,783        | 118.8 us   | 84.8 us     | 59,867        | 40,541         |
| 64 | 64  | 713 ms   | 8.6 s    | 19.0 MiB    | 18.7 MiB     | 75,202       | 68,783        | 115.8 us   | 84.4 us     | 61,509        | 40,541         |
| 64 | 128 | 719 ms   | 8.4 s    | 17.9 MiB    | 18.7 MiB     | 50,922       | 68,783        | 113.9 us   | 82.8 us     | 66,638        | 40,541         |
| 64 | 256 | 739 ms   | 8.5 s    | 17.0 MiB    | 18.7 MiB     | 31,310       | 68,783        | 109.5 us   | 83.5 us     | 70,282        | 40,541         |

What the sweep shows:

- One incremental union costs about 45 ms at 1.0-1.4M rows (hourly) and
  100-150 ms at 1.4-4M rows (daily), essentially the cost of copying the
  rows and hashing the file; 24 hourly merges together are 3x cheaper than
  one rebuild of the final set at T = 32 (1.05 s against 3.3 s), and the
  7 daily merges 30x cheaper (0.8 s against 24.5 s; k-means over 4M rows is
  the rebuild's cost, superlinear in the size of the large cells).
- Without coalescing (C = 0) lists pile up: 3x the lists of a rebuild
  after 24 hourly merges, 1.5x the TIVF bytes, and queries 1.5-1.7x slower
  than on the rebuilt index. Any C > 0 brings the list count and the TIVF
  size below the rebuild's (the invariant packs cells more tightly than
  k-means' `ceil(m / T)`), and the bound of section 3 held throughout.
- Query time on the merged index is minimized at C = 2T for T = 16 and
  T = 32 and at C = T for T = 64; the raw minimum over the hourly sweep is
  T = 32, C = 64 (29.2 us, within 9% of the rebuilt index's 26.7 us), with
  T = 16, C = 64 a statistical tie (29.6 us) at a 60% higher rebuild cost
  and 20% more TIVF. Larger C trades list bounds for scanned rows: at
  C = 4T the merged index scans 40-70% more rows than at 2T and queries
  are 15-20% slower, since coalescing by smallest union radius still joins
  clusters k-means would have kept apart.
- The daily scenario is the hard case for the merge: each batch is 43% of
  the master, so most lists of the final index come from the batches' own
  fresh builds and their coalesced pairs; the merged index scans 1.9x the
  rows of a rebuild and answers in 1.3x the time (120 us against 90 us at
  the default), still two orders of magnitude under brute force over 4M
  rows (~2.2 ms). Query time improves slightly with larger C here because
  halving the lists saves more bound evaluations than the extra rows cost,
  but at the price of scanned rows that keep growing; it does not change
  the choice.

At N = 100,000 (same sweep, 4.8 minutes) the hourly final set is 532k rows
of which 80% came in through the batches, so it behaves like the daily case
above: at T = 32 the merged index answers in 21.1 / 19.1 / 17.9 us for
C = T / 2T / 4T against 17.5 us rebuilt (39.9 us without coalescing), with
13.7-13.9k rows scanned against 11.1k; 24 merges take 0.3 s against a
0.5 s rebuild. The daily scenario at this N is a 3.1M-row set built almost
entirely from 432k-row batches: 56.5 us merged against 38.1 us rebuilt at
the default, 0.5 s of merges against a 15.4 s rebuild.

Defaults: T = `TLSH_IVF_TARGET_LIST_SIZE` = 32 confirmed, and C =
`TLSH_IVF_DEFAULT_COALESCE` = 2T = 64, the configuration that minimizes the
query time on the merged index while the merge stays 3-30x cheaper than a
rebuild and the storage bound holds (the merged TIVF is in fact smaller
than the rebuilt one). A master that takes daily batches of this size for
weeks will drift further from a fresh clustering than this table shows;
when the rows scanned per query matter, a rebuild (any merge with
`SFHASH_HSET_TLSH_INDEX` against an input without an index, or
`build_tlsh_ivf`) restores the fresh profile and the incremental merges
resume from it.

**With BISECT** (`MERGE_BENCH_BUILD=bisect`, the default; 2026-10-23,
second round, the fresh build no longer coalescing; the KMEANS rows are a
rerun of the first BISECT round, on a loaded machine, which reproduced the
list counts and rows scanned above exactly with 20–35% longer times). The
full table is in `docs/BENCHMARKS.md` §7; the default configuration,
T = 32, C = 64:

| batches     | method | merges  | rebuild | lists merged | lists rebuilt | kNN merged | kNN rebuilt | rows/q merged | rows/q rebuilt |
|-------------|--------|---------|---------|--------------|---------------|------------|-------------|---------------|----------------|
| 24 × 18,000 | BISECT | 995 ms  | 440 ms  | 40,094       | 50,381        | 29.6 us    | 28.9 us     | 16,855        | 12,386         |
| 24 × 18,000 | KMEANS | 1040 ms | 4497 ms | 40,197       | 50,378        | 36.7 us    | 32.3 us     | 16,916        | 12,586         |
| 7 × 432,000 | BISECT | 782 ms  | 2525 ms | 93,946       | 131,274       | 127.6 us   | 94.7 us     | 56,676        | 31,668         |
| 7 × 432,000 | KMEANS | 881 ms  | 31.3 s  | 94,042       | 131,172       | 161.4 us   | 120.0 us    | 56,972        | 30,776         |

- The rebuild of the final set costs 0.44–0.45 s at 1.43M rows and
  2.2–2.5 s at 4.0M (KMEANS: 3.3 s and 24.5 s in the run above), so an
  hourly rebuild costs less than half the 24 merges, and the daily merges
  are 3x cheaper than a rebuild instead of 30x. A single merge is still
  about 10x cheaper than a rebuild.
- The merged indexes are nearly the same with either build (lists and rows
  scanned within 1%): after 24 or 7 merges most lists come from the
  batches and from coalescing.
- The rebuilt BISECT index has KMEANS's list counts (50,381 against
  50,378 at 1.43M, 131,274 against 131,172 at 4.0M) and scans 1.6% fewer
  rows at 1.43M and 2.9% more at 4.0M (31,668 against 30,776).
- The lists bound (merged ≤ rebuilt + nonempty cells) held in every
  configuration with C > 0, C = T included. (In the first BISECT round,
  whose fresh build coalesced and so had fewer lists than ⌈m/T⌉, it failed
  in all six C = T configurations.) C = 2T remains the query-time minimum
  of the merged index at T = 32 (29.6 us; C = T 32.3, 4T 34.2).

## 6. Using the embedding from Python

The ctypes bindings compute the embedding from the rows: `hasher.tlsh_embed`
for one digest, and `HSet.tlsh_embeddings(tidx=None)` for a whole TLSH hash
set as a new (n, 264) float32 numpy array whose row r is the embedding of row
r (about 1 KiB per row in memory), computed by one `sfhash_tlsh_embed_n` call
over the rows:

```python
import hasher
from hasher import hsvectors
with hasher.HSet.open('corpus.hset') as hset:
    X = hset.tlsh_embeddings()                    # (n, 264) float32
D = hsvectors.load_tlsh_digests('corpus.hset')   # (n, 36) uint8, row r <-> X[r]
R = hsvectors.load_tlsh_record_index('corpus.hset')  # (n,) uint64 RIDX, or None
```

`X` can go straight into numpy, scikit-learn, faiss, HDBSCAN or UMAP; drop
column 256 (`hasher.TLSH_EMBEDDING_L_DIM`, the length coordinate) for the
`include_length = false` distance. `hasher.hsvectors`
(`python/hasher/hsvectors.py`) walks the chunks of an hset in pure Python,
with no dependency on libhasher, and maps the rows and record index into
numpy; `hsvectors.tlsh_hex(bytes(D[r]))` renders a row as `"T1..."`,
`hsvectors.read_toc(path)` lists every chunk, and `utils/hschunks.py` prints
that table. `utils/hsvectors_example.py` runs brute-force kNN,
`NearestNeighbors` and HDBSCAN over the embeddings of a file.

Next to them, `HSet.tlsh_knn(digest, k, max_distance, include_length,
strategy)` is the exact kNN of section 4:

```python
import hasher
with hasher.HSet.open('corpus.hset') as hset:
    tidx = hset.index_for_type(hasher.TLSH)
    for row, dist in hset.tlsh_knn(hasher.tlsh_from_hex('T1...'), k=5):
        print(dist, hasher.tlsh_to_hex(hset.hash(tidx, row)))
```
