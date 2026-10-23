# TLSH in hset: design decisions

A log of the decisions taken on the `tlsh` and `tlsh-embedding` branches,
with the alternatives considered and the measurements that settled them
(numbers in `docs/BENCHMARKS.md`). Format details live in `HASHSET_FORMAT`
and `docs/TLSH_EMBEDDING.md`.

## Digest and hashing

- **Own streaming hasher, reference vendored for conformance.** The reference
  `Tlsh` class has a shallow copy constructor (heap bucket array), so it
  cannot back `clone()`. Our hasher keeps 256 counters, a 5-byte window and the
  checksum in a trivially copyable object and is tested bit-exact against the
  reference on its 80 example files and on random inputs. The reference
  library is linked for `l_capturing` and for tests only.
- **36-byte canonical row whose bytewise order is the canonical order**
  (L, Q1 Q2, plane_hi, plane_lo, checksum, reserved). The spec's row put the
  checksum first and Q1 in the low nibble; we moved them so that the existing
  hset machinery (bytewise sort, `std::unique`, binary search) works unchanged
  and every header cell is a contiguous run. The all-zero row is TNULL.
- **Body stored as two 128-bit planes.** Body distance becomes
  `popcount(X^Y) + popcount(Y) + 5 popcount(X&Y&S)`; three popcounts instead
  of 32 table lookups.

## hset integration

- **Duplicates stay duplicate rows mapped through RIDX**, as the existing
  format does for every hash type, instead of the spec's CSR
  `TLSH_RECORD_MAP`.
- **Cell index as a HINT (type 0x7400)**: the spec's 65,537-offset table, in
  the slot where other hash types keep their block hints. Readers may rebuild
  it; writers always emit it.
- **Exact `contains` via the cell index**, binary search inside the cell.

## Embedding

- **Per-component lower bounds, orthogonal blocks.** Body: 2-D staircase
  (1,0),(0,0),(0,1),(-1,1) giving 1,1,1,2,2,5 against TLSH's 1,1,1,2,2,6;
  the triangle inequality caps d(0,3) at (1+√2)² ≈ 5.83 given adjacent
  distances 1, so 5 is the best integer placement. L: linear, k² ≤ 12k for
  k ≤ 12; a unit-step chain bounds any realization by k², so this is optimal
  up to the 144 cap. Q1/Q2: regular 16-gons with unit edges. Checksum: three
  bits scaled by 1/√3. Float32, 264 dims, row-major, page aligned, so numpy,
  faiss, scikit-learn and HDBSCAN consume it without conversion.
- **Rejected:** a thermometer (unary) code for L (valid for all k but 12x
  looser at k = 1); bit-plane coordinates for the body (α+β ≤ 1 forces a
  looser bound than the staircase).

## Index

- **IVF grouped by header cell, not by L or globally.** v1 grouped by L with
  264-dim centroids: slow to build (quadratic k-means over huge groups) and a
  centroid pass over all lists per query; it lost to the plain cell index.
  Grouping by cell makes the header exact and leaves the embedding only the
  body to bound, which also removes the 144 cap: the index is exact for every
  distance.
- **Medoid digest + integer radius instead of float centroid + float radius.**
  A list bound becomes one popcount kernel call and 40 bytes instead of ~1 KiB
  and 256 float ops; query time fell from 44 µs to 26 µs at 1M.
- **Target list size T = 32** (sweep in BENCHMARKS §4; the BISECT sweep,
  §9, puts T = 16 and 32 within 4% of each other, 32 ahead by the
  summary's minimum and 16 by Criterion-style means; 32 builds in half
  the time with half the lists).
- **Vectors are optional and the index does not need them.** TIVF embeds
  digests on the fly, so very large sets can carry the index without the
  1 KiB/row TVEC.
- **Default builder: integer k-means under a coarse bisection (BISECT).**
  A cell of more than `TLSH_IVF_BISECT_FLAT_MAX` = 4096 rows is split in two
  around two far-apart member pivots (A farthest from a random member, B
  farthest from A), with a median split when one side would get under 1/8;
  each node of at most 4096 rows is clustered flat into ⌈s/T⌉ lists by
  k-means whose centroids are exact integers (int32 coordinate sum + count;
  nearest centroid by cross-multiplying the rational squared distances in
  64 bits, `tlsh_ivf_nearer`, overflow excluded by a static_assert on
  FLAT_MAX; k-means++ seeding with the kernel; ≤ 10 rounds, none needed
  more than 7). Without coalescing (below; `bench_tlsh`, T = 32): at 1M
  rows 4,659 rows scanned/query vs 4,848 for the float k-means, 36,823
  lists vs 36,820, build 136 ms vs 1,481 ms; at 4M 4,752 vs 4,631 rows,
  129,948 vs 129,872 lists, build 1.26–1.41 s vs 25.7 s; query time
  within noise at 1M, 4–14% above KMEANS at 4M. O(m) kernel calls per
  bisection level and a flat cost per row that grows with the cell size
  up to FLAT_MAX ("Rebuild scaling"). Decision (Jon, 2026-10-23): BISECT
  is the default.
- **Rejected on the way** (1M rows, rows scanned/query; k-means 4,848):
  pure recursive bisection down to lists of ≤ 4T/3 (13,533; 22 ms build;
  a hard two-way split cuts families across the boundary); refinement
  rounds for its pivots (0 rounds 14,043, 2: 13,533, 6: 13,629; removed);
  flat k-medoids below FLAT_MAX, k-medoids++ seeding and Lloyd rounds with
  a sum-of-squares medoid update (11,627, 16.8 µs; size-weighted mean list
  radius 10.1 vs 7.1: a data point is a poor center in 256 dimensions).
- **FLAT_MAX = 4096.** Forcing the coarse split down to 512 or 256 rows
  moved k-medoids' rows scanned only from 11,627 to 13,221 / 13,520, so the
  split is cheap in quality and the flat partition is what matters. 4096
  bounds a flat node's k-means to ⌈4096/T⌉ centroids (128 at T = 32), and
  `tlsh_ivf_nearer`'s 64-bit products stay exact up to 2^13 rows.
- **Medoid = exact 1-center** (the member minimizing the max distance to
  the others, so the smallest member radius2) of every list.
- **No coalescing in a fresh build.** A fresh BISECT index's lists are
  exactly the nonempty k-means groups of its flat nodes, so a cell has at
  most Σ ⌈s_i/T⌉ lists (⌈m/T⌉ below FLAT_MAX) and need not satisfy
  `tlsh_ivf_check_invariant` at any threshold. The first BISECT round
  coalesced lists below T/2 per cell (C = T) so that it would; in a fresh
  build that pairs unrelated small families into wide lists, and the
  pairing costs O(s²) in a cell's small lists. At 4M rows (`bench_tlsh`,
  T = 32) coalescing gave 76,993 lists, 839 bounds and 7,501 rows
  scanned per query, 22.8 µs, build 1,618 ms; without it 129,948 lists,
  1,464 bounds, 4,752 rows, 12.5 µs, 1,263 ms (controller's run,
  2026-10-23; this round 13.5–14.2 µs, 1,264–1,409 ms). Removed with
  `TLSH_IVF_BISECT_COALESCE_FACTOR`. The merge path's coalescing (C = 2T,
  "Set operations") is unchanged: there the small lists come from small
  batches, and the bound on lists depends on it.
- **Lists in depth-first order of the bisection.** A cell's lists are
  contiguous by subtree, so a later TIVF version can add per-subtree bounds
  without re-clustering.
- **KMEANS kept as the float alternative**, selected by
  `SFHASH_HSET_TLSH_INDEX_KMEANS` (8) in `HSET_TLSH_OPTIONS` (`mkhashset`,
  `hsetop`) or the builder's TLSH options; it governs only indexes built
  from scratch (a merge with `SFHASH_HSET_TLSH_INHERIT` never rebuilds).
  Decision (Jon): keep both for now, with CLI control.
- **Reproducible index bytes.** BISECT has no floating point; integer sums
  are order-independent and random draws are `rng() % n` from
  mt19937_64 (fully specified by the standard), never a std distribution.
  `test/test_tlsh_ivf_golden.cpp` records the SHA-256 of the TIVF bytes for
  two integer-generated corpora (one cell above FLAT_MAX); a mismatch on
  another platform is a reproducibility bug, not a constant to update.
  `utils/hschunks.py` prints each chunk's payload SHA-256, so real files can
  be compared across machines (the FHDR timestamp makes whole-file hashes
  differ by design). The real golden test: 9M-sample VirusShare builds on
  arm64 and x86 (Jon).
- **No intra-cell work-stealing.** Parallelism stays per cell; an
  unnecessary complication (decision, Jon).
- **Rejected:** per-row projections for pruning (the kernel at 0.55 ns/row is
  already cheaper than any projection check); duplicating digests in list
  order inside TIVF (the ids indirection cost ~0.3 ns/row after prefetching,
  not worth doubling storage).

## Search

- **Cells enumerated in header-cost order without sorting** (`TlshHeaderOrder`:
  L offsets 0, ±1, ±2, …; Q bytes from a static cost-sorted (k1, k2) table
  translated by the query).
- **Bounded max-heap on (distance, index)**; ties by ascending index so every
  strategy returns identical lists.
- **Single-list cells scanned contiguously** (their ids are the cell's row
  range), lists shorter than 4 rows never bounded.

## Set operations

- **Merge, don't rebuild.** Sections are merged two-pointer style; the cell
  index is a prefix sum; TVEC rows follow their digests; TIVF lists are
  concatenated per cell with ids remapped, medoids and radii kept (a radius
  depends only on a list's members, so exactness is preserved; a medoid need
  not be a member).
- **One API.** `sfhash_hashset_builder_union_open/_intersect_open/_subtract_open`
  now run the merge path; `sfhash_hashset_merge` is the one-call form; the
  record-rebuild path is gone. Set operations work on hashsets-only files too.
- **Bounded coalescing, C = 2T = 64.** Lists smaller than C/2 are coalesced
  pairwise by smallest exact union radius until at most one remains per cell.
  Proven: lists ≤ 2m/C + 1 per cell (≤ ⌈m/T⌉ + 1 at C = 2T); storage over a
  rebuild ≤ 48 B x nonempty cells ≤ 3 MiB independent of n and merge count;
  ≤ one extra bound evaluation per visited cell per query. Rows scanned is
  measured, not bounded. The sweep (BENCHMARKS §7) picked C = 2T as the
  minimum merged-index query time; C = 4T trades lists for 40–70% more rows
  scanned, C = 0 triples the lists.
- **Known wart:** builder set-op contexts default to writing vectors and
  index; `sfhash_hashset_merge` and `hsetop` default to inheriting from the
  inputs.

## Open issues

- **Resolved: BISECT degraded at 4M rows** (76,993 lists, 7,501 rows
  scanned against KMEANS's 129,872 and 4,631). The cause was the
  coalescing of the fresh build (see "Index"); without it, 129,948 lists
  and 4,752 rows. The merge sweep's rebuilt 4.0M index (T = 32) now has
  131,274 lists (KMEANS 131,172) and scans 31,668 rows (KMEANS 30,776).
- **Resolved: BISECT's build "not linear in n".** Part of the growth was
  the fresh build's `coalesce_cell` (1,618 ms at 4M with it, 1,263 ms
  without); the rest is the cost model, not a bug ("Rebuild scaling").
  A NEON int8 × int16 dot product for the centroid distances is a
  possible follow-up if the 120M build needs it.
- **`coalesce_cell` is O(s²) in the small lists of a cell** (distance
  matrix + heap), now on the merge path only. Negligible at 1M (9.9 ms
  summed over threads, 0.10 ms max per cell, measured when the fresh build
  still coalesced), but a 10M-row cell with a few percent of small lists
  would need gigabytes; a windowed or per-subtree variant is needed before
  the 120M corpus is merged incrementally.
- **BISECT depends only weakly on the seed** (the farthest-point pivots
  and k-means++ often come out the same on small corpora).
- **A node of identical bodies is one list**, however large (up to
  FLAT_MAX = 4096 rows); its radius is 0, and its 1-center costs O(s²)
  kernel calls.
- **Per-subtree bounds for 120M rows.** A query visits ~59 cells; at 120M
  rows it would evaluate ~75,000 list bounds there. Lists are in
  depth-first order so a later TIVF version can add bounds per bisection
  subtree without re-clustering.
- **Daily-scale incremental merges** (batch ≈ 40% of master) degrade pruning
  to ~1.9x rows scanned; rebuild when rows scanned matter.
- **x86 kernel path untested** (scalar fallback; NEON only on arm64).
- **Full-embedding L caveat**: the 264-dim embedding's bound holds for
  diff ≤ 144 and ignores L wraparound at multi-terabyte inputs; the index is
  unaffected (L is constant within a cell).

## Rebuild scaling: analysis and outcome

**Complexity.** The index build runs an independent k-means per header cell.
For a cell of m rows and k = m/T lists, three phases each cost O(m · k · d)
with d = 256 float dimensions: k-means++ seeding, the Lloyd iterations (up to
10, over a sample of 32k rows, so O(k² · d) per iteration), and the final
assignment of all m rows to the nearest of k centroids. A cell therefore costs
Θ(m² · d / T) and the build Θ(d / T · Σ_c m_c²): dominated by the largest
cells, not by n. Evenly spread rows give n²/C over C cells; a real corpus,
concentrated in a few dozen L values, sits nearer n². Parallelism is per cell,
so one giant cell occupies one thread and bounds the wall time regardless of
core count.

**Observed** (T = 32, 15 threads, synthetic corpus): 1.45 s at 1.0M rows,
3.3 s at 1.43M, 24.5 s at 4.0M (2.8x the rows, 7.4x the time; quadratic
predicts 7.9x). T = 16: 48 s at 4.0M; T = 64: 8.5 s. Extrapolated to 100M rows
with the same cell occupancy: hours.

**Correctness principle.** The index is exact because, and only because, every
member of a list lies within the list's stored `radius2` of its medoid, and
both are computed exactly with the integer kernel over the full planes after
the partition is chosen. How rows are partitioned into lists is a quality knob
(rows scanned per query, hence time), never a correctness knob. Every
mitigation below changes only the partition; `test/test_tlsh_ivf.cpp`,
`test/test_hset_tlsh_vectors.cpp` and `test/test_hset_merge*.cpp` assert
kNN == brute force for whatever partition the builder produces, and
`test/bench_hset_merge.cpp` / `test/bench_tlsh.cpp` measure the quality side.

**Outcome, per item of the plan:**

1. *Hierarchical clustering inside large cells:* done, as BISECT (see
   "Index"): a coarse integer bisection above 4096 rows, flat integer
   k-means below, so O(m log m) kernel calls for the splits and linear
   flat work per cell. Pure bisection and flat k-medoids were tried and
   rejected on rows scanned.
2. *Cap the Lloyd sample:* moot. The integer k-means has no sample (it
   runs over every row of a flat node of at most 4096 rows); KMEANS is no
   longer the default and keeps its sample as it was.
3. *Cheaper distances:* moot. The integer centroids are the int8
   quantization, exactly; reproducible bytes came with them.
4. *Lazy per-cell rebuilds:* remaining, a possible follow-up. The decision
   stands: the full rebuild must always remain available.
5. *Locality-order partition:* moot; the integer build is already
   bit-reproducible and of k-means quality.

**Observed, BISECT without coalescing** (T = 32, 15 threads, same corpus,
2026-10-23, second round; `test/bench_hset_merge` "rebuild" = sort, dedup,
index build and file write through the builder): 0.41–0.43 s at 1.0M rows
(the master build; KMEANS 1.45 s), 0.44–0.45 s at 1.43M (3.3 s),
2.2–2.5 s at 4.0M (24.5 s); T = 16: 3.7–4.3 s at 4.0M (48 s); T = 64:
1.4–1.5 s (8.5 s). Index build alone (`test/bench_tlsh`): 136 ms at 1M,
437 ms at 2M, 1.26–1.41 s at 4M, against KMEANS's 1.48 s and 25.7 s at 1M
and 4M (same session).

**BISECT's cost per row grows with the cell size, up to FLAT_MAX.** A row
costs one 256-coordinate dot product per centroid of its flat node per
k-means round, and a flat node of s rows has ⌈s/T⌉ centroids, at most
⌈4096/32⌉ = 128. The synthetic corpus has about 9,000–9,600 nonempty
cells at every size (8,975 at 1M, 9,607 at 4M), so rows per cell grow
linearly with n; the row-weighted mean of min(⌈m_c/T⌉, 128) over the
cells is 21.2 at 1M, 39.8 at 2M and 63.5 at 4M (an upper estimate of the
centroids per row: a cell above FLAT_MAX is split into nodes of fewer
than 4096 rows; 0.6%, 4.6% and 22.8% of the rows are in such cells).
That predicts 3.8x and 3.2x per doubling; the build took 3.2x (136 →
437 ms) and 2.9x (437 → 1,264 ms). Once a corpus's cells exceed 4096
rows the cost per row is constant and the build linear in n. The
k-means++ seeding (k passes over the node, one kernel call per row) and
the 1-center of each list (O(list²) kernel calls) add terms of the same
or smaller order. A NEON int8 × int16 dot product is the possible
follow-up if the 120M build needs it.
