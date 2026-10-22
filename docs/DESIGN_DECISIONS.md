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
- **Target list size T = 32** (sweep in BENCHMARKS §4).
- **Vectors are optional and the index does not need them.** TIVF embeds
  digests on the fly, so very large sets can carry the index without the
  1 KiB/row TVEC.
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
  Proven: lists ≤ 2m/C + 1 per cell (≤ fresh + 1 at C = 2T); storage over a
  rebuild ≤ 48 B x nonempty cells ≤ 3 MiB independent of n and merge count;
  ≤ one extra bound evaluation per visited cell per query. Rows scanned is
  measured, not bounded. The sweep (BENCHMARKS §7) picked C = 2T as the
  minimum merged-index query time; C = 4T trades lists for 40–70% more rows
  scanned, C = 0 triples the lists.
- **Known wart:** builder set-op contexts default to writing vectors and
  index; `sfhash_hashset_merge` and `hsetop` default to inheriting from the
  inputs.

## Open issues

- **Rebuild cost is superlinear in cell size.** See "Rebuild scaling" below.
- **Daily-scale incremental merges** (batch ≈ 40% of master) degrade pruning
  to ~1.9x rows scanned; rebuild when rows scanned matter.
- **x86 kernel path untested** (scalar fallback; NEON only on arm64).
- **Full-embedding L caveat**: the 264-dim embedding's bound holds for
  diff ≤ 144 and ignores L wraparound at multi-terabyte inputs; the index is
  unaffected (L is constant within a cell).

## Rebuild scaling: analysis and plan

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

**Mitigations (planned, not implemented), in order:**

1. *Hierarchical or bisecting k-means inside large cells.* Two levels of √k
   clusters give O(m^1.5 · d); bisecting k-means gives O(m · log k · d). No
   effect on results.
2. *Cap the Lloyd sample independently of k.* Today the iterations run over a
   random subset of up to max(32k, 2048) rows of the cell, followed by one
   exact nearest-centroid assignment of all rows; a fixed cap (e.g. 4096)
   makes the iterations linear in m. Centroids, partition and index bytes
   change slightly; kNN results do not; the build stays deterministic per
   seed. Also parallelize the final assignment pass within a cell so a giant
   cell no longer serializes on one thread.
3. *Cheaper distances for the assignment only.* Body coordinates are in
   {-1, 0, 1}, so the dot product with an int8-quantized centroid is NEON byte
   arithmetic (~8–16x fewer cycles than 256 float ops); alternatively assign
   in a seeded 32-dim random projection (Johnson–Lindenstrauss). Medoid and
   radius are then computed exactly in full space, so kNN results are
   unchanged; only boundary assignments move. Side benefit: an integer
   assignment path makes the index bytes reproducible across compilers and
   platforms, which the float path is not (accumulation order).
4. *Lazy per-cell rebuilds* (recluster only cells whose list count exceeds
   1.5x ⌈m/T⌉ after merges) as an additional operation. Decision (Jon,
   2026-10-22): the full rebuild (`build_tlsh_ivf`) must always remain
   available; lazy rebuilds supplement it, they never replace it.
5. *Locality-order partition for huge cells*: sort the cell's rows by a
   locality-preserving key on the body planes (Gray-code / plane-prefix
   order), cut into runs of T, compute medoid and radius exactly. O(m log m),
   trivially parallel, no floating point (bit-reproducible everywhere), but
   lower quality than k-means (coherent in the leading planes only), which
   coalescing and the rows-scanned statistic expose. Usable as the initial
   partition that (1) refines, or as a fallback. To be evaluated once real
   data is available.

Items 1–3 together are expected to bring the 4M build from 24.5 s to the low
seconds and 100M rows to minutes rather than hours.
