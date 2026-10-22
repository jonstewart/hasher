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

- **Rebuild cost is superlinear in cell size.** Per cell with m rows and
  k = m/T lists, k-means++ seeding, Lloyd iterations over a sample that grows
  with k, and the final assignment are each O(m · k · d) = O(m² · d / T),
  d = 256; summed over cells the build is Σ m_c², dominated by the largest
  cells, and a single large cell is handled by one thread. Observed at
  T = 32: 1.45 s at 1M rows, 3.3 s at 1.43M, 24.5 s at 4.0M. Candidate
  mitigations, in order: two-level (√k) or bisecting k-means inside large
  cells (O(m^1.5) or O(m log k)); a sample cap independent of k for the Lloyd
  iterations; int8/NEON or random-projected (JL, 32-dim) distances for the
  assignment, with exact medoid radii computed afterwards in full space;
  within-cell parallelism for the assignment pass; lazy per-cell rebuilds
  (recluster only cells whose list count exceeds 1.5x ⌈m/T⌉ after merges).
- **Daily-scale incremental merges** (batch ≈ 40% of master) degrade pruning
  to ~1.9x rows scanned; rebuild when rows scanned matter.
- **x86 kernel path untested** (scalar fallback; NEON only on arm64).
- **Full-embedding L caveat**: the 264-dim embedding's bound holds for
  diff ≤ 144 and ignores L wraparound at multi-terabyte inputs; the index is
  unaffected (L is constant within a cell).
