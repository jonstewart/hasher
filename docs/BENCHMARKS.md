# TLSH benchmarks: results across parameters

All numbers on this page were measured on the `tlsh`/`tlsh-embedding` branches
with the synthetic family corpus from `test/tlsh_corpus.cpp` (families of
mutated content hashed with TLSH, then digest-space perturbation; see
`docs/TLSH_EMBEDDING.md` §5 for its construction and its limits). Hardware:
Apple Silicon laptop (M-series; the incremental-merge sweep ran on an M5 Pro,
15 cores), clang 21, `-O3`, single thread for queries and brute-force scans,
all cores for index builds. Every strategy was asserted to return identical
(distance, row) lists before being timed. How to reproduce:

| suite | command |
|---|---|
| kNN strategies | `TLSH_BENCH_N=10000,100000,1000000 ./test/bench_tlsh "tlsh_knn"` |
| IVF list size | `TLSH_BENCH_LIST=<T> TLSH_BENCH_N=1000000 ./test/bench_tlsh "tlsh_knn"` |
| hashing | `./test/bench_tlsh "tlsh_hash_throughput"` |
| incremental merge sweep | `MERGE_BENCH_N=1000000 ./test/bench_hset_merge` |
| merge vs rebuild (test) | `./test/test "hset_merge_timing"` |
| Criterion (through the C API over hset files) | `cd rust/tlsh-bench && cargo bench` |

## 1. kNN strategies vs corpus size

k = 10, max_distance = 144, include_length = true, 20 queries drawn from the
corpus and perturbed; per-query time, min of repeated passes.

| rows | reference brute (`Tlsh::totalDiff`) | kernel brute | cell index | IVF index | IVF build (15 threads) |
|---|---|---|---|---|---|
| 10,000 | 95 µs | 7.0 µs | 3.4 µs | 4.5 µs | 2 ms |
| 100,000 | 941 µs | 57 µs | 6.8 µs | 8.9 µs | 17 ms |
| 1,000,000 | 9.5 ms | 566 µs | 16 µs | 8.3 µs | 1.4 s |

Rows touched per query at 1,000,000: brute 1,000,000; cell index 18,900 over
59 cells; IVF 4,850 over the same 59 cells with 618 list bounds evaluated.

Through the C API over an hset file (Criterion, `hset_knn`, one FFI call per
row for the naive baseline): at 1M rows, naive 3.04 ms, hset brute 560 µs,
hset index 17 µs per query (different corpus seed from the C++ bench).

## 2. Kernel rounds (brute-force scan, ns per row)

| version | ns/row | note |
|---|---|---|
| reference `Tlsh::totalDiff` | 9.5 | 32 byte-pair table lookups + header |
| scalar bit-plane kernel (3 popcounts per 64-bit word) | 1.6 | `popcount(X^Y) + popcount(Y) + 5 popcount(X&Y&S)` |
| + per-query header cost tables | 1.5 | |
| NEON per-query planes, one horizontal reduction | 0.55 | `TlshBodyQuery` |

## 3. IVF design iterations (1M rows, per query)

| version | design | query | build | exact for |
|---|---|---|---|---|
| v1 | lists grouped by L, 264-dim float centroids, all lists bounded | 777 µs | 124 s (1 thread) | diff ≤ 144 only |
| v2 | lists grouped by header cell, 256-dim float body centroids | 44 µs | 3.6 s (1 thread) | every distance |
| v3 | v2 with medoid digests + integer radii (bound = one kernel call) | 26 µs | 3.6 s (1 thread) | every distance |
| v3 + NEON kernel, contiguous single-list cells, list size 32 | 8.9 µs | 12.2 s (1 thread) | every distance |
| + parallel per-cell build | 8.3 µs | 1.45 s (15 threads) | every distance |

## 4. IVF target list size T (1M rows, v3, pre-NEON kernel)

| T | lists | bounds/query | rows scanned/query | query | build (1 thread) |
|---|---|---|---|---|---|
| 16 | 67,368 | 1,205 | 3,159 | 13.4 µs | 20.3 s |
| 32 | 36,820 | 618 | 4,879 | 13.9 µs | 12.2 s |
| 64 | 21,571 | 326 | 8,226 | 20.2 µs | 6.5 s |
| 128 | 14,283 | 180 | 12,171 | 26.0 µs | 3.6 s |
| 256 | 10,971 | 109 | 16,123 | 33.1 µs | 1.9 s |

Chosen: T = 32 (knee of the curve; 16 costs 70% more build for 4% less query
time).

## 5. Hashing throughput (4 MiB random buffer)

| implementation | throughput |
|---|---|
| reference `Tlsh` | 312 MiB/s |
| `TlshHasher`, first version | 256 MiB/s |
| `TlshHasher`, sliding window in registers | 295 MiB/s |

## 6. Set operations: merge vs rebuild

Union of 199,991 + 200,000 TLSH rows (299,991 after dedup), single thread for
the merge, parallel k-means for the rebuild:

| output sections | merge | from-scratch build |
|---|---|---|
| HDAT + HINT + TIVF | 12–19 ms | 190 ms |
| + TVEC (1 KiB/row, 315 MiB file) | 172 ms | 504 ms |

Criterion `hset_incremental_merge`: master 999,975 rows + batch 18,000:
incremental union 41.5 ms vs rebuild 1.45 s (35x); kNN on the merged index
19.8 µs vs 19.0 µs on the rebuilt one.

## 7. Incremental merge sweep (coalescing threshold C)

Full tables for N = 1M and 100k, hourly (24 x 18,000) and daily (7 x 432,000)
batches, T in {16, 32, 64} x C in {0, T, 2T, 4T}, are in
`docs/TLSH_EMBEDDING.md` §5 "Incremental merge". Headline, N = 1M, hourly,
T = 32:

| C | 24 merges | 1 rebuild | lists merged / rebuilt | kNN merged / rebuilt | rows/query merged / rebuilt |
|---|---|---|---|---|---|
| 0 (none) | 1.11 s | 3.30 s | 146K / 50K | 43.5 / 28.2 µs | 15.1K / 12.6K |
| 32 (T) | 1.07 s | 3.32 s | 55K / 50K | 30.9 / 26.4 µs | 16.0K / 12.6K |
| **64 (2T)** | **1.05 s** | **3.32 s** | **40K / 50K** | **29.2 / 26.7 µs** | **16.9K / 12.6K** |
| 128 (4T) | 1.05 s | 3.31 s | 25K / 50K | 34.0 / 26.5 µs | 23.3K / 12.6K |

Daily batches (43% of the master each): merges 0.7–1.0 s vs 24.5 s rebuild at
T = 32; the merged index scans 1.9x the rows of a rebuild and answers in 1.3x
the time, the documented no-formal-bound regime.

## 8. Rebuild cost vs set size (T = 32, 15 threads)

| rows | k-means build |
|---|---|
| 1,000,000 | 1.45 s |
| 1,431,931 | 3.3 s |
| 4,023,698 | 24.5 s (T = 16: 48 s; T = 64: 8.5 s) |

Superlinear: cost is dominated by the largest header cells, each costing
O(m² · d / T) for m rows (see `docs/DESIGN_DECISIONS.md`, "Open issues").
