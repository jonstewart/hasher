# TLSH benchmarks: results across parameters

All numbers on this page were measured on the `tlsh`/`tlsh-embedding` branches
with the synthetic family corpus from `test/tlsh_corpus.cpp` (families of
mutated content hashed with TLSH, then digest-space perturbation; see
`docs/TLSH_EMBEDDING.md` §5 for its construction and its limits). Hardware:
Apple Silicon laptop (M-series; the incremental-merge sweep ran on an M5 Pro,
15 cores), clang 21, `-O3`, single thread for queries and brute-force scans,
all cores for index builds. Every strategy was asserted to return identical
(distance, row) lists before being timed.

**Build method.** Sections 1, 3, 4, 6, 7 (tables as first published) and
the KMEANS column of 8 were measured with the float k-means index build
(`TlshIvfBuild::KMEANS`), the default until 2026-10-23. Section 9 and the
BISECT rows of sections 7 and 8 use the integer build (`BISECT`), now the
default. The BISECT round (2026-10-23, Apple M5 Pro, 15 cores) ran on a
loaded machine: index query times of *both* methods came out 30–40% above
the earlier figures with identical rows scanned (KMEANS at 1M: IVF 11.9 µs
against 8.3 µs, cell index 21 µs against 16 µs; KMEANS rebuilds 20–35%
slower; Criterion 10–15% slower), so compare numbers within a table, not
across rounds.

How to reproduce:

| suite | command |
|---|---|
| kNN strategies | `TLSH_BENCH_N=10000,100000,1000000 ./test/bench_tlsh "tlsh_knn"` |
| build method | `TLSH_BENCH_BUILD=bisect\|kmeans` (default `bisect`) with the kNN command |
| IVF list size | `TLSH_BENCH_LIST=<T> TLSH_BENCH_N=1000000 ./test/bench_tlsh "tlsh_knn"` |
| hashing | `./test/bench_tlsh "tlsh_hash_throughput"` |
| incremental merge sweep | `MERGE_BENCH_N=1000000 MERGE_BENCH_BUILD=bisect\|kmeans ./test/bench_hset_merge` (default `bisect`; `MERGE_BENCH_T`, `MERGE_BENCH_C` narrow the sweep) |
| merge vs rebuild (test) | `./test/test "hset_merge_timing"` |
| Criterion (through the C API over hset files) | `cd rust/tlsh-bench && cargo bench` (uses the library default, BISECT since 2026-10-23) |
| BISECT index bytes (golden) | `./test/test "tlsh_ivf_golden*"`; `utils/hschunks.py <file.hset>` for per-chunk SHA-256 of real files |

## 1. kNN strategies vs corpus size (KMEANS)

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

## 3. IVF design iterations (1M rows, per query; KMEANS)

| version | design | query | build | exact for |
|---|---|---|---|---|
| v1 | lists grouped by L, 264-dim float centroids, all lists bounded | 777 µs | 124 s (1 thread) | diff ≤ 144 only |
| v2 | lists grouped by header cell, 256-dim float body centroids | 44 µs | 3.6 s (1 thread) | every distance |
| v3 | v2 with medoid digests + integer radii (bound = one kernel call) | 26 µs | 3.6 s (1 thread) | every distance |
| v3 + NEON kernel, contiguous single-list cells, list size 32 | 8.9 µs | 12.2 s (1 thread) | every distance |
| + parallel per-cell build | 8.3 µs | 1.45 s (15 threads) | every distance |

## 4. IVF target list size T (1M rows, v3, pre-NEON kernel, KMEANS)

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

## 6. Set operations: merge vs rebuild (KMEANS)

Union of 199,991 + 200,000 TLSH rows (299,991 after dedup), single thread for
the merge, parallel k-means for the rebuild:

| output sections | merge | from-scratch build |
|---|---|---|
| HDAT + HINT + TIVF | 12–19 ms | 190 ms |
| + TVEC (1 KiB/row, 315 MiB file) | 172 ms | 504 ms |

Criterion `hset_incremental_merge`: master 999,975 rows + batch 18,000:
incremental union 41.5 ms vs rebuild 1.45 s (35x); kNN on the merged index
19.8 µs vs 19.0 µs on the rebuilt one.

With BISECT (2026-10-23, loaded machine, `cargo bench`, 2 min 10 s for all
groups): incremental union 38.6 ms vs rebuild 346 ms (9x); kNN on the
merged index 22.5 µs vs 20.5 µs on the rebuilt one. `hset_knn` at 1M:
naive 3.35 ms, hset brute 605 µs, hset index 19.5 µs per query; the 1M-row
hset builds in 0.44 s (KMEANS: 1.45 s) and is 40.3 MiB (40.6).

## 7. Incremental merge sweep (coalescing threshold C)

First published with KMEANS (tables below); BISECT rows follow.

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

**BISECT** (2026-10-23, loaded machine, see the top of the page), N = 1M,
hourly, T = 32, with the same-session KMEANS run for comparison (its rows
scanned and list counts are identical to the first KMEANS run; its times
are not):

| C | build | 24 merges | 1 rebuild | lists merged / rebuilt | kNN merged / rebuilt | rows/query merged / rebuilt |
|---|---|---|---|---|---|---|
| 0 (none) | BISECT | 1.11 s | 0.53 s | 141K / 41K | 59.7 / 34.2 µs | 15.5K / 13.0K |
| 32 (T) | BISECT | 1.05 s | 0.50 s | 54K / 41K | 40.1 / 30.8 µs | 15.9K / 13.0K |
| **64 (2T)** | **BISECT** | **1.04 s** | **0.49 s** | **40K / 41K** | **37.3 / 30.3 µs** | **16.9K / 13.0K** |
| 128 (4T) | BISECT | 1.04 s | 0.51 s | 25K / 41K | 43.3 / 31.9 µs | 23.3K / 13.0K |
| 0 (none) | KMEANS | 1.13 s | 5.14 s | 146K / 50K | 54.8 / 34.4 µs | 15.1K / 12.6K |
| 32 (T) | KMEANS | 1.05 s | 4.58 s | 55K / 50K | 40.2 / 33.0 µs | 16.0K / 12.6K |
| 64 (2T) | KMEANS | 1.04 s | 4.50 s | 40K / 50K | 36.7 / 32.3 µs | 16.9K / 12.6K |
| 128 (4T) | KMEANS | 1.04 s | 4.46 s | 25K / 50K | 41.6 / 32.2 µs | 23.3K / 12.6K |

Daily, T = 32, C = 64: BISECT merges 0.78 s against a 2.97 s rebuild
(KMEANS same session: 0.88 s against 31.3 s); 93K / 104K lists merged /
rebuilt (KMEANS 94K / 131K); 165 / 129 µs (KMEANS 161 / 120 µs); rows
scanned 56.9K / 35.9K (KMEANS 57.0K / 30.8K).

What changes with BISECT:

- One hourly rebuild (0.5 s) now costs half the 24 hourly merges (1.0 s);
  the daily rebuild (2.7–3.0 s) still costs about 3.5x the 7 daily merges
  (0.7–0.9 s), against 30x with KMEANS. A single merge (~45 ms hourly)
  stays ~10x cheaper than a rebuild.
- The merged indexes are nearly the same as with KMEANS (lists and rows
  scanned within 1–2%): after 24 or 7 merges most lists come from the
  batches and from coalescing, not from the master's build.
- The rebuilt index has fewer lists (41K against 50K hourly, 104K against
  131K daily) and scans more rows (13.0K against 12.6K hourly, 35.9K
  against 30.8K daily, +17%), so a rebuild restores less of the fresh
  profile than it did with KMEANS; see section 9 for the same effect at
  4M rows in `bench_tlsh`.
- The lists bound (merged ≤ rebuilt + nonempty cells) held in every
  configuration with C ≥ 2T and failed in every C = T configuration
  (6 of 6; e.g. hourly T = 32: 54,408 > 41,274 + 9,704), where it is not
  implied: the BISECT rebuild has fewer lists than ⌈m/T⌉ per cell, which
  is what the proven bound is measured against. With KMEANS (same
  session) every C = T run held.
- The default C = 2T is still the query-time minimum of the merged index
  at T = 32 (37.3 µs; 40.1 at C = T, 43.3 at 4T).

Full BISECT sweep, N = 1M (171.6 s for the whole sweep; KMEANS took
619.7 s in the same session):

| T  | C   | merges | rebuild | TIVF merged | TIVF rebuilt | lists merged | lists rebuilt | bound | kNN merged | kNN rebuilt | rows/q merged | rows/q rebuilt |
|----|-----|--------|---------|-------------|--------------|--------------|---------------|-------|------------|-------------|---------------|----------------|
| hourly | | | | | | | | | | | | |
| 16 | 0   | 1165 ms | 749 ms | 13388 KiB | 9036 KiB | 160,842 | 67,983 | - | 63.9 us | 40.4 us | 14,159 | 11,494 |
| 16 | 16  | 1119 ms | 814 ms | 10011 KiB | 9036 KiB | 88,798 | 67,983 | - | 63.3 us | 50.5 us | 14,565 | 11,494 |
| 16 | 32  | 1106 ms | 810 ms | 8699 KiB | 9036 KiB | 60,807 | 67,983 | ok | 46.2 us | 46.8 us | 15,206 | 11,494 |
| 16 | 64  | 1070 ms | 802 ms | 7864 KiB | 9036 KiB | 42,980 | 67,983 | ok | 42.9 us | 45.2 us | 16,700 | 11,494 |
| 32 | 0   | 1111 ms | 527 ms | 12455 KiB | 7784 KiB | 140,919 | 41,274 | - | 59.7 us | 34.2 us | 15,451 | 12,986 |
| 32 | 32  | 1049 ms | 503 ms | 8399 KiB | 7784 KiB | 54,408 | 41,274 | - | 40.1 us | 30.8 us | 15,898 | 12,986 |
| 32 | 64  | 1038 ms | 491 ms | 7717 KiB | 7784 KiB | 39,849 | 41,274 | ok | 37.3 us | 30.3 us | 16,941 | 12,986 |
| 32 | 128 | 1040 ms | 509 ms | 7030 KiB | 7784 KiB | 25,193 | 41,274 | ok | 43.3 us | 31.9 us | 23,302 | 12,986 |
| 64 | 0   | 1094 ms | 334 ms | 11909 KiB | 7107 KiB | 129,271 | 26,827 | - | 56.2 us | 38.5 us | 19,304 | 16,030 |
| 64 | 64  | 1027 ms | 329 ms | 7444 KiB | 7107 KiB | 34,035 | 26,827 | ok | 40.0 us | 29.5 us | 19,890 | 16,030 |
| 64 | 128 | 1016 ms | 332 ms | 6972 KiB | 7107 KiB | 23,961 | 26,827 | ok | 43.2 us | 30.0 us | 23,862 | 16,030 |
| 64 | 256 | 1011 ms | 333 ms | 6626 KiB | 7107 KiB | 16,584 | 26,827 | ok | 44.5 us | 30.2 us | 26,942 | 16,030 |
| daily | | | | | | | | | | | | |
| 16 | 0   | 879 ms | 4194 ms | 27935 KiB | 25322 KiB | 255,186 | 199,441 | - | 192.1 us | 133.8 us | 39,970 | 23,528 |
| 16 | 16  | 814 ms | 4370 ms | 26810 KiB | 25322 KiB | 231,195 | 199,441 | - | 192.6 us | 133.5 us | 40,223 | 23,528 |
| 16 | 32  | 863 ms | 4356 ms | 23779 KiB | 25322 KiB | 166,520 | 199,441 | ok | 186.0 us | 132.5 us | 48,013 | 23,528 |
| 16 | 64  | 927 ms | 4458 ms | 20854 KiB | 25322 KiB | 104,125 | 199,441 | ok | 169.1 us | 136.0 us | 55,798 | 23,528 |
| 32 | 0   | 761 ms | 2733 ms | 23417 KiB | 20828 KiB | 158,799 | 103,570 | - | 169.6 us | 132.7 us | 51,542 | 35,917 |
| 32 | 32  | 799 ms | 2707 ms | 22054 KiB | 20828 KiB | 129,715 | 103,570 | - | 170.0 us | 162.3 us | 52,103 | 35,917 |
| 32 | 64  | 780 ms | 2971 ms | 20334 KiB | 20828 KiB | 93,042 | 103,570 | ok | 165.4 us | 128.6 us | 56,916 | 35,917 |
| 32 | 128 | 847 ms | 2698 ms | 18551 KiB | 20828 KiB | 54,997 | 103,570 | ok | 158.5 us | 131.8 us | 65,509 | 35,917 |
| 64 | 0   | 738 ms | 1509 ms | 21126 KiB | 18695 KiB | 109,931 | 58,071 | - | 160.4 us | 118.4 us | 60,316 | 42,870 |
| 64 | 64  | 728 ms | 1485 ms | 19496 KiB | 18695 KiB | 75,160 | 58,071 | - | 157.3 us | 116.8 us | 60,939 | 42,870 |
| 64 | 128 | 720 ms | 1465 ms | 18344 KiB | 18695 KiB | 50,583 | 58,071 | ok | 151.1 us | 116.0 us | 66,493 | 42,870 |
| 64 | 256 | 761 ms | 1467 ms | 17437 KiB | 18695 KiB | 31,236 | 58,071 | ok | 144.9 us | 115.7 us | 70,296 | 42,870 |

"bound" is the benchmark's check lists merged ≤ lists rebuilt + nonempty
cells. The rebuilt index is the same in every C row of a T; its kNN time
varies between them by up to 25% (162.3 against 128.6 µs, daily T = 32),
which is this round's timing noise.

## 8. Rebuild cost vs set size (T = 32, 15 threads)

Through the builder (sort, dedup, index build, file write;
`bench_hset_merge`'s "rebuild", and the 1M row is its master build):

| rows | KMEANS, first run | KMEANS, 2026-10-23 (loaded) | BISECT, 2026-10-23 (loaded) |
|---|---|---|---|
| 1,000,000 | 1.45 s | 1.73–1.99 s | 0.44–0.45 s |
| 1,431,931 | 3.3 s | 4.46–5.14 s | 0.49–0.53 s |
| 4,023,698 | 24.5 s (T = 16: 48 s; T = 64: 8.5 s) | 29.8–33.0 s (T = 16: 61.1–62.1 s; T = 64: 9.8–10.1 s) | 2.70–2.97 s (T = 16: 4.19–4.46 s; T = 64: 1.47–1.51 s) |

(The KMEANS first-run 1M figure is Criterion's `rebuild_union` of 1.018M
rows.) The index build alone (`bench_tlsh`, its own corpus):

| rows | KMEANS | BISECT |
|---|---|---|
| 1,000,000 | 1,587 ms | 152 ms |
| 2,000,000 | – | 498 ms |
| 4,000,000 | 28,580 ms | 1,618 ms |

KMEANS is superlinear: cost is dominated by the largest header cells, each
costing O(m² · d / T) for m rows (see `docs/DESIGN_DECISIONS.md`, "Rebuild
scaling"). BISECT is 10–18x faster but its wall time is not linear either
(3.2x per doubling from 1M to 4M), which is not yet explained (an open
issue in `docs/DESIGN_DECISIONS.md`).

## 9. IVF build method: BISECT vs KMEANS

`bench_tlsh "tlsh_knn"`, T = 32, k = 10, max_distance = 144, 20 queries,
2026-10-23 on a loaded machine (see the top of the page; one process per N,
`TLSH_BENCH_BUILD` set explicitly). Build on all cores; query single
thread.

| rows | method | IVF build | lists | bounds/query | rows scanned/query | IVF query | cell index query |
|---|---|---|---|---|---|---|---|
| 10,000 | BISECT | 1.8 ms | 3,138 | 152 | 1,917 | 6.1 µs | 4.0 µs |
| 10,000 | KMEANS | 2.1 ms | 3,138 | 152 | 1,920 | 6.3 µs | 3.8 µs |
| 100,000 | BISECT | 5.5 ms | 7,788 | 346 | 6,724 | 10.2 µs | 9.2 µs |
| 100,000 | KMEANS | 18.5 ms | 7,853 | 352 | 6,757 | 10.2 µs | 8.8 µs |
| 1,000,000 | BISECT | 152 ms | 31,668 | 501 | 5,110 | 11.6 µs | 20.9 µs |
| 1,000,000 | KMEANS | 1,587 ms | 36,820 | 618 | 4,848 | 11.9 µs | 21.1 µs |
| 2,000,000 | BISECT | 498 ms | 46,179 | 570 | 5,900 | 14.7 µs | 27.2 µs |
| 4,000,000 | BISECT | 1,618 ms | 76,993 | 839 | 7,501 | 22.8 µs | 41.9 µs |
| 4,000,000 | KMEANS | 28,580 ms | 129,872 | 1,463 | 4,631 | 17.6 µs | 44.0 µs |

A rerun of the default (`TLSH_BENCH_N=10000,100000,1000000`, one process)
gave 6.0 / 9.9 / 11.2 µs and 1.6 / 5.6 / 153 ms, with the same lists and
rows. Up to 1M rows BISECT matches KMEANS within 6% on rows scanned at a
tenth of the build time; at 4M it scans 62% more rows (its lists average
52 rows against T = 32) and answers 30% slower, an open issue
(`docs/DESIGN_DECISIONS.md`).

**The rounds that led to BISECT** (1M rows, T = 32, rows scanned per
query; the KMEANS reference was 4,848 rows, 8.9–9.3 µs, 1.45–1.47 s build;
earlier sessions):

| round | partition of a cell | rows/query | query | build | outcome |
|---|---|---|---|---|---|
| 1 | recursive bisection to leaves ≤ 4T/3, farthest-pair member pivots, 1/8 median fallback, exact 1-center leaves | 13,533 | 19.5 µs (KMEANS 9.3) | 22 ms | a hard two-way split cuts families across the boundary |
| 1′ | pivot refinement rounds: 0 / 2 / 6 | 14,043 / 13,533 / 13,629 | | | no measurable effect, removed |
| 2 | bisection above 4096 rows, flat k-medoids++ seeding below | 13,775 | | | |
| 2′ | + Lloyd rounds with sum-of-squares medoid update | 11,627 | 16.8 µs | | mean list radius 10.1 against 7.1: a data point is a poor center in 256 dims |
| 2″ | forced splits down to 512 / 256 rows | 13,221 / 13,520 | | | the coarse split is cheap; the flat partition was the problem |
| 3 | flat k-means over exact integer centroids (BISECT today) | 5,110 | 8.6 µs (KMEANS 8.9) | 135 ms (KMEANS 1,467) | 31,668 lists against 36,820; radius 7.12 against 7.13; default since 2026-10-23 |

**BISECT target list size T** (1M rows, `TLSH_BENCH_LIST=<T>`, loaded
machine; compare with section 4's KMEANS sweep for the shape, not the
times):

| T | lists | bounds/query | rows scanned/query | query | build |
|---|---|---|---|---|---|
| 16 | 46,525 | 801 | 4,091 | 13.0 µs | 274 ms |
| 32 | 31,668 | 501 | 5,110 | 12.1 µs | 152 ms |
| 64 | 20,801 | 301 | 8,021 | 15.4 µs | 106 ms |
| 128 | 13,825 | 165 | 12,658 | 21.8 µs | 71 ms |
| 256 | 10,825 | 105 | 15,965 | 23.9 µs | 54 ms |

T = 32 remains the query-time minimum; T = 16 scans 20% fewer rows but
evaluates 60% more bounds.
