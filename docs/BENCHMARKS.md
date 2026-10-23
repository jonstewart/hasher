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
across rounds. The BISECT rows of sections 7, 8 and 9 and the Criterion
rerun come from a second round the same day (2026-10-23), after the fresh
BISECT build stopped coalescing. That machine was quieter (load averages
1.5–3.7 during the kNN runs; IVF query at 1M 8.3 µs against 11.6 µs
before) but short of memory (8.6 of 10 GiB swap in use): the first full
merge sweep stalled for minutes (generating the hourly batches took
1,020 s against 13 s), so its hourly T = 16 and T = 32 timings were
replaced by reruns (`MERGE_BENCH_T`); list counts and rows scanned are
deterministic and agreed.

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

With BISECT without fresh coalescing (2026-10-23, second round, `cargo
bench`, 2 min for all groups): incremental union 41.5 ms vs rebuild
309 ms (7.4x); kNN on the merged index 19.6 µs vs 18.7 µs on the rebuilt
one. `hset_knn` at 1M: naive 3.09 ms, hset brute 570 µs, hset index
17.6 µs per query; the 1M-row hset builds in 0.43 s (KMEANS: 1.45 s) and
is 40.6 MiB, as with KMEANS. (First BISECT round, coalescing, loaded
machine: union 38.6 ms vs rebuild 346 ms, kNN 22.5 / 20.5 µs, index
19.5 µs, 40.3 MiB.)

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

**BISECT** (2026-10-23, second round, see the top of the page; the fresh
build no longer coalesces), N = 1M, hourly, T = 32, with the KMEANS run of
the first BISECT round for comparison (a loaded machine; its rows scanned
and list counts are identical to the first KMEANS run, its times are
not):

| C | build | 24 merges | 1 rebuild | lists merged / rebuilt | kNN merged / rebuilt | rows/query merged / rebuilt |
|---|---|---|---|---|---|---|
| 0 (none) | BISECT | 1.05 s | 0.44 s | 146K / 50K | 45.6 / 29.3 µs | 15.1K / 12.4K |
| 32 (T) | BISECT | 1.01 s | 0.45 s | 54K / 50K | 32.3 / 28.7 µs | 15.9K / 12.4K |
| **64 (2T)** | **BISECT** | **1.00 s** | **0.44 s** | **40K / 50K** | **29.6 / 28.9 µs** | **16.9K / 12.4K** |
| 128 (4T) | BISECT | 1.01 s | 0.45 s | 25K / 50K | 34.2 / 29.0 µs | 23.3K / 12.4K |
| 0 (none) | KMEANS | 1.13 s | 5.14 s | 146K / 50K | 54.8 / 34.4 µs | 15.1K / 12.6K |
| 32 (T) | KMEANS | 1.05 s | 4.58 s | 55K / 50K | 40.2 / 33.0 µs | 16.0K / 12.6K |
| 64 (2T) | KMEANS | 1.04 s | 4.50 s | 40K / 50K | 36.7 / 32.3 µs | 16.9K / 12.6K |
| 128 (4T) | KMEANS | 1.04 s | 4.46 s | 25K / 50K | 41.6 / 32.2 µs | 23.3K / 12.6K |

Daily, T = 32, C = 64: BISECT merges 0.72–0.78 s against a 2.24–2.53 s
rebuild (KMEANS, first BISECT round: 0.88 s against 31.3 s); 94K / 131K
lists merged / rebuilt (KMEANS 94K / 131K); 123–128 / 95 µs (KMEANS 161 /
120 µs on the loaded machine); rows scanned 56.7K / 31.7K (KMEANS 57.0K /
30.8K).

What changes with BISECT:

- One hourly rebuild (0.44 s) costs less than half the 24 hourly merges
  (1.0 s); the daily rebuild (2.2–2.5 s) costs about 3x the 7 daily merges
  (0.7–0.8 s), against 30x with KMEANS. A single merge (~42 ms hourly)
  stays ~10x cheaper than a rebuild.
- The merged indexes are nearly the same as with KMEANS (lists and rows
  scanned within 1%): after 24 or 7 merges most lists come from the
  batches and from coalescing, not from the master's build.
- The rebuilt index has as many lists as KMEANS's (50,381 against 50,378
  hourly, 131,274 against 131,172 daily) and scans 1.6% fewer rows hourly
  (12,386 against 12,586) and 2.9% more daily (31,668 against 30,776).
- The lists bound (merged ≤ rebuilt + nonempty cells) held in every
  configuration with C > 0, C = T included (e.g. hourly T = 32: 54,400 ≤
  50,381 + 9,704).
- C = 2T is the merged index's query-time minimum hourly at T = 32 in
  the rerun (29.6 µs, within 3% of the rebuilt 28.9 µs; C = T 32.3 µs,
  4T 34.2 µs); in the stalled full sweep 4T came out 1 µs ahead (35.3
  against 36.2 µs), within that run's noise. C = 2T remains the default.

With the coalescing fresh build of the first BISECT round (rejected), the
rebuilt index had 41K lists hourly and 104K daily, scanned 13.0K and
35.9K rows, and the bound failed in all six C = T configurations.

Full BISECT sweep, N = 1M (second round; hourly T = 16 and T = 32 from
the `MERGE_BENCH_T` reruns, the rest from the full sweep, whose hourly
part was stalled by memory pressure; see the top of the page):

| T  | C   | merges | rebuild | TIVF merged | TIVF rebuilt | lists merged | lists rebuilt | bound | kNN merged | kNN rebuilt | rows/q merged | rows/q rebuilt |
|----|-----|--------|---------|-------------|--------------|--------------|---------------|-------|------------|-------------|---------------|----------------|
| hourly | | | | | | | | | | | | |
| 16 | 0   | 1104 ms | 644 ms | 14369 KiB | 10278 KiB | 181,758 | 94,477 | - | 55.7 us | 43.2 us | 13,159 | 10,478 |
| 16 | 16  | 1091 ms | 653 ms | 10010 KiB | 10278 KiB | 88,762 | 94,477 | ok | 44.8 us | 43.9 us | 14,573 | 10,478 |
| 16 | 32  | 1078 ms | 649 ms | 8707 KiB | 10278 KiB | 60,960 | 94,477 | ok | 34.8 us | 42.9 us | 15,171 | 10,478 |
| 16 | 64  | 1087 ms | 644 ms | 7878 KiB | 10278 KiB | 43,293 | 94,477 | ok | 30.0 us | 42.9 us | 16,350 | 10,478 |
| 32 | 0   | 1049 ms | 437 ms | 12703 KiB | 8211 KiB | 146,227 | 50,381 | - | 45.6 us | 29.3 us | 15,073 | 12,386 |
| 32 | 32  | 1009 ms | 447 ms | 8399 KiB | 8211 KiB | 54,400 | 50,381 | ok | 32.3 us | 28.7 us | 15,898 | 12,386 |
| 32 | 64  | 995 ms | 440 ms | 7728 KiB | 8211 KiB | 40,094 | 50,381 | ok | 29.6 us | 28.9 us | 16,855 | 12,386 |
| 32 | 128 | 1005 ms | 449 ms | 7027 KiB | 8211 KiB | 25,130 | 50,381 | ok | 34.2 us | 29.0 us | 23,252 | 12,386 |
| 64 | 0   | 1034 ms | 303 ms | 11944 KiB | 7192 KiB | 130,033 | 28,643 | - | 43.4 us | 24.2 us | 19,031 | 15,776 |
| 64 | 64  | 984 ms | 314 ms | 7444 KiB | 7192 KiB | 34,027 | 28,643 | ok | 39.3 us | 29.7 us | 19,888 | 15,776 |
| 64 | 128 | 958 ms | 292 ms | 6975 KiB | 7192 KiB | 24,014 | 28,643 | ok | 33.3 us | 24.2 us | 23,779 | 15,776 |
| 64 | 256 | 986 ms | 298 ms | 6627 KiB | 7192 KiB | 16,588 | 28,643 | ok | 39.2 us | 28.7 us | 26,888 | 15,776 |
| daily | | | | | | | | | | | | |
| 16 | 0   | 845 ms | 3726 ms | 29656 KiB | 27998 KiB | 291,904 | 256,529 | - | 159.6 us | 103.0 us | 37,602 | 20,001 |
| 16 | 16  | 817 ms | 3710 ms | 26813 KiB | 27998 KiB | 231,248 | 256,529 | ok | 158.1 us | 100.4 us | 40,159 | 20,001 |
| 16 | 32  | 908 ms | 3749 ms | 23847 KiB | 27998 KiB | 167,982 | 256,529 | ok | 144.7 us | 122.8 us | 47,652 | 20,001 |
| 16 | 64  | 1077 ms | 3872 ms | 20870 KiB | 27998 KiB | 104,472 | 256,529 | ok | 129.7 us | 101.0 us | 55,374 | 20,001 |
| 32 | 0   | 748 ms | 2280 ms | 23983 KiB | 22127 KiB | 170,872 | 131,274 | - | 135.2 us | 97.7 us | 49,491 | 31,668 |
| 32 | 32  | 781 ms | 2312 ms | 22056 KiB | 22127 KiB | 129,773 | 131,274 | ok | 129.3 us | 94.6 us | 52,081 | 31,668 |
| 32 | 64  | 782 ms | 2525 ms | 20377 KiB | 22127 KiB | 93,946 | 131,274 | ok | 127.6 us | 94.7 us | 56,676 | 31,668 |
| 32 | 128 | 840 ms | 2362 ms | 18550 KiB | 22127 KiB | 54,977 | 131,274 | ok | 121.6 us | 94.3 us | 65,290 | 31,668 |
| 64 | 0   | 706 ms | 1406 ms | 21274 KiB | 19202 KiB | 113,077 | 68,879 | - | 141.9 us | 130.0 us | 59,256 | 40,650 |
| 64 | 64  | 710 ms | 1380 ms | 19497 KiB | 19202 KiB | 75,173 | 68,879 | ok | 146.4 us | 101.7 us | 60,925 | 40,650 |
| 64 | 128 | 715 ms | 1376 ms | 18357 KiB | 19202 KiB | 50,854 | 68,879 | ok | 122.3 us | 90.7 us | 66,330 | 40,650 |
| 64 | 256 | 732 ms | 1455 ms | 17438 KiB | 19202 KiB | 31,247 | 68,879 | ok | 121.1 us | 90.0 us | 70,179 | 40,650 |

"bound" is the benchmark's check lists merged ≤ lists rebuilt + nonempty
cells. The rebuilt index is the same in every C row of a T; its kNN time
varies between them by up to 43% (130.0 against 90.7 µs, daily T = 64),
which is this round's timing noise. The rerun of the daily T = 32 rows
gave merges 721–835 ms, rebuilds 2,203–2,257 ms and kNN 117.2–137.0 /
94.7–95.8 µs, with the same lists and rows.

## 8. Rebuild cost vs set size (T = 32, 15 threads)

Through the builder (sort, dedup, index build, file write;
`bench_hset_merge`'s "rebuild", and the 1M row is its master build):

| rows | KMEANS, first run | KMEANS, 2026-10-23 (loaded) | BISECT, 2026-10-23, no fresh coalescing |
|---|---|---|---|
| 1,000,000 | 1.45 s | 1.73–1.99 s | 0.41–0.43 s |
| 1,431,931 | 3.3 s | 4.46–5.14 s | 0.44–0.45 s |
| 4,023,698 | 24.5 s (T = 16: 48 s; T = 64: 8.5 s) | 29.8–33.0 s (T = 16: 61.1–62.1 s; T = 64: 9.8–10.1 s) | 2.20–2.53 s (T = 16: 3.71–4.32 s; T = 64: 1.38–1.46 s) |

(The KMEANS first-run 1M figure is Criterion's `rebuild_union` of 1.018M
rows.) The index build alone (`bench_tlsh`, its own corpus):

| rows | KMEANS | BISECT |
|---|---|---|
| 1,000,000 | 1,481 ms | 136 ms |
| 2,000,000 | – | 437 ms |
| 4,000,000 | 25,743 ms | 1,264–1,409 ms |

(The 1M BISECT row is the T = 32 run of the T sweep and the main run,
135.5 and 136.3 ms; the first BISECT round, which coalesced, took 152 /
498 / 1,618 ms.) KMEANS is superlinear: cost is dominated by the largest
header cells, each costing O(m² · d / T) for m rows (see
`docs/DESIGN_DECISIONS.md`, "Rebuild scaling"). BISECT is 11–20x faster;
its cost per row is one 256-coordinate dot product per centroid of the
row's flat node per round, and the centroids, ⌈s/T⌉, grow with the cell
size up to 128 at FLAT_MAX = 4096. With about 9,000–9,600 cells at every
size the row-weighted mean of min(⌈m_c/T⌉, 128) is 21.2 / 39.8 / 63.5
at 1M / 2M / 4M, which predicts 3.8x and 3.2x per doubling against the
measured 3.2x and 2.9x; above 4096 rows per cell the cost per row is
constant.

## 9. IVF build method: BISECT vs KMEANS

`bench_tlsh "tlsh_knn"`, T = 32, k = 10, max_distance = 144, 20 queries,
2026-10-23, second round (the fresh build no longer coalesces; see the
top of the page). BISECT `TLSH_BENCH_N=10000,100000` and
`1000000,2000000,4000000` in one process each, KMEANS 1M and 4M in one
process; the KMEANS rows at 10k and 100k are from the first round, on a
loaded machine. Build on all cores; query single thread; the query times
are the summary's minimum of repeated passes.

| rows | method | IVF build | lists | bounds/query | rows scanned/query | IVF query | cell index query |
|---|---|---|---|---|---|---|---|
| 10,000 | BISECT | 1.7 ms | 3,138 | 152 | 1,917 | 5.4 µs | 3.8 µs |
| 10,000 | KMEANS (1st round) | 2.1 ms | 3,138 | 152 | 1,920 | 6.3 µs | 3.8 µs |
| 100,000 | BISECT | 4.8 ms | 7,853 | 352 | 6,691 | 8.7 µs | 7.1 µs |
| 100,000 | KMEANS (1st round) | 18.5 ms | 7,853 | 352 | 6,757 | 10.2 µs | 8.8 µs |
| 1,000,000 | BISECT | 136 ms | 36,823 | 618 | 4,659 | 8.3 µs | 17.7 µs |
| 1,000,000 | KMEANS | 1,481 ms | 36,820 | 618 | 4,848 | 8.4 µs | 17.4 µs |
| 2,000,000 | BISECT | 437 ms | 67,728 | 866 | 4,557 | 10.1 µs | 24.8 µs |
| 4,000,000 | BISECT | 1,264 ms | 129,948 | 1,464 | 4,752 | 14.2 µs | 40.7 µs |
| 4,000,000 | KMEANS | 25,743 ms | 129,872 | 1,463 | 4,631 | 11.9 µs | 40.3 µs |

A rerun of BISECT at 4M gave 13.5 µs and 1,409 ms with the same lists and
rows. Catch2's mean per pass of 20 queries puts the two methods closer at
4M (225–229 µs BISECT, 220 µs KMEANS, so 11.3–11.5 against 11.0 µs per
query) and level at 1M (163 against 170 µs). BISECT now has the lists of
KMEANS at every size, scans 4% fewer rows at 1M and 2.6% more at 4M, at
a tenth to a twentieth of the build time. With the coalescing fresh build
of the first round (rejected) it had 31,668 / 46,179 / 76,993 lists and
scanned 5,110 / 5,900 / 7,501 rows at 1M / 2M / 4M (22.8 µs at 4M).

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
| 3 | flat k-means over exact integer centroids, coalescing at C = T | 5,110 | 8.6 µs (KMEANS 8.9) | 135 ms (KMEANS 1,467) | 31,668 lists against 36,820; radius 7.12 against 7.13; default since 2026-10-23 |
| 4 | the same without coalescing (BISECT today) | 4,659 | 8.3 µs (KMEANS 8.4) | 136 ms (KMEANS 1,481) | 36,823 lists against 36,820 |

**BISECT target list size T** (1M rows, `TLSH_BENCH_LIST=<T>`, second
round, one process per T; compare with section 4's KMEANS sweep for the
shape, not the times; "mean" is Catch2's mean per pass of 20 queries
divided by 20):

| T | lists | bounds/query | rows scanned/query | query (min) | query (mean) | build |
|---|---|---|---|---|---|---|
| 16 | 67,350 | 1,205 | 3,142 | 9.2 µs | 7.9 µs | 239 ms |
| 32 | 36,823 | 618 | 4,659 | 8.9 µs | 8.2 µs | 136 ms |
| 64 | 21,569 | 326 | 7,729 | 11.5 µs | 11.1 µs | 92 ms |
| 128 | 14,283 | 180 | 11,928 | 15.5 µs | 15.4 µs | 65 ms |
| 256 | 10,971 | 109 | 15,622 | 18.3 µs | 18.3 µs | 45 ms |

T = 16 and T = 32 are within 4% of each other (T = 32 ahead by the
minimum, T = 16 by the mean); T = 16 scans a third fewer rows but
evaluates twice the bounds and builds in 1.8x the time with 1.8x the
lists, so T = 32 stays. (First round, coalescing: 46,525 / 31,668 /
20,801 / 13,825 / 10,825 lists and 4,091 / 5,110 / 8,021 / 12,658 /
15,965 rows scanned.)
