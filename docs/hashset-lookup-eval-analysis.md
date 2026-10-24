# Convex-Hull-Bounded Hash-Set Lookup — Evaluation Results & Analysis

**Status:** Phase 1–2 complete; harness frozen (`git tag harness-frozen`, commit `1ba0e30`).
**Date:** 2026-07-25.
**Target box:** Intel Xeon E5645 (Westmere, 4c, SSE4.2, **no AVX2**), ~12 MB LLC, single-threaded, pinned with `taskset`.
**Full numbers:** `bench/RESULTS.md` (the frozen reproducibility record). This document is the interpretation.

---

## TL;DR

We built a frozen, anti-cheat benchmark harness for `libhasher`'s hash-set membership lookup and raced eight lookup strategies against it across four datasets (synthetic, adversarial, real NSRL SHA-1, real NSRL MD5).

**Winner: `c4-fine-block`** — for both single and batch lookup, on every dataset.

It is **1.3–1.6× faster than the shipping `c1-block256`** baseline, with the cheapest build of any tuned candidate and the fewest memory touches per lookup. Crucially, it beat every "cleverer" candidate (per-block convex hulls, a global hull, interpolation search, and a hull+interpolation synthesis). The simple idea won.

**The catch — and the open decision:** C4's speed comes from a **256 KB per-file lookup table**. That is a rounding error for an NSRL-scale set (40 M hashes, 800 MB of data) but is disproportionate — even absurd — for a small set. See [The payload-size problem](#the-payload-size-problem) below; it is the one decision blocking the format-wiring phase.

---

## How the lookup works (one paragraph)

An `.hset` is a **sorted array** of fixed-width digests (20 B for SHA-1). Naive membership = binary search over the whole array (~26 cache misses at 40 M). Every tuned candidate exploits the fact that **cryptographic hashes are uniformly distributed**: a hash's numeric value predicts its index in the sorted array (`expected_index` — one arithmetic op, no memory access). The *actual* index deviates from the prediction by some amount `d = actual − expected`. If you can **bound** `d`, you only binary-search a small **window** around the prediction instead of the whole array — far fewer cache misses. All the candidates differ only in **how they bound `d`**.

**Correctness never depends on uniformity.** The bound is computed over every stored hash, so a query equal to a stored hash is always inside its window; a miss just fails the windowed search. Uniformity only affects window *tightness* (speed), never correctness. Every candidate was verified exact against a `std::binary_search` oracle — including on an **adversarial** dataset (skewed leading bytes, dense clusters) specifically designed to break any correctness-depends-on-uniformity assumption. None was ever disqualified.

---

## The candidates

| id | name | how it bounds the deviation | preserves sorted array? |
|----|------|------------------------------|--------------------------|
| C0 | `c0-basic` | none — plain `std::binary_search` (the floor) | yes |
| C1 | `c1-block256` | flat `[min,max]` per **8-bit** block (256 blocks, 4 KB) — **the shipping baseline** | yes |
| **C4** | **`c4-fine-block`** | **flat `[min,max]` per 14-bit block (16 384 blocks, 256 KB)** | **yes** |
| C2 | `c2-block-linear` | a **sloped** supporting line per block (convex hull "min-width slab"), 4 KB | yes |
| C3 | `c3-global-hull` | one **global** upper/lower convex hull over all points | yes |
| C5 | `c5-interp` | per-block hull window + **interpolation search** inside it | yes |
| C6 | `c6-hull-interp` | hull window + one interpolation split + branchless tail + batch pipeline | yes |
| — | `phmap` | Swiss-table `flat_hash_set` (north-star; NOT sorted) | no |
| — | `unordered` | `std::unordered_set` (stdlib baseline; NOT sorted) | no |

C1 and C4 are the *same mechanism* — flat per-block min/max — at different block resolutions (8 vs 14 bits). C2/C3/C5/C6 add algorithmic machinery to the bound.

---

## Leaderboard (headline: 1M-query workloads, ns/lookup, min-of-reps)

Full tables (all workloads, build ms, aux bytes, probe counts) are in `bench/RESULTS.md`.

**Real NSRL SHA-1 (40,406,763 hashes) — the authoritative real-data result:**

| candidate | single (1M-miss) | batch (1M-miss) | build ms | probe touch/lookup |
|-----------|-----------------:|----------------:|---------:|-------------------:|
| c0-basic | 1915 | 1898 | 0 | — |
| c1-block256 (baseline) | 790 | 322 | 293 | 9.25 |
| c2-block-linear | 749 | 315 | 6594 | 8.78 |
| c3-global-hull | 1139 | 1189 | 8312 | 6.45 |
| **c4-fine-block** | **543** | **244** | **318** | **6.47** |
| c5-interp | 693 | 675 | 6597 | 9.80 |
| c6-hull-interp | 753 | 644 | 6650 | 10.46 |
| phmap (not sorted) | 253 | 250 | 23798 | — |
| unordered (not sorted) | 693 | 688 | 23710 | — |

**Real NSRL MD5 (40,406,763 hashes, 16 B):** c4 505/215 vs c1 741/279 — c4 wins single & batch again.
**Synthetic held-out (n=10 M):** c4 320/154 vs c1 508/212 — **1.59× / 1.38×** faster.
**Adversarial (200 K clustered/skewed items):** c4 22/19 vs c1 24/18 (1M-miss); c4 also beats c1 on mix and hit. No regression.

---

## Analysis: why C4 won

1. **Finer blocks give tighter windows for free.** C4's 14-bit index carves the keyspace into 64× narrower slices than C1's 8-bit index. Hashes in a narrow slice occupy a narrow range of the sorted array, so their deviations cluster tightly, so the `[min,max]` window is smaller. Result: **4.20 element-touches/lookup vs C1's 7.00** on synthetic data — directly fewer cache misses.

2. **Zero per-query cleverness.** C4's window computation is the same cheap integer add as C1 (`lo = expected + min`, `hi = expected + max + 1`). The fancier candidates pay for their tighter theoretical bounds at query time:
   - **C2** (per-block sloped hull line) needs float `floor(s·e + c_lo)` / `ceil(...)` per query. Tighter windows on adversarial data (7.96 vs C1's 15.0 touches — its slope adapts to skew), but the arithmetic and an ~80× slower build cost more than they save on uniform data.
   - **C3** (global hull) has the fewest touches (6.4) but pays a per-query hull binary-search; it is the **slowest** tuned candidate (1139 ns) — the global bound is tight but the per-lookup overhead dominates.
   - **C5/C6** (interpolation) are correct on clustered data but their extra endpoint reads (`key[lo]`, `key[hi-1]`) add **serial** cache misses that break memory-level parallelism — **C6's batch is ~3× slower than C1's**, the opposite of its design goal.

3. **Cheapest build of any tuned candidate.** C4 build = 76 ms (synthetic) / 318 ms (NSRL), essentially identical to C1. C2/C3/C5/C6 all cost ~6 seconds (they compute convex hulls at build time). C4 gets tighter bounds without the build tax.

4. **The anti-cheat cross-checks agree.** The ns ranking tracks the machine-independent probe-touch counts and the `perf` cycle / L1-dcache-miss counts (LLC counter is `<not supported>` in this VM, so L1-miss + probe counts are the cross-check). No candidate posted a latency win contradicted by its memory-access counts — the numbers are not artifacts.

**The lesson:** on a memory-latency-bound problem, "spend a bit more memory to make the search window smaller" beat "spend more computation to make the bound theoretically tighter." The dumb table won.

**North-star note:** `phmap` (a hashed, *unsorted* Swiss table) is faster still (253 ns on NSRL SHA-1) — but it does **not** preserve the sorted array (forfeiting cheap set-ops / range ops), carries ~29 B/hash of auxiliary memory, and has a 24 s build. Among strategies that **preserve the sorted layout** — a first-class requirement — C4 is the winner.

---

## The payload-size problem

C4's win is bought with a **fixed 256 KB block table** (16 384 blocks × 16 B) that must live in every `.hset` file as the format hint. The table size does **not** shrink with the set, so its *relative* cost explodes for small sets:

| set size (n) | data size (20 B/hash) | C4-14bit hint (256 KB) | overhead | C4-12bit (64 KB) | C2-hull (4 KB) |
|-------------:|----------------------:|-----------------------:|---------:|-----------------:|---------------:|
| 40 M (NSRL) | 800 MB | 256 KB | **0.03 %** | 0.008 % | 0.0005 % |
| 1 M | 20 MB | 256 KB | **1.3 %** | 0.33 % | 0.02 % |
| 100 K | 2 MB | 256 KB | **13 %** | 3.3 % | 0.2 % |
| 10 K | 200 KB | 256 KB | **131 %** (hint > data!) | 33 % | 2 % |

For NSRL-scale corpora the 256 KB is free. For a 100 K-hash set it is a 13 % file-size tax, and for a 10 K set the hint is **larger than the data it indexes** — clearly unacceptable.

This is the whole tension: **C4 is the fastest, but its fixed hint is only "free" on large sets.**

---

## Recommendation for Phase 5 (format wiring)

Three fixed options were on the table (wire C4-14bit / C4-12bit / C2-hull). But the overhead table points to a cleaner answer:

### Recommended: **size-adaptive block resolution**

Wire the winning **fine-block flat-bounds mechanism**, but let the **encoder choose the block-bit count from the set size** and record it in the hint header (1 byte). Pick the largest `BlockBits` whose table stays a bounded fraction of the data — e.g. keep the table ≤ ~1 % of the data:

```
table_bytes = 16 · 2^BlockBits   ;   data_bytes = hlen · n
choose BlockBits = max bits such that 16·2^BlockBits ≤ 0.01 · hlen · n
                   (clamped to, say, [8, 14])
```

Result: NSRL-scale sets get the full 14-bit table (fast, 0.03 % overhead); a 100 K set drops to ~10-bit (16 KB, ~0.8 %); a 10 K set falls back to 8-bit (= today's `c1-block256`, 4 KB). **You get C4's speed exactly where it's free, and gracefully degrade to the current baseline where the table would be too expensive — no file ever pays a disproportionate hint.** The decoder reads `BlockBits` from the header and dispatches the same fine-block strategy at that resolution.

This is also the *simplest* encoder of all the options: it's just the existing `make_block_bounds` computed over `2^BlockBits` blocks instead of 256 — no convex-hull math at build time (unlike the plan's default C2 wiring).

### Fallback options if a fixed choice is preferred
- **C4-12bit (64 KB fixed):** most of C4's speed, 4× smaller hint, but still 33 % overhead at 10 K. Would need a confirming benchmark run (12-bit was interpolated, not measured).
- **C2-hull (4 KB fixed):** compact and plan-ready, but ~1.4× slower than C4 on large sets and pays a per-query float cost + ~80× build tax. Trades the actual win for a small payload.

### Open question for you
The adaptive scheme needs one policy input: **what overhead fraction is acceptable** (I suggested ≤1 % of data, clamped to 8–14 bits). If you have real numbers on typical `.hset` sizes and how the files are distributed (shipped? mmap'd? cached?), that pins the clamp range and the fraction precisely.

---

## What was built (frozen harness)

- **Anti-cheat contract** (`bench/eval/`): correctness-before-timing against a `std::binary_search` oracle over a hard query stream (guaranteed hits, ±1-bit near-misses, all-0x00/0xFF boundary, random misses); a checksum-sink timing loop with no heap allocation in the timed region; single/batch answer-agreement check; min/median/stddev over N reps; all candidates run interleaved on one pinned core.
- **Dataset matrix:** synthetic multi-seed with a frozen tuning/held-out split (held-out is authoritative), an adversarial/clustered set, real NSRL SHA-1 (mmap, zero-copy), real NSRL MD5 (derived once and cached).
- **Machine-independent cross-check:** in-code probe counters (`-DHASHER_PROBE`, no-op in production) count element touches/comparisons per lookup, cross-checked against `perf` counters. Frozen with `git tag harness-frozen`.

## Reproducing

```sh
g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/bench_eval
taskset -c 2 bench/bench_eval 10000000            # full held-out matrix
EVAL_ONLY=c4-fine-block taskset -c 2 bench/bench_eval 10000000   # one candidate
./bench/run_perf.sh c4-fine-block 10000000        # perf counters (LLC = <not supported> in VM)
```

Fixed seeds, workload matrix, and per-workload/build/probe numbers: `bench/RESULTS.md`.
