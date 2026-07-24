# libhasher lookup benchmarks

A small, self-contained benchmark for the hash-set lookup path. It generates
synthetic sorted sets in memory (no external `.hset` files needed) and compares
lookup strategies, validating each against a `std::binary_search` ground truth
before timing.

Uniform-random hashes are a faithful model of real corpora (NSRL, VirusShare):
cryptographic hashes are uniformly distributed, which is exactly the assumption
the `expected_index` predictor relies on, so the observed deviation windows
match those seen on real data.

## Build & run

From the repository root (needs only `expected_index` from the library, so it
does not require the full library link):

```sh
g++ -O3 -march=native -std=c++17 -Iinclude -Ibench \
    bench/bench_lookup.cpp src/lib/hashset/util.cpp -o bench/bench_lookup

bench/bench_lookup 10000000     # set size (default 10,000,000)
```

## Frozen leaderboard eval driver

Runs the full candidate bar (c0-basic, c1-block256, phmap, unordered) across
synthetic held-out, adversarial, and real NSRL datasets. Numbers from this
driver are authoritative; see `bench/RESULTS.md` for fixed seeds and CPU info.

```sh
g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/bench_eval
taskset -c 2 bench/bench_eval 10000000
```

`-march=native` lets the compiler emit `bswap`/`prefetch`; the code is portable
and also builds without it (a scalar fallback path).

### Profiling: gprof call-graph time

Build with `-pg` to collect call-graph information on a single candidate:

```sh
g++ -O3 -march=native -std=c++17 -pg -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/bench_eval_pg
EVAL_ONLY=c1-block256 taskset -c 2 bench/bench_eval_pg 10000000
gprof bench/bench_eval_pg gmon.out | head -40
```

The `EVAL_ONLY` env var (set via `bench/run_perf.sh` or manually) filters the
candidate set to a single entry, isolating its time.

### Instrumented probe counters

Build with `-DHASHER_PROBE` to measure memory-system-independent counters
(element touches, comparisons) rather than hardware events:

```sh
g++ -O3 -march=native -std=c++17 -DHASHER_PROBE -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/bench_eval_probe
EVAL_ONLY=c1-block256 taskset -c 2 bench/bench_eval_probe 10000000
```

Probe output is printed to stdout and provides a cross-check on hardware perf
counters. Note: `LLC-load-misses` may read `<not supported>` in VMs; probe
counters are a machine-independent alternative.

## What it measures

Three strategies, across workloads that vary batch size (4K vs 1M queries) and
hit ratio (all-miss / mixed / all-hit):

| column           | path exercised                                             |
|------------------|------------------------------------------------------------|
| `basic`          | `std::binary_search` over the whole set                    |
| `block256(ref)`  | `BlockLookupStrategy::contains()` — one hash at a time     |
| `block256.batch` | `BlockLookupStrategy::contains_batch()` — a batch at once   |

Numbers are ns/lookup (lower is better). Judge relative columns within one run:
absolute ns depend on the machine and on memory-system load.

## Results (Xeon E5645, single thread, N = 10,000,000)

Authoritative before/after (old vs new compared in the same process):

| set        | old `contains` | new `contains` | speedup | new `contains_batch` (1M) | speedup | batch @ 4K |
|------------|---------------:|---------------:|--------:|--------------------------:|--------:|-----------:|
| SHA-1 (20) |         606 ns |         441 ns |  1.37×  |                    187 ns |  3.2×   | 154 (1.8×) |
| MD5 (16)   |         510 ns |         376 ns |  1.36×  |                    159 ns |  3.2×   | 150 (1.7×) |

### Where the speedups come from

* **`contains()` (1.35×)** — the inner search now does a *branchless*
  `lower_bound` (no ~50%-mispredicted data-dependent branch on random keys) and
  compares the leading 8 bytes of each hash as a single big-endian integer
  instead of a byte-by-byte `std::array` compare (the first 8 bytes decide
  ~99.99% of uniform-hash comparisons). See `include/hashset/hash_compare.h`.

* **`contains_batch()` (3.2×)** — a single lookup is a chain of ~8 dependent
  cache misses, so it is latency-bound and leaves the memory system idle. The
  batch path keeps `D = 32` lookups in flight, advancing each by one probe per
  round and software-prefetching each lane's next probe, so up to `D` misses
  overlap (memory-level parallelism). This is the big win for the "lots of
  hashes against a big set" case (NSRL, VirusTotal-style). Sorting the query
  batch first was tried and did **not** pay off — the sort cost exceeds the
  marginal locality gain for these already-narrow windows.

## Files

* `harness.h`    — data generation, workloads, timing, and the validate+compare
  suite. Every candidate is checked against ground truth before timing.
* `reference.h`  — builds the real library strategies and the block bounds.
* `bench_lookup.cpp` — the driver.
