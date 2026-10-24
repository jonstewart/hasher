# libhasher lookup benchmarks

> **HARNESS FROZEN — 2026-07-24**
> The harness, datasets, seeds, and anti-cheat contract are fixed.
> Subagents may only *add* candidate files (`bench/candidates/*.h` + one `registry.h` line).
> No changes to the eval driver (`bench/eval.cpp`), datasets, seeds, or workload matrix.

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

Runs all 9 candidates (c0–c6, phmap, unordered) across synthetic held-out,
adversarial, and real NSRL datasets. Numbers from this driver are authoritative;
see `bench/RESULTS.md` for fixed seeds, CPU info, and the full leaderboard.

```sh
g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/bench_eval
taskset -c 2 bench/bench_eval 10000000
```

Winner (2026-07-24): **c4-fine-block** — fastest single AND batch across all datasets.
- Synthetic held-out n=10M, 1M-miss: 320 ns single / 154 ns batch (vs c1-block256: 508 / 212 ns)
- NSRL SHA-1 1M-miss: 543 ns single / 244 ns batch (vs c1: 790 / 322 ns)
- NSRL MD5 1M-miss: 505 ns single / 215 ns batch (vs c1: 741 / 279 ns)

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

> **Superseded**: see `bench/RESULTS.md` for the full frozen leaderboard (all 9 candidates,
> all 4 datasets). The table below is the original before/after from an earlier development phase.

Historical before/after (c1-block256 vs original `std::binary_search`):

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

## vs_lookup_eval: per-query lookup timings against a real hset

`vs_lookup_eval.cpp` times single SHA-256 lookups through the client API,
`sfhash_hashset_lookup` on the hset's sha256 hash set (the BlockLookupStrategy
the decoder builds from the file's hint), one query at a time, and writes every
timing to a CSV for DuckDB. It was written for the VirusShare hset (records
plus md5/sha1/sha256/tlsh hash sets) but runs on any hset with a sha256 hash
set; a records-only file is refused. Unlike the frozen harness above it reads
a real `.hset` and measures what clients get.

```sh
make bench/vs_lookup_eval
H=vs.hset
taskset -c 3 bench/vs_lookup_eval export   $H --out sha256.txt            # --seed S, --unique
taskset -c 3 bench/vs_lookup_eval found    $H --list sha256.txt --csv found.csv
taskset -c 3 bench/vs_lookup_eval notfound $H --list sha256.txt --csv notfound.csv  # --seed S, --count N
```

* `export` writes every row of the sha256 hash set as lowercase hex, one per
  line, shuffled by `std::shuffle` with `std::mt19937_64(seed)` (default seed
  `0x56534c4b55500001`, printed and recorded). With records the hash set has
  one row per record, so a SHA-256 shared by records that differ in other
  fields appears more than once; the duplicate count and the record count are
  reported (`--unique` drops the duplicates).
* `found` looks up every hash of the list, each in its own timed region, and
  stops with exit status 2 at the first miss, printing the hash and its
  0-based position in the list. `--limit K` queries only the first K.
* `notfound` looks up `--count` (10,000) uniformly random SHA-256 values,
  32 bytes from `std::mt19937_64(seed)`, the seed from `std::random_device`
  unless `--seed` is given (printed and recorded either way). Every query is
  checked against the exported list: a hit in the list is a genuine collision
  (recorded, exit 0), a hit not in the list or a list member that was not found
  is a lookup bug (exit 2). Without `--list`, any hit exits 2.
  `--inject-hits K` overwrites K queries with stored hashes to exercise those
  paths.

Before a timed pass the file is read sequentially `--warm-reads N` times
(default 3; 16 MiB `pread`s, MiB/s per pass printed, so the first pass shows
whether the file was cached), every page of the library's read-only mapping is
touched once (no page faults during timing), the file size is compared with
MemAvailable (a warning above 80%), and `--warmup-queries M` (default 100,000,
`all` for the whole list) untimed lookups run: sampled from the list for
`found`, other random values for `notfound`. After the per-query pass an
aggregate pass times the whole query set as one region, a mean free of the
per-query timer cost; `--catch-bench K` adds a Catch2 `BENCHMARK` over K
sampled queries as a further cross-check.

The timer is `std::chrono::steady_clock` (vDSO `clock_gettime`, the `tsc`
clocksource on this VM) or, with `--timer rdtscp`, `lfence; rdtsc; lfence`
... `rdtscp; lfence` with the TSC rate calibrated against steady_clock (the
CPU has `constant_tsc` and `nonstop_tsc`). The overhead of an empty timed
region (1M repetitions) is printed and recorded; the CSV's `ns` is the raw
interval and includes it.

Outputs:

* the CSV, `i,sha256,found,ns`: query position, lowercase hex, 0/1, and ns
  (an integer for steady_clock, two decimals for rdtscp). For example
  `duckdb -c "select count(*), avg(ns), quantile_disc(ns, [0.5, 0.9, 0.99, 0.999]), max(ns) from 'found.csv'"`;
  the program's percentiles are the sorted sample's element floor(q (n - 1)),
  which is `quantile_disc`, and its stddev is the sample stddev (`stddev_samp`).
* `<csv>.meta.json` (`--meta` to change; `<list>.meta.json` for `export`):
  hset path, size and name, sha256 and record counts, seeds, warm-up settings
  and times, MemAvailable, the timer and its overhead, CPU model, affinity,
  clocksource, load average, the date, and the summary statistics
  (n, mean, median, stddev, p90, p99, p99.9, min, max) and wall times.

Run it single-threaded and pinned: `taskset -c N`, with N a CPU nothing else
is pinned to; the program warns when its affinity mask has more than one CPU.

Also before a timed pass, `--noise-secs S` (default 2) reads the clock back to
back for S seconds and counts the gaps, the times the CPU was taken away; the
pass itself records the pinned CPU's `/proc/stat` deltas (irq, softirq, steal)
and the process's page faults and context switches. On this VM every CPU loses
5-20 us about 1,250-1,700 times a second (the 1000 Hz tick, CONFIG_HZ=1000,
plus other interrupts and VM exits), so about 0.1% of queries carry one
(7,692 of 9M over 10 us in the steady_clock run below): p99 and below measure
the lookup, p99.9 sits on the edge of the interference (1.8 us in one run,
15.6 us in the next) and max measures the platform.

First numbers (2026-10-24, Xeon E5645 VM, `taskset -c 3`, other agents
running; synthetic hset of 9,000,000 random md5/sha1/sha256 records built by
mkhashset in 2 min 20 s and 1.4 GB of RSS, a 1.37 GiB file, cached):

| pass | n | mean | median | stddev | p90 | p99 | p99.9 | max | aggregate mean |
|------|--:|-----:|-------:|-------:|----:|----:|------:|----:|---------------:|
| found, steady_clock | 9,000,000 | 682 | 642 | 1,620 | 907 | 1,182 | 1,753 | 4.3 ms | 606 |
| found, rdtscp | 9,000,000 | 792 | 754 | 2,610 | 1,046 | 1,338 | 15,575 | 4.8 ms | 677 |
| notfound, steady_clock | 10,000 | 814 | 774 | 793 | 1,078 | 1,349 | 18,735 | 30 us | 642 |

ns per query, raw (the timer's overhead included: 28-30 ns median for
steady_clock, 21.7 ns for rdtscp). The two found rows differ by more than the
timers do; the aggregate passes, which have no per-query timer, differ by the
same 10%, so that is run-to-run variation on a shared box. The export takes
5 s, a found run under a minute (reading the list 9 s, the pass 6.4 s, the
aggregate pass 5.4 s, the 710 MB CSV 8.5 s), and the notfound check against
the sorted list 13.5 s.

## Files

* `eval.cpp`             — frozen eval driver (all 9 candidates, 4 datasets, fixed seeds)
* `eval/suite.h`         — `run_leaderboard()` timing harness
* `eval/datasets.h`      — NSRL SHA-1/MD5 loading (mmap + derived cache)
* `eval/candidate.h`     — candidate interface
* `candidates/registry.h` — candidate instantiation + EVAL_ONLY filter
* `candidates/c0_basic.h` through `c6_hull_interp.h` — the 7 sorted-array candidates
* `candidates/ext_phmap.h`, `ext_unordered.h` — hash-set north-star / baseline
* `run_perf.sh`          — perf stat runner (EVAL_ONLY + taskset + hardware counters)
* `RESULTS.md`           — frozen leaderboard, seeds, environment, winner declaration
* `harness.h`            — (legacy) data generation for `bench_lookup.cpp`
* `bench_lookup.cpp`     — (legacy) standalone benchmark driver
* `vs_lookup_eval.cpp`   — per-query lookup eval against a real hset (`make bench/vs_lookup_eval`)
