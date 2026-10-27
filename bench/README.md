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
bench/vs_lookup_eval export   $H --out sha256.txt            # --seed S, --unique
bench/vs_lookup_eval found    $H --list sha256.txt --csv found.csv
bench/vs_lookup_eval notfound $H --list sha256.txt --csv notfound.csv  # --seed S, --count N
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
clocksource on this VM). The overhead of an empty timed region (1M
repetitions) is printed and recorded; the CSV's `ns` is the raw interval and
includes it.

Outputs:

* the CSV, `i,sha256,found,ns`: query position, lowercase hex, 0/1, and ns
  (an integer). For example
  `duckdb -c "select count(*), avg(ns), quantile_disc(ns, [0.5, 0.9, 0.99, 0.999]), max(ns) from 'found.csv'"`;
  the program's percentiles are the sorted sample's element floor(q (n - 1)),
  which is `quantile_disc`, and its stddev is the sample stddev (`stddev_samp`).
* `<csv>.meta.json` (`--meta` to change; `<list>.meta.json` for `export`):
  hset path, size and name, sha256 and record counts, seeds, warm-up settings
  and times, MemAvailable, the timer and its overhead, CPU model,
  clocksource, load average, the date, and the summary statistics
  (n, mean, median, stddev, p90, p99, p99.9, min, max) and wall times.

Also before a timed pass, `--noise-secs S` (default 2) reads the clock back to
back for S seconds and counts the gaps, the times the CPU was taken away; the
pass itself records the process's page faults and context switches. On this VM every CPU loses
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
| found, rdtscp (a since-removed option) | 9,000,000 | 792 | 754 | 2,610 | 1,046 | 1,338 | 15,575 | 4.8 ms | 677 |
| notfound, steady_clock | 10,000 | 814 | 774 | 793 | 1,078 | 1,349 | 18,735 | 30 us | 642 |

ns per query, raw (the timer's overhead included: 28-30 ns median for
steady_clock, 21.7 ns for rdtscp). The two found rows differ by more than the
timers do; the aggregate passes, which have no per-query timer, differ by the
same 10%, so that is run-to-run variation on a shared box. The export takes
5 s, a found run under a minute (reading the list 9 s, the pass 6.4 s, the
aggregate pass 5.4 s, the 710 MB CSV 8.5 s), and the notfound check against
the sorted list 13.5 s.

## vs_knn_eval: TLSH kNN eval against a real hset

`vs_knn_eval.cpp` times TLSH k-nearest-neighbour queries one at a time against
the TLSH hash set of an hset with a `TIVF` index (the VirusShare hset, or a
synthetic one), with three methods per query:

* `brute`: `sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_BRUTE)`, every
  row, exact; the TLSH ground truth.
* `index`: `sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_INDEX)`, the
  `TIVF` search, exact (docs/TLSH_EMBEDDING.md section 4).
* `embed`: approximate kNN in embedding space, CrowdStrike style:
  `sfhash_tlsh_embed` of the query, squared Euclidean distance to every row's
  embedding (all 264 dims, the length dim only with `--include-length true`),
  top k in a bounded max-heap on (dist2, row), so ties go to the lower row.
  The distance is a plain loop with float reassociation allowed for that one
  function, so that GCC vectorizes it (SSE here); `--embed-kernel lib` uses
  the library's strictly ordered, scalar `sfhash_tlsh_embed_dist2` instead
  (about 2.5x slower per row). hset files do not store the embeddings (the
  `TVEC` chunk was removed, docs/DESIGN_DECISIONS.md), so the driver computes
  every row's embedding with `sfhash_tlsh_embed` into a 4096-aligned
  n x 264 float32 matrix in memory (1,056 bytes per row) before the timed
  passes, untimed and on `--threads` threads; it is computed only when the
  `embed` method or the deep ranking (`--deep-k`) needs it, and its time is
  `hset.embed_seconds` in `run.json`. The outputs are the same as with the
  stored matrix: on a 5,000-row hset, queries, results, deep and hist CSVs
  were byte-identical to a run of the previous driver over the same file
  with a `TVEC` chunk added. Budget memory for the matrix on top of the
  hset: a run that used the stored matrix had it in the mapped file instead.

Two query sets of `--queries` (1,000) each: `member`, rows sampled uniformly
without replacement from the non-null rows (the query is that row's digest),
and `random`, uniformly random valid digests (uniform L byte, Q1/Q2 nibbles,
checksum byte and 128 2-bit codes; reserved byte 0; never the null digest;
each round-trips through `sfhash_tlsh_to_hex` / `sfhash_tlsh_from_hex`), which
stand in for client queries not in the set. Both use `std::mt19937_64` with
fixed, recorded seeds (`--member-seed`, `--random-seed`).

```sh
make bench/vs_knn_eval
bench/vs_knn_eval --hset vs.hset --out knn-out
# defaults: --k 100 --max-distance unbounded --include-length true
#           --queries 1000 --warm-reads 3 --warmup 50 --deep-k 1000
```

Timing. Before anything is timed, the file is read sequentially `--warm-reads`
times (MiB/s per pass printed: the first pass shows whether it was cached),
then mapped, and the size is printed against MemAvailable, with a warning
when it does not fit. The passes run per set, per method (all 1,000 queries
of one method in a row, each method warmed by `--warmup` untimed queries of
that set, drawn with `--warmup-seed` apart from the measured ones). Each query is timed alone with
`steady_clock` around the kNN call only (for `embed`: query embedding, scan
and heap). The timer overhead (an empty region, 1M repetitions) is recorded
and not subtracted. The timing thread is single-threaded.

Analysis pass (untimed, after the timed passes, `--threads`, default all CPUs,
eight queries per scan): for every query, the TLSH distance of every row (a
histogram), and the embedding ranking to depth `--deep-k` with the same
distance function as the timed `embed` (its top k is checked to be a prefix).
`--no-analysis` skips it.

Outputs in `--out` (CSV with a header; `read_csv_auto` in DuckDB; ranks are
1-based, rows are TLSH hash-set row indexes, usable with
`sfhash_hashset_hash` and the record map):

| file | columns |
|------|---------|
| `queries.csv` | `qset, qid, digest` (T1 hex), `lval` (L byte), `source_row` (empty for random), `n_identical` (rows with this exact digest, the query's own row included), `d_k` (k-th smallest TLSH distance), `count_lt` / `count_le` (rows with distance < / <= `d_k`), `index_exact` (brute and index results identical) |
| `timings.csv` | `qset, qid, method, ns, n_results, ivf_cells, ivf_lists, ivf_rows` (index only: header cells visited, list bounds evaluated, rows scanned; from a second, untimed run of the same search) |
| `results.csv` | `qset, qid, method, rank, row_idx, tlsh_dist, emb_dist2` (`tlsh_dist` from `sfhash_tlsh_diff` with the length setting, computed after timing; `emb_dist2` with the embed kernel, for all three methods) |
| `deep.csv` | `qset, qid, rank, row_idx, emb_dist2, tlsh_dist`: embedding top `--deep-k` |
| `hist.csv` | `qset, qid, tlsh_dist, n_rows`: the full distance histogram, nonzero bins (`--no-hist` to skip) |
| `run.json` | hset path, size, name, rows, null rows, lists, row-embedding seconds; parameters; seeds (hex strings); warm-up passes and settings; timer overhead; CPU, MemTotal/MemAvailable; date, git commit, argv; per pass n/mean/median/stddev/p99/max/min in us; checks |
| `summary.txt` | the printed summary |

With ties at the k-th distance (identical digests are common in real
malware), a tie-aware relevance is `tlsh_dist <= d_k`: any k rows with
distance at most `d_k` are a correct answer, `count_le` rows qualify, and
`count_lt` of them must be in every correct answer. p99 is nearest-rank
(`quantile_disc(ns, 0.99)`), stddev the sample stddev.

The summary prints, per set and method, mean, median, stddev, p99, max and min
in us and ns per row; per set the brute/index mismatches (flagged loudly; the
run continues and exits with status 3) and the mean recall@k of embed against
brute, naive (row overlap) and tie-aware. It also warns if the library's
distances disagree with `sfhash_tlsh_diff`, if brute's k-th distance disagrees
with the histogram, or if the embed top k is not the prefix of the deep
ranking. For example, recall@100 in SQL:

```sql
create view q as from 'knn-out/queries.csv';
create view r as from 'knn-out/results.csv';
select e.qset, avg(hit) as recall_naive, avg((e.tlsh_dist <= q.d_k)::int) as recall_tie
from (select e.*, exists (select 1 from r b where b.method = 'brute' and b.qset = e.qset
        and b.qid = e.qid and b.row_idx = e.row_idx)::int as hit
      from r e where e.method = 'embed') e
join q using (qset, qid) group by e.qset;
```

Synthetic check (2026-10-24, Xeon E5645, timing thread pinned to CPU 2 with a
since-removed option, other work on the VM; `make_tlsh_corpus` digests plus
15% exact duplicates, built by `mkhashset ... md5 tlsh true true`; mean us per
query, member / random):

| rows | queries/set | brute | index | embed | embed recall@100 naive / tie-aware | brute/index mismatches | wall |
|------|-------------|-------|-------|-------|------------------------------------|------------------------|------|
| 100k | 1,000 | 2,876 / 3,143 | 1,485 / 1,871 | 22,492 / 22,956 | 0.780 / 0.787, 0.230 / 0.239 | 0 | 71 s |
| 1M | 1,000 | 22,899 / 31,476 | 1,807 / 15,209 | 202,479 / 237,480 | 0.904 / 0.919, 0.210 / 0.220 | 0 | 602 s |
| 4M | 200 | 119,373 / 141,308 | 1,005 / 33,177 | 897,950 / 874,696 | 0.945 / 0.990, 0.132 / 0.140 | 0 | 510 s |

Brute costs 23-35 ns per row and embed 200-240 ns per row (1,056 bytes of
floats per row, single-threaded, memory-bound), so at 9M rows a query costs
about 0.3 s and 2 s, and the default run (2 sets x 1,000 queries x 3 methods,
warm-ups and the analysis pass included) takes about 1.6-1.8 hours, most of
it in embed. The library is built for baseline x86-64 (no `-mpopcnt`), so
brute and index count bits without the POPCNT instruction this CPU has.

## vs_report: DuckDB analysis and HTML report for the two evals

`vs_report/vs_report.py` loads a `vs_knn_eval` output directory and the
`vs_lookup_eval` found / notfound CSVs (with their `.meta.json`) into a DuckDB
file, computes the latency and information-retrieval metrics in SQL
(`vs_report/sql/*.sql`), and writes a static, self-contained HTML report
(inline SVG charts, no scripts, no network) whose prose is filled in from the
numbers, with `[TO FINISH]` markers where a human judgement is needed. Python
standard library only, DuckDB through its CLI.

```sh
python3 -I bench/vs_report/vs_report.py \
    --knn /work/vs-eval/knn \
    --found /work/vs-eval/lookup/lookup_found.csv \
    --notfound /work/vs-eval/lookup/lookup_notfound.csv \
    --out /work/vs-eval/report          # writes index.html and vs.duckdb
# --build-seconds S  extra build time of the TIVF index, for the break-even query count
# --synthetic        banner and caveat for a pipeline check
# --threads 4 --memory 8GB (DuckDB), --reuse-db (re-render from an existing --db)
# optional inputs:
#   --build-costs F    JSON: mkhashset builds with HSET_TLSH_OPTIONS 0 and 2
#   --judgements F     JSON {"q1": html, "q2": html}, the author's judgements
#   --corpus F         JSON: corpus counts for Methods
#   --knn-extra DIR    another vs_knn_eval run over the same queries at another k and/or
#                      --max-distance (brute and index; --no-analysis is fine); repeatable
#   --hset H           the evaluated hset: the header-split diagnostic (--libdir, default src/lib/.libs)
```

The optional inputs add to the report and change nothing without them; the
judgement and build-time placeholders stay marked `[TO FINISH]` then.
`--build-costs` is `{"description", "input_digests", "rows", "variants":
[{"name", "options", "wall_s", "user_s", "maxrss_kb", "bytes"}, ...],
"records_build": {"tool", "wall_s"}}`; TIVF is the variant with options 2
minus the one with 0, and the break-even uses the TIVF wall time unless
`--build-seconds` is given. Measurements from before the `TVEC` chunk was
removed (such as the VirusShare run's) also have a variant with options 1,
which wrote the vectors; the report shows it as TVEC when it is at least
1 KiB per row larger than the 0 build. A build today writes nothing for
bit 1, so there is no TVEC variant to measure. Likewise the report describes
the embed method's rows as the hset's `TVEC` rows for a run whose `run.json`
has `has_vectors` (vs_knn_eval before the removal) and as embeddings
computed in memory otherwise. `--corpus` is `{"name", "zips",
"entries", "records", "lost_zip", "lost_cause", "tnull", "distinct_tlsh",
"duplicate_sha256", "notes": [html, ...]}` and is checked against the hset's
TLSH rows and the lookup's SHA-256 count. `--hset` runs
`vs_report/header_split.py` (libhasher through the repo's `python/`
package), which splits the TLSH distance of embed's results and of brute's
results that embed missed into the header terms (L, Q1, Q2:
`tlsh_diff(q, r[:2] + q[2:])`) and the body + checksum rest
(`tlsh_diff(q, q[:2] + r[2:])`); the report checks that the two add up to
every row's distance. Each `--knn-extra` run adds rows, with k and max
distance columns, to the latency, speedup and index-work tables (embed only
for the main run), a chart of index median and p99 latency against the bound
when several runs share the main run's k, and checks: brute and index agree
on rows, distances and result counts, the query digests are the main run's,
each bounded brute result is the main run's brute top k cut to distance <=
max_distance, and the means match its `summary.txt`. A k = 10, max distance
144 run also gets the comparison with the M5 figure. (`--knn-k10 DIR` is an
older name for one `--knn-extra`.)

Any of `--knn`, `--found`, `--notfound` may be left out. The exit status is
1 when a validation check fails: brute/index mismatches (rows, and distance
at every rank), internal consistency of the kNN outputs (k-th distance,
count_le against `hist.csv`, embed a prefix of the deep ranking), agreement
with the program's `summary.txt` and `meta.json` statistics, and the lookup assertions (every stored SHA-256 found, no random one found).

Metrics: latency per set x method (n, mean, median, stddev, p90, p99, p99.9,
min, max), speedups (ratios of means and medians, per-query paired ratios),
the index's work (rows, lists, cells) against its latency, latency against
the neighbourhood (count_le, n_identical, d_k); for embed against the brute
ground truth, per query and aggregated: precision, recall and F1 at k, naive
(row identity) and tie-aware (relevant = distance <= d_k), recall over all
tied rows, recall@k' to the deep depth (the recall of re-ranking k'
embedding candidates by TLSH) and the depth needed, AP@k, nDCG@k with a
graded gain, RBO, Kendall tau-b and Spearman rho, ROC and PR AUC with bounds
for the rows beyond the recorded depth, and distance errors per rank and at
the k-th result. The report defines each one. The tables (`lat_stats`,
`speedup`, `ir_q`, `ir_summary`, `auc_q`, `deep_curve`, `depth_needed`,
`dist_err_by_rank`, `index_work`, `density_corr`, `lookup_stats`, ...) stay
in the DuckDB file for further queries. On the 1M synthetic run plus the 9M
lookup CSV it takes about 2 minutes on 4 threads, most of it loading the
9M-row found CSV.

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
* `vs_knn_eval.cpp`      — TLSH kNN eval (brute / index / embed) against a real hset (`make bench/vs_knn_eval`)
* `vs_report/`           — DuckDB analysis and static HTML report of the two evals (`vs_report.py`, `header_split.py`, `sql/`, `svgchart.py`, `report.css`)
