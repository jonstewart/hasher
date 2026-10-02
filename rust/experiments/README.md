# Lookup experiments

Everything that informed the design of the table-driven lookup is reproducible
from this directory, so the measurements can be repeated on other hardware and
compared side by side. Hardware matters here: the whole design is about memory
latency, outstanding misses, and cache sizes, and the optimum shifts between an
old Xeon and a modern core.

## Running

```sh
cd rust
experiments/run_all.sh                       # full matrix: 10 M and 40 M hashes, ~30 min, ~2.5 GB scratch
N=1000000 NBIG=0 experiments/run_all.sh      # quick version, a few minutes
PERF=1 experiments/run_all.sh                # add perf-stat marginal counters (Linux)
```

The script builds the release binaries, generates synthetic SHA-1 sets with
fixed seeds (`hset/examples/synth_hset.rs`, SplitMix64, same seeds as the C++
harness), runs `hset bench` over the matrix below, and writes a Markdown
report to `results/<host>-<date>.md` with the machine description, toolchain,
and commit hash in its header. Knobs: `N`, `NBIG`, `HLEN`, `QUERIES`,
`SCRATCH`, `PIN` (core-pinning prefix; `taskset -c 1` on Linux, empty on
macOS), `PERF`.

For statistically characterised latency distributions:

```sh
HSET_BENCH_ALL=1 HSET_BENCH_N=1000000 cargo bench -p hset --bench lookup
cargo bench -p hset --bench build
```

Criterion keeps its reports under `target/criterion`; the summary lines from
this machine's run are in `results/criterion-*.txt`.

## What is measured

| section | question |
|---|---|
| 1 | default configuration against the legacy C++ hint and plain binary search |
| 2, 3 | table size (block bits) against search mode inside the window (8-ary vs recursive dictionary search), at 10 M and 40 M hashes |
| 4 | batch pipeline structure: staged interleave, independent lanes, struct-of-arrays passes with sub-batch sweep |
| 5 | hardware-dependent prefetch thresholds: whole-window prefetch bytes, recursive region bytes |
| 6 | adversarial (skewed) data: correctness is guaranteed, this measures the speed cost |
| 7 | hint-less search: bisection vs recursive interpolation with no table at all |
| 8 | perf-stat marginal cycles, instructions, L1 loads and misses per batched lookup |

## Results on file

- `results/xeon-e5645-westmere-2026-10-02.md`: the reference run on the
  machine the design was developed on (Intel Xeon E5645, Westmere, 2.4 GHz,
  SSE4.2 only, 12 MB L3, about ten line-fill buffers, virtualised, 4 K pages).
- `results/criterion-lookup-1m-xeon-e5645-2026-10-02.txt`: Criterion medians
  for every strategy variant at 1 M hashes on the same machine.
- `results/notes-2026-10-02.md`: the development-time sweeps that were run by
  hand on intermediate revisions (pipeline distance, region cap, pass sizes),
  with the conclusions drawn from them. Treat those numbers as historical; the
  report above is the authoritative measurement of the committed code.

## Naming caveat for the 2026-10-02 files

In the reports from 2026-10-02 the row `binary search (no hint)` (sections 1
and 6) and the Criterion variant `basic` were produced with the automatic search
mode, which for a hint-less digest section is the recursive interpolation
search, not bisection. Bisection without a table is the `kary` row of section 7
and the Criterion variant `basic-binary`. Later builds label these rows
`no hint (auto search)` and `none-auto` / `none-binary`.

## Interpreting

Window statistics (`hset verify`) are machine independent and are the
cross-check for every latency number: a strategy that reports fewer
candidates per lookup but more time per lookup is paying for something other
than memory, and that is worth understanding before tuning. The `README.md`
one directory up discusses the conclusions drawn so far.
