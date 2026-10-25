# hset — the libhasher hash-set format in Rust

A Rust rewrite of libhasher's `.hset` hash-set library: the chunked on-disk
format (encoder and decoder), exact membership lookup over the sorted hash
arrays, set operations, and command-line tools. It reads every file the C++
implementation writes and can write files the C++ implementation reads.

```
rust/
  hset/        library crate (format, lookup strategies, builder, set ops)
  hset-cli/    the `hset` command-line tool
```

## Building and testing

```sh
cd rust
cargo build --release            # library + `target/release/hset`
cargo bench -p hset              # Criterion: lookup latency/throughput, build cost, hex codec
```

The rest runs through `just` (`just --list` for the menu):

| Recipe | Runs | Tier |
|---|---|---|
| `default` | `just --list` | |
| `fmt` / `fmt-check` | `cargo fmt --all` / `-- --check` | gate |
| `lint` | `cargo clippy --workspace --all-targets -- -D warnings`, then the same over `fuzz/Cargo.toml` so targets never rot | gate |
| `test` | `cargo nextest run --workspace`, then `cargo test --workspace --doc` (nextest skips doctests); proptests at their default case count | gate |
| `check` | `fmt-check lint test` | gate |
| `prop` | `PROPTEST_CASES=${PROPTEST_CASES:-20000} cargo nextest run --workspace`; the whole suite, since in-crate proptests live in the unit-test binaries and the example tests cost only seconds | nightly |
| `mutants crate` | `cargo mutants -p crate -j $MUTANTS_JOBS` inside `systemd-run --user --scope -p MemoryMax=$MUTANTS_MEMORY -p MemorySwapMax=0 -p OOMPolicy=continue` (the last so an OOM kill takes only the runaway mutant's test, not the whole run); without `systemd-run` (macOS) run uncapped with a warning | nightly |
| `mutants-diff` | `git diff --relative main... > target/mutants.diff; cargo mutants --workspace --in-diff target/mutants.diff` | on demand |
| `fuzz target` | `cargo fuzz run -s $FUZZ_SANITIZER target target/fuzz-corpus/target fuzz/corpus/target -- <limits>`; unbounded | on demand |
| `fuzz-ci` | every target from `cargo fuzz list`, `-max_total_time=$FUZZ_SECONDS` each | nightly |
| `fuzz-seed` | `cargo fuzz cmin target` merging the scratch corpus into `fuzz/corpus/target` | on demand |
| `verify` | `cargo kani -p hset` inside the same capped `systemd-run` scope as `mutants` (`MemoryMax=$KANI_MEMORY`); without `systemd-run` run uncapped with a warning | nightly |
| `check-slow` | `prop fuzz-ci verify`, then `just mutants` for `hset` and `hset-cli` | nightly |

Test builds use `[profile.test] opt-level = 1` (Cargo.toml): unoptimized,
the TLSH index builds and the property tests took `just test` to 42 s on the
16-core VM; at opt-level 1 the run takes about 6 s. `cargo test --workspace`
run bare, without `just`, runs the same test set but is slower because it
lacks nextest's process-per-test parallelism; the commit-gate's 30 s budget is
measured on `just test`, not the bare command.

Variables with environment overrides: `FUZZ_SECONDS` (default 60),
`FUZZ_SANITIZER` (default `none`; the crate's only `unsafe` is the prefetch
hint and the TLSH POPCNT dispatch, and sanitizer-free builds are portable), `MUTANTS_JOBS` (default 2),
`MUTANTS_MEMORY` (default `3G`), `KANI_MEMORY` (default `4G`),
`PROPTEST_CASES` (default 20000 for `prop`).
`HSET_FIXTURES_DIR` points the fixture-backed tests at the C++ reference
fixtures; the `mutants` and `mutants-diff` recipes set it to an absolute
path because cargo-mutants' per-mutant build copy does not include `test/`,
which sits outside the `rust/` workspace.

Recipes that depend on a missing optional tool (`cargo-fuzz`, `cargo kani`,
`systemd-run`) print `SKIP:` or `NOTE:` to stderr and exit 0; `cargo-nextest`
is required by the gate (`just test`/`just check`) and its absence is an
error, and `cargo-mutants` is required by the `mutants`/`mutants-diff`
recipes the same way.

`hset-testkit` holds Rust-internal oracles (reference hex codec, brute-force
lookup, etc.) used from each crate's `tests/` directory and from the fuzz
crate. The fuzz crate's targets, corpora and invocation are documented in
`fuzz/README.md`. `just verify` runs 29 Kani harnesses over the pure integer
functions of `hset`, in the same capped `systemd-run` scope `mutants` uses
(`MemoryMax=$KANI_MEMORY`) when `systemd-run` is available. Mutation testing
(`cargo-mutants`, configured in `.cargo/mutants.toml`) is triaged on a
strict policy: every surviving mutant gets a new test that kills it, an
`exclude_re` line with a comment saying why it is unobservable, or removal
of dead code, and the triage summary is written to
`experiments/results/mutants-<host>-<date>.md`.

Benchmark knobs: `HSET_BENCH_N` (set size, default 1,000,000),
`HSET_BENCH_HLEN` (hash length, default 20), `HSET_BENCH_ALL=1` (extra
variants: fixed block bits, binary single search), `HSET_BENCH_HEX_LEVELS=1`
(hex codec pinned to each SIMD level as well as the detected one).

## Hex codec

`hset::hex` encodes and decodes the digests in text input and output with
SIMD kernels built on [`fearless_simd`](https://crates.io/crates/fearless_simd),
which selects the instruction level (SSE2, SSE4.2, AVX2, AVX-512, NEON) at
runtime. Both kernels work on 16-byte blocks: encode splits nibbles, maps them
to ASCII with a compare-and-select, and interleaves; decode classifies digits
and case-folded letters with unsigned compares, accumulates an invalid-lane
mask that is checked once, and packs nibble pairs through 16-bit lanes. A
trailing partial block re-runs the kernel on the last full block with
overlapping output.

The API comes in three tiers over the same kernels:

* `encode` / `decode` allocate and return a `String` or `Vec<u8>`.
* `encode_into`, `encode_to_string` (appends to a `String`),
  `encode_to_writer` (any `io::Write`) and `decode_into` fill caller-owned
  storage and never allocate.
* `encode_rows`, `encode_rows_to_writer` and `decode_rows` handle a whole
  array of fixed-width values at once, the layout of a section's hash data,
  running the kernel densely across row boundaries. `hset dump` streams
  digest sections with `encode_rows_to_writer`; `hset query -f` gathers its
  input with `decode_rows`.

`hex::scalar` is the portable reference and the oracle for the tests, which
sweep every length up to 80 bytes, every byte value, and every invalid byte
at every position. On the development machine (Westmere, SSE4.2) a single
decode runs 2.4x to 7.4x faster than the scalar reference across the digest
widths and encode 1.4x to 3.2x; the row batches reach 15 to 20 ns per
SHA-1 hash either way, and `hset dump` of 1 M SHA-1 hashes went from 0.13 s
to 0.03 s. See `experiments/results/criterion-hex-*.md`.

The full experiment matrix behind the design decisions below is reproducible
with `experiments/run_all.sh`; see `experiments/README.md`. Results from the
development machine are committed under `experiments/results/`, and runs on
other hardware should be added there.

## The `hset` tool

```sh
# Build from text: one record per line, one space-separated column per type.
hset make -t md5,sha1 -n "NSRL" -d "RDS 2.80" -o nsrl.hset hashes.txt
hset make -t sha1 -o s.hset < sha1-list.txt          # stdin
hset make -t sha1,size --hint legacy -o s.hset in.txt # readable by the C++ library
hset make -t md5,tlsh -o t.hset md5_tlsh.txt         # TLSH: T1 hex, TNULL/empty = none
hset make -t md5,tlsh --no-tlsh-index -o t.hset in.txt # no TIVF kNN index
HSET_TLSH_OPTIONS=0 hset make -t md5,tlsh -o t.hset in.txt  # the same, as mkhashset reads it

hset info nsrl.hset [--chunks]       # metadata, sections, hints, TLSH index, chunk table
hset verify nsrl.hset                # digest, ordering, record links, hint soundness, TLSH cells/index
hset dump nsrl.hset [-t sha1]        # records (or one type's hashes) as text

hset query nsrl.hset d404b125f9f11f2e2a86a6090def8a23 ...   # type inferred from length
hset query nsrl.hset -t sha1 -f hashes.txt --found-only      # bulk, batched lookups
hset query nsrl.hset -t sha1 -r 7f8d4622...                  # print matching records
hset query nsrl.hset -q <hash>       # exit status only: 0 = all found, 1 = some missing
hset query t.hset T11FA1B357F7...    # exact TLSH lookup, T1 hex

hset knn t.hset T11FA1B357F7... [-k 10] [--max-distance 144] [--no-length]
hset knn t.hset -f digests.txt --strategy brute|index|auto --records --stats

hset union a.hset b.hset -o aub.hset
hset intersect a.hset b.hset -o anb.hset
hset subtract a.hset b.hset -o a-b.hset

hset reindex old.hset -o new.hset --hint hull        # rewrite with a new hint
hset bench nsrl.hset --queries 1000000 --compare     # ns/lookup, single and batch
```

Exit status is 2 on any error.

TLSH sections print and parse digests in the `T1` hex form. `hset make`
writes the TIVF kNN index unless given `--no-tlsh-index`; without the flag
it reads `HSET_TLSH_OPTIONS` as `mkhashset` does (2 = index, 0 = none; 1 and
4 are ignored), and rejects a negative or non-numeric value, the k-means
bit 8, or any other bit. `hset reindex` keeps a TLSH section's TIVF index
byte for byte (rebuilding it only when `--no-records` drops duplicate rows)
and rewrites its cell hint.

`hset knn` prints one line per match, `QUERY<TAB>DISTANCE<TAB>ROW<TAB>DIGEST`
(with `--records`, the row's record in place of the digest), or
`QUERY<TAB>none`; `--stats` adds `# QUERY: strategy=index cells=C lists=L
rows=R` (or `strategy=brute rows=R`) after each query. Every strategy
returns the same matches. Its exit status is 1 when some query has no
match within `--max-distance`.

## Lookup acceleration: convex-hull fitted blocks

An `.hset` section is a sorted array of fixed-width digests. Because digests
are uniformly distributed, a hash's numeric value predicts its index; every
accelerated strategy bounds the error of that prediction so only a small
window has to be searched. The C++ branch benchmarked several ways of bounding
it (`bench/RESULTS.md`): flat per-block `[min, max]` deviation tables at 8 and
14 bits won there, while the convex-hull variants lost to floating-point
arithmetic on the query path and loose 8-bit blocks.

The Rust port revisits the hull idea and makes it the default hint (type
`0x68xx`, "h" + block bits):

* The key space is split into `2^bits` blocks by the leading bits of the hash.
  For each block the `(key fraction, index)` points are already sorted, so
  the upper and lower convex hulls are built in linear time (monotone chain).
  The narrowest slab enclosing a point set is flush with a hull edge, so the
  optimal slope is found by evaluating each hull edge's slope against the hull
  vertices only. Build cost is linear in the number of hashes (about 0.75 s
  for 10 M SHA-1 on the test machine).
* The line is stored as a `u32` fixed-point slope and the search window as
  exact integer residual bounds `rmin`/`rmax`, computed with the same integer
  formula the query uses. There is no floating point on the query path and no
  "verify and widen" loop: every stored hash is inside its own window by
  construction, on any distribution. Entries are 12 bytes (versus 16 for the
  flat tables), so a given table budget buys more blocks.
* Block bits are chosen from the set size (table at most 2 % of the hash data,
  clamped to 4..20 bits), so small files never pay a disproportionate hint.

At 10 M SHA-1 hashes the 18-bit hull table (3 MiB) leaves a mean window of
6.8 candidates (max 17). The remaining cost is memory latency, which the
searcher attacks directly:

* **Single lookups** prefetch every cache line of a small window at once and
  then scan it, so the window costs one memory round trip instead of one per
  probe. Wide windows (weak hints, adversarial data) use an 8-ary search whose
  seven loads per step are independent and overlap.
* **Batched lookups** run a three-stage software pipeline over the query
  stream: prefetch the table entry of query *i*, prefetch the window of query
  *i − 8*, search query *i − 16* from cache. Models with wide windows fall
  back to 32 interleaved searches that each prefetch their next probe.
* **Hint-less sections** use recursive interpolation instead of bisection;
  see the section on Lemire's suggestion below.

### Measured (Xeon E5645, 2.4 GHz, one pinned core, `hset bench`, 1 M queries, 50 % hits)

| set | strategy | single ns | batch ns |
|-----|----------|----------:|---------:|
| 10 M SHA-1, uniform | **hull, 18 bits (default)** | **217** | **97** |
| | legacy flat 8-bit blocks (`0x6208`) | 519 | 225 |
| | binary search, no hint | 1200 | 614 |
| 1 M SHA-1, uniform | **hull, 15 bits** | **149** | **79** |
| | legacy flat 8-bit blocks | 311 | 162 |
| | binary search | 642 | 432 |
| 2 M SHA-1, adversarial (6 leading bytes, dense runs) | **hull, 16 bits** | **171** | **134** |
| | legacy flat 8-bit blocks | 710 | 271 |
| | binary search | 615 | 434 |

### Criterion, 1 M SHA-1 (`HSET_BENCH_ALL=1 cargo bench --bench lookup`, medians)

Batch figures are per lookup within 4096-query batches. "auto" marks the
table size the default policy picks; the other rows hold the table bits fixed
so hull and flat tables can be compared at equal or smaller memory.

| strategy | table | single miss ns | single hit ns | batch miss ns | batch hit ns |
|----------|------:|---------------:|--------------:|--------------:|-------------:|
| binary search (no hint) | 0 | 769 | 777 | 436 | 399 |
| legacy flat 8-bit | 4 KiB | 341 | 329 | 166 | 146 |
| flat 14-bit (auto) | 256 KiB | 181 | 188 | 86 | 88 |
| **hull 15-bit (auto, default)** | 384 KiB | **162** | **172** | **73** | **76** |
| hull 14-bit | 192 KiB | 166 | 185 | 78 | 82 |
| flat 16-bit | 1 MiB | 171 | 215 | 73 | 84 |
| hull 16-bit | 768 KiB | 148 | 193 | 70 | 77 |
| hull 15-bit, binary single / lane batch | 384 KiB | 221 | 178 | 103 | 88 |

The hull table at 14 bits (192 KiB) beats the flat table at 14 bits
(256 KiB) on every column, and the 8-ary single search plus staged batch
pipeline is worth a further 10–30 % over the binary/lane searcher on the same
table.

Run-to-run noise on this VM is about ±10 %. For reference, the frozen C++
leaderboard on the same CPU and set size (`bench/RESULTS.md`, n = 10 M)
reports 515 / 210 ns for the shipping flat 8-bit strategy and 320 / 154 ns
for the best candidate (flat 14-bit blocks), so the Rust default is roughly
1.5× faster than the best C++ candidate and 2.3× faster than the shipping
strategy on both axes, while keeping the sorted array untouched. Copying a
memory-mapped file into huge-page-backed memory (`hset bench --copy`) shaves a
further ~10 % off single lookups by avoiding TLB misses.

## Recursive dictionary search (Lemire's suggestion)

Interpolation ("dictionary") search is recursive: one interpolation step
shrinks the uncertainty from W to about √W on uniform keys, so a search takes
log log n dependent steps instead of log n. The question was whether that can
be done profitably *inside* the hull-bounded window. The port implements it as
`SingleMode::Recursive` (CLI: `hset bench --single recursive`):

* Level 1 fetches the lines around the model's own prediction, with a radius
  that covers 90 % of the residuals (sampled at load time), in one round trip.
  No endpoint keys are read; the C++ C5/C6 candidates lost precisely because
  they paid two serial misses for `key[lo]` and `key[hi-1]` before the first
  useful probe.
* If the key lies outside the fetched region, the region's edge key and the
  model's density (the hull slope) give the next estimate; the error of that
  estimate grows like the square root of the distance jumped, so the next
  region shrinks accordingly. The bracket narrows strictly at every level, so
  the search is exact on any data and falls back to the 8-ary search after
  eight levels.
* Batches use the same idea per lane: interpolating probes first, bisection of
  the small remainder afterwards.

What the data says (Xeon E5645, SHA-1, 1 M queries, 50 % hits, one core):

| set | table | window mean | 8-ary single / batch | recursive single / batch |
|-----|------:|------------:|---------------------:|-------------------------:|
| 10 M, no hint | 0 B | 10 M | 1215 / 640 | **500 / 211** |
| 10 M, hull 0-bit (global envelope) | 12 B | 2666 | 606 / 318 | **460 / 243** |
| 10 M, hull 8-bit | 3 KiB | 230 | 459 / 210 | 441 / 207 |
| 10 M, hull 12-bit | 48 KiB | 56 | 304 / 156 | 287 / 163 |
| 10 M, hull 14-bit | 192 KiB | 28 | 273 / 178 | 282 / 175 |
| 10 M, hull 16-bit | 768 KiB | 14 | 203 / 96 | 201 / 97 |
| 10 M, hull 18-bit (default) | 3 MiB | 6.8 | 243 / 99 | 242 / 94 |
| 40 M, hull 14-bit | 192 KiB | 56 | 386 / 210 | 366 / 236 |
| 40 M, hull 16-bit | 768 KiB | 28 | 294 / 185 | 295 / 186 |
| 40 M, hull 20-bit (default) | 12 MiB | 6.8 | 286 / 123 | 291 / 125 |

Conclusions:

1. **Without a table the recursion wins decisively**: 2.4× on single lookups
   and 3× on batches over bisection, with zero auxiliary bytes. It is therefore
   the default for hint-less digest sections (`SingleMode::Auto`).
2. **Once a table bounds the window, the two converge.** With a 3 KiB table
   the gap is 4 %, from 48 KiB upward it is noise. The reason is structural:
   a table lookup buys the same √-shrinkage as one interpolation level for the
   price of an L2/L3 access instead of a DRAM round trip, and once the window
   fits in the lines a core can fetch at once there is nothing left to recurse
   on. The 8-ary step and the recursive level are both "one round trip that
   shrinks the window a lot"; they differ only in how the probes are placed.
3. **Very large sets argue for small tables, not for dropping them.** At 40 M
   the default 12 MiB table no longer fits in cache, so its tiny windows buy
   nothing over a 768 KiB table (286 vs 294 ns single). Choosing table bits so
   the table stays L2/L3 resident and letting one round trip cover the window
   is the right structure at scale; the recursion is the fallback for when
   even that table is unaffordable.
4. **This core caps how much can be fetched per level.** Regions above about
   eight lines (512 B) got slower, consistent with Westmere's ten line-fill
   buffers; raising the whole-window threshold above 1 KiB also hurt. These
   two knobs are runtime tunables (`SearchConfig::region_bytes`,
   `SearchConfig::window_prefetch_bytes`; `hset bench --region-bytes
   --window-bytes`) because a modern core with far deeper memory-level
   parallelism may prefer larger regions and fewer levels. Sweeping them on
   an Apple-silicon machine is the obvious next experiment.

## Batch structure and SIMD

Two batch organisations are implemented and selectable (`BatchMode`, CLI
`hset bench --batch-mode`):

* **Staged**: one loop whose body advances three stages at once: touch the
  table entry of query *i*, evaluate the window of query *i − 8* and prefetch
  its lines, search query *i − 16* from cache.
* **Passes**: struct-of-arrays passes over sub-batches, pipelined three
  sub-batches deep. Every load within a pass is independent of every other,
  and the window arithmetic (`frac × slope >> 32`, add, clamp) runs as a plain
  loop over arrays; LLVM vectorises it with `pmuludq` (two 32×32→64 lanes on
  this SSE4.2 machine, four with AVX2).

Measured per batched lookup, 4096-query batches (Xeon E5645):

| set | staged | passes, sub-batch 8 / 16 / 32 / 64 |
|---|---:|---:|
| 10 M | **103 ns** | 153 / 147 / 149 / 145 |
| 1 M | **81 ns** | 121 / 117 / 119 / 113 |

Marginal counters per lookup (`perf stat`, 10 M): staged 370 instructions,
62 L1 loads, 10.2 L1 misses; passes 410 instructions, 72 L1 loads, 13.6 L1
misses. The passes version does less arithmetic per query but moves more data
through L1 (it writes and re-reads the key and window arrays) and overlaps
search with memory traffic less well than the fine-grained interleave. The
batch is bound by memory stalls, not by the linear-function arithmetic
(IPC is below one), so vectorising that arithmetic cannot move the number
much on this core; it would matter on a core where the window data is already
cache resident. Passes stays available because a core with deeper memory-level
parallelism and larger L1/L2 may rank the two differently; `--sub-batch` sets
its depth.

### Hardware-dependent parameters

Four knobs depend on the machine rather than the data: the whole-window
prefetch threshold, the recursive region size, the staged pipeline distance,
and the passes sub-batch. The first two and the last are runtime fields of
`SearchConfig` (comparing against a register costs the same as against an
immediate in these loops, so const generics would buy nothing); the hash
length is a const generic because it changes the inner loops. The missing
piece is a cheap startup guess, `SearchConfig::for_this_machine()`, built on
`cpuid` leaf 4 / `sysctl` for cache sizes and a small table keyed on
microarchitecture for the number of outstanding misses, which no interface
reports.

## TLSH kernel performance

Rust targets baseline x86-64, where `u64::count_ones` is a bit-twiddling
sequence, while the C++ library is built with `-mpopcnt`. Every TLSH scan
loop (brute, cell and TIVF kNN, the BISECT build's distance loops, the
merge's coalescing radii, TIVF validation) therefore runs through one
dispatcher, `tlsh::distance::Popcount::scan`, which calls a
`#[target_feature(enable = "popcnt")]` copy after `is_x86_feature_detected!`
(the crate's second `unsafe`, next to the prefetch hint), else the portable
copy; aarch64 has one copy (`count_ones` is NEON `cnt` there).
`tlsh::distance::with_popcount` forces either kind on a thread for tests and
benchmarks; results never differ. Three more fixes closed the rest of the
gap: `TopK::offer` tests its bound inline (a call per row before), the BISECT
k-means dot product keeps vector accumulators across the 256 dims, and the
TIVF scan of multi-list cells prefetches rows 8 entries ahead, as C++ does.

`cargo bench --bench tlsh` (`hset/benches/tlsh.rs`) against a C++ twin of it
built on `libhasher.a`, both on the same rows (`HSET_BENCH_TLSH_TEXT`: the
digests of `vs-eval/synthetic/s100k.txt` and `s1m.txt`, the C++ synthetic
hsets' inputs) and the same 20 SplitMix64 queries per set; Xeon E5645, one
pinned core, interleaved runs on a shared VM, best of 3 (s100k) or 2 (s1m);
per query, build single-threaded; "before" is 5a02c6b:

| | s100k before | after | C++ | s1m before | after | C++ |
|---|---|---|---|---|---|---|
| body kernel, ns/row | 15.1 | 7.1 | 7.7 | 17.3 | 9.0 | 9.6 |
| brute, near (k 10, max 144) | 604 µs | 508 µs | 491 µs | 8.68 ms | 7.41 ms | 7.81 ms |
| brute, member (k 100, unbounded) | 1218 µs | 871 µs | 896 µs | 12.8 ms | 9.74 ms | 9.94 ms |
| brute, random (k 100, unbounded) | 1550 µs | 1051 µs | 1083 µs | 15.6 ms | 11.4 ms | 11.2 ms |
| TIVF, near | 207 µs | 130 µs | 117 µs | 191 µs | 114 µs | 103 µs |
| TIVF, member | 848 µs | 549 µs | 495 µs | 1.25 ms | 0.72 ms | 0.66 ms |
| TIVF, random | 1115 µs | 805 µs | 763 µs | 8.09 ms | 4.71 ms | 4.35 ms |
| BISECT build | 386 ms | 269 ms | 281 ms | 32.1 s | 20.9 s | 22.8 s |

Brute force and the build are level with C++; the TIVF search is within
about 10%. The body row is a plain loop over `BodyQuery::body` compiled
with POPCNT (a caller's own loop gets the portable kernel, 12.9 ns/row on
s100k). The s1m build numbers are single runs; these corpora have large,
duplicate-heavy cells, so the build is far slower than on `bench_tlsh`'s
corpus. The bench's default corpus (`HSET_BENCH_TLSH_N`, testkit digest-space
families) spreads rows over many more cells.

## Format notes

The container is the C++ version-2 chunked format (see `hset/src/format/mod.rs`
for the chunk table). Compatibility details:

* Files with the legacy hint (`--hint legacy`) decode in the C++ library; it
  rejects any other hint type, including the default hull hint. Files written
  by the C++ encoder load here and their hints are used.
* Version-1 files (fixed 4 KiB header, no chunks) are not supported by either
  implementation; this crate reports them explicitly.
* The C++ encoder wrote incorrect `RIDX` (record index) chunks, most indices
  pointing at records that do not contain the hash, until its sort was fixed
  (300ace3). `hset verify` reports such files. The interop tests now require
  the `test/md5_sha1_*.hset` fixtures to verify cleanly and re-encode byte for
  byte, `RIDX` and digest included.
* TLSH hash sets and record fields (type 2^15), which the C++ library writes,
  are not read yet; the fixture tests skip such files.

### Hint type `0x68xx` layout

```
HINT data:  u16 BE  0x68 | bits
            2^bits entries of 12 bytes, little endian:
              u32 slope   positions per 2^32 units of the 32 key bits below the block prefix
              i32 rmin    minimum of (index - predicted) over the block's hashes
              i32 rmax    maximum of (index - predicted); rmin > rmax marks an empty block
query:      block = key >> (64 - bits); frac = (key << bits) >> 32
            predicted = (frac * slope) >> 32
            window    = [predicted + rmin, predicted + rmax] clamped to [0, n)
```

`key` is the leading 8 bytes of the hash as a big-endian integer (shorter
hashes are left-aligned). Flat tables use `0x62xx` with 16-byte
`(i64 min, i64 max)` entries and the legacy `expected_index` predictor.

## Library overview

```rust
use hset::{Builder, BuildOptions, HashType, Hashset};

let mut b = Builder::new(&[HashType::Md5, HashType::Sha1])?;
b.add_text_line("d404b125f9f11f2e2a86a6090def8a23 7f8d4622dbd32bda0f546bc4a6027c96d2bead90")?;
let bytes = b.build(&BuildOptions::new("demo", "two hashes"))?;

let hs = Hashset::load(&bytes)?;            // borrows the bytes (mmap friendly)
let sha1 = hs.index_for_type(HashType::Sha1).unwrap();
assert!(hs.contains(sha1, &hset::hex::decode("7f8d4622dbd32bda0f546bc4a6027c96d2bead90")?));
for rec in hs.records_for(sha1, &hash) { /* linked records */ }
```

Modules: `format` (chunks, decode, encode), `lookup` (`Lookup` trait, hull and
flat models, searcher, `BitsPolicy`), `builder`, `ops` (union, intersection,
difference), `synth` (deterministic data for tests and benches), `hex`,
`hash_type`.
