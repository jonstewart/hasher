# tlsh-bench

Criterion benchmarks that drive libhasher's TLSH C API through FFI. They
exist so that the distance kernel and the index-accelerated hash set kNN can
be measured from the same harness that downstream Rust callers would use.

The crate is standalone (`publish = false`) and is not part of the autotools
build.

## Build

libhasher must be built first; the crate links statically against
`src/lib/.libs/libhasher.a` in the repository two levels up:

```
./bootstrap.sh && ./configure ... && make
cd rust/tlsh-bench
cargo test
cargo bench
```

`cargo bench` writes Criterion's HTML report to
`target/criterion/report/index.html` (one page per group and benchmark under
`target/criterion/<group>/<benchmark>/<N>/report/index.html`).

The hash set benchmark is the slow one; these are the settings the table
below was measured with:

```
cargo bench -- hset_knn --warm-up-time 1 --measurement-time 3
```

`TLSH_BENCH_N` overrides the hash set sizes (a comma-separated list):

```
TLSH_BENCH_N=10000,100000 cargo bench -- hset_knn
```

### Pointing at a different build

| variable           | meaning                                                            | default              |
|--------------------|--------------------------------------------------------------------|----------------------|
| `HASHER_LIB_DIR`   | directory containing `libhasher.a`                                 | `../../src/lib/.libs` |
| `HASHER_BUILD_DIR` | configured build tree whose `Makefile` lists `-L`/`-l` link flags  | `../..`              |
| `FUZZY_LIB_DIR`    | directory containing libfuzzy (ssdeep), if not found via Makefile  | probes `/opt/local/lib`, `/opt/homebrew/lib`, `/usr/local/lib` |

libcrypto is found through the Makefile's `PROJECT_LIBS`, or `pkg-config
libcrypto` when no Makefile is present. The C++ runtime (`c++` on macOS,
`stdc++` elsewhere) is always linked.

`libhasher.a` is passed to the linker by absolute path, so an installed
libhasher (for example in a `LIBRARY_PATH` prefix) is never picked up in
its place; `otool -L` / `ldd` on the bench binary should not list libhasher.

## What is measured

| group            | benchmark          | measures                                                                 |
|------------------|--------------------|--------------------------------------------------------------------------|
| `tlsh_diff_pair` |                    | one `sfhash_tlsh_diff` call                                              |
| `knn_brute_ffi`  | `N`                | brute-force k=10 over N in {10 000, 100 000} digest-space perturbations in memory, one `sfhash_tlsh_diff` call per row |
| `tlsh_hash_4mib` | `sfhash_hasher`    | `sfhash_create_hasher`/`update`/`get_hashes` over a 4 MiB random buffer  |
| `hset_knn`       | `naive_brute_ffi`  | the naive baseline: brute-force kNN in Rust over the hset's rows held in memory, one `sfhash_tlsh_diff` FFI call per row |
| `hset_knn`       | `hset_knn_brute`   | `sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_BRUTE)`: libhasher's popcount kernel over every row of the file |
| `hset_knn`       | `hset_knn_index`   | `sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_INDEX)`: the TIVF inverted-file index over the lower-bound embedding (`docs/TLSH_EMBEDDING.md`) |
| `hset_knn`       | `hset_knn_default` | `sfhash_hashset_tlsh_knn`, which picks the index when the file has one   |
| `hset_incremental_merge` | `incremental_union` | `sfhash_hashset_merge(UNION)` of an 18,000-row batch into a 1,000,000-row master hset: rows merged, the TIVF index carried through and its small lists coalesced (`docs/TLSH_EMBEDDING.md` section 3); the output file is written each iteration |
| `hset_incremental_merge` | `rebuild_union`     | the alternative: one from-scratch build of the same 1,018,000 rows through the builder API (sort, dedup, index build with the library's default method, file write) |
| `hset_incremental_merge` | `knn_merged`, `knn_rebuilt` | `sfhash_hashset_tlsh_knn_with(..., INDEX)` over the merged and over the rebuilt file, 20 queries as in `hset_knn` |

`hset_knn` runs for N in {10 000, 100 000, 1 000 000} rows by default. Each
N builds a TLSH-only hset once (through the builder API, with the TIVF index)
in a fresh directory
under the system temp dir, loads it, and answers 20 fixed queries per
iteration with k = 10, max_distance = 144 and the length included. Before
timing, the harness asserts that the four strategies return identical
`(index, distance)` lists for every query. Corpus generation, build and load
times are printed to stderr and not benchmarked; the files are removed when
the group finishes.

Throughput is `rows x queries` per iteration, so Criterion's `elem/s` is rows
scanned per second for the brute-force cases and the equivalent rate for the
index, which touches only a fraction of the rows.

`hset_incremental_merge` builds the master (1,000,000 rows, index only) and
one batch (18,000 rows: 9,000 new families plus 9,000 digest-space
perturbations of master rows) once, then times one incremental union
against one from-scratch build of the union's rows, and finally the kNN
query time over each result (the harness first asserts that the two files
have the same row count and answer the 20 queries identically). The files
carry the TIVF index. `TLSH_BENCH_COALESCE` overrides the coalescing threshold
(`SFHASH_HSET_COALESCE_DEFAULT` otherwise; 0 disables coalescing).

All kNN groups return matches nearest first, ties by ascending row index,
exactly as the C API does, so the naive baseline and the hash set calls are
comparable element for element.

### Corpora

`make_hashed_corpus` in `src/lib.rs` mirrors `make_tlsh_corpus` in
`test/tlsh_corpus.cpp`: families of real content (random base buffers of
1 KiB to 64 KiB over full-byte, small-alphabet, text-like and run-length
alphabets, plus 9 mutated copies each with byte flips over 0.5 to 5 % of the
bytes, small insertions and deletions and a duplicated or moved block) are
hashed through `sfhash_create_hasher(SFHASH_TLSH)`. At most 20 000 digests
are hashed; larger corpora are filled up by digest-space perturbation
(`perturb_corpus`, as `perturb_tlsh_corpus` in C++). Everything is
deterministic per seed (SplitMix64, so the digests differ from the C++
corpus, which uses mt19937_64).

`knn_brute_ffi` keeps using the cheaper purely digest-space corpus
(`make_corpus`). Queries are corpus rows perturbed once at a 5 % bucket flip
rate.

## Results

The tables below were measured with the float k-means index build, the
library default until 2026-10-23; the rerun with the current default
(BISECT, integer clustering) follows each.

Apple M-series, `cargo bench -- hset_knn --warm-up-time 1 --measurement-time 3`,
20 queries per iteration, k = 10, max_distance = 144, include_length = true.
Times are per query (the Criterion iteration time divided by 20).

| rows      | `naive_brute_ffi` | `hset_knn_brute` | `hset_knn_index` | `hset_knn_default` | naive / index | brute / index |
|-----------|-------------------|------------------|------------------|--------------------|---------------|---------------|
| 10 000    | 30.3 us           | 7.1 us           | 3.0 us           | 3.0 us             | 10x           | 2.3x          |
| 100 000   | 302 us            | 58.8 us          | 9.8 us           | 9.9 us             | 31x           | 6.0x          |
| 1 000 000 | 3.04 ms           | 560 us           | 17.1 us          | 17.0 us            | 178x          | 33x           |

Criterion's own figures for the same run (per iteration of 20 queries) were
606 us / 141 us / 60.6 us / 60.5 us at 10 000 rows, 6.04 ms / 1.18 ms /
197 us / 198 us at 100 000 and 60.8 ms / 11.2 ms / 342 us / 341 us at
1 000 000; the throughput column read 330 Melem/s for the naive scan,
1.4 to 1.8 Gelem/s for the kernel brute force and 3.3 / 10.2 / 58.4 Gelem/s
for the index. Building the 1M-row hset (sort, dedup, TIVF index) took 1.45 s
and the file was 40.6 MiB; generating the corpus took 1.4 s.

Rerun with BISECT (2026-10-23, Apple M5 Pro, plain `cargo bench`, 2 min
for every group, after the fresh BISECT build stopped coalescing small
lists; compare within the table):

| rows      | `naive_brute_ffi` | `hset_knn_brute` | `hset_knn_index` | `hset_knn_default` | naive / index | brute / index |
|-----------|-------------------|------------------|------------------|--------------------|---------------|---------------|
| 10 000    | 31.5 us           | 7.4 us           | 3.2 us           | 3.2 us             | 10x           | 2.3x          |
| 100 000   | 309 us            | 61.0 us          | 10.6 us          | 10.4 us            | 29x           | 5.8x          |
| 1 000 000 | 3.09 ms           | 570 us           | 17.6 us          | 17.7 us            | 176x          | 32x           |

Criterion's figures per iteration of 20 queries: 630 us / 148 us / 63.9 us /
63.8 us at 10 000 rows, 6.18 ms / 1.22 ms / 212 us / 208 us at 100 000 and
61.8 ms / 11.4 ms / 352 us / 353 us at 1 000 000. Building the 1M-row hset
took 0.43 s (k-means: 1.45 s) and the file was 40.6 MiB. (The earlier
BISECT run, whose fresh build coalesced, on a loaded machine: index 3.4 /
11.4 / 19.5 us, 40.3 MiB.)

### Incremental merge

Apple M5 Pro, `cargo bench -- hset_incremental_merge` (default coalescing
threshold, `SFHASH_HSET_COALESCE_DEFAULT` = 64), master 999,975 rows
(40.6 MiB with the index, no vectors), batch 18,000 rows, union 1,017,974
rows:

| benchmark           | per iteration     | note                                                        |
|---------------------|-------------------|-------------------------------------------------------------|
| `incremental_union` | 41.5 ms           | `sfhash_hashset_merge`, output 40.9 MiB written each time   |
| `rebuild_union`     | 1.449 s           | builder over the 1,017,974 rows, output 41.3 MiB            |
| `knn_merged`        | 397 us (19.8 us/query) | index carried through the merge, coalesced             |
| `knn_rebuilt`       | 381 us (19.0 us/query) | fresh k-means index                                    |

Rerun with BISECT (same run as above):

| benchmark           | per iteration     | note                                                        |
|---------------------|-------------------|-------------------------------------------------------------|
| `incremental_union` | 41.5 ms           | output 40.9 MiB                                             |
| `rebuild_union`     | 309 ms            | output 41.3 MiB                                             |
| `knn_merged`        | 392 us (19.6 us/query) | index carried through the merge, coalesced             |
| `knn_rebuilt`       | 373 us (18.7 us/query) | fresh BISECT index                                     |

With k-means the incremental union was 35x cheaper than the rebuild and
its index answered within 4% of the rebuilt one's time; with BISECT the
rebuild is 4.7x cheaper than before, the union 7.4x cheaper than the
rebuild, and the merged index answers within 5% of the rebuilt one. (The
earlier, coalescing BISECT run: union 38.6 ms, rebuild 346 ms, kNN 22.5
against 20.5 us per query.) Either way the
merged file is slightly smaller (fewer, fuller lists). The C++ sweep over T and C, hourly and daily batch
sizes and 24 or 7 successive merges is in `docs/TLSH_EMBEDDING.md`
section 5 ("Incremental merge").

The naive baseline is roughly a few nanoseconds per row (an FFI call per
pair), the kernel brute force a fraction of a nanosecond per row, and the
index is close to flat in N. For the C++ view of the same comparison,
including the reference `Tlsh::totalDiff` brute force (not reachable through
the C API, so not benchmarked here), see `test/bench_tlsh.cpp` and section 5
of `docs/TLSH_EMBEDDING.md`.

## Tests

`cargo test` checks the FFI surface: `SFHASH_HashValues` layout
(`size_of` must equal 624, the value printed by
`sizeof(SFHASH_HashValues)` in a C++ program compiled against
`include/hasher/hasher.h`), hex round trips, distances, a hashing vector
cross-checked against libhasher, and that the heap-based kNN agrees with
an exhaustive sort.

The hash set tests build a 2000-digest hset with the builder API into a
temporary directory and check the row count (rows are deduplicated), the
sorted row order, that `tlsh_knn` with `INDEX`, `BRUTE` and the default give
the same answer as a pure-Rust brute force over `sfhash_tlsh_diff` for 20
queries x k in {1, 10} x max_distance in {30, 144, 1000} x both
`include_length` settings, and that options with the reserved bit 1 set
build the same file. A second hset is built without the index to check the
fallbacks. A merge
test unions two built hsets through `sfhash_hashset_merge` with the default,
a disabled and an explicit coalescing threshold and checks the rows against
the deduplicated union and the carried index against a Rust brute force,
then the difference and the intersection.
