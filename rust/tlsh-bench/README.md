# tlsh-bench

Criterion benchmarks that drive libhasher's TLSH C API through FFI. They
exist so that distance-kernel and (later) index-accelerated kNN work can be
measured from the same harness that downstream Rust callers would use.

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

`cargo bench` writes Criterion's HTML report to `target/criterion/report/index.html`.
For a quick smoke run:

```
cargo bench -- --warm-up-time 1 --measurement-time 2
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

| group            | measures                                                                        |
|------------------|---------------------------------------------------------------------------------|
| `tlsh_diff_pair` | one `sfhash_tlsh_diff` call                                                     |
| `knn_brute_ffi`  | brute-force k=10 nearest neighbours over N in {10 000, 100 000} synthetic digests, 20 queries per iteration; throughput is rows scanned |
| `tlsh_hash_4mib` | `sfhash_create_hasher`/`update`/`get_hashes` over a 4 MiB random buffer         |

The corpus is generated in Rust (`make_corpus` in `src/lib.rs`): a few
hundred random seed digests, each row a digest-space perturbation of one of
them. It mirrors `perturb_tlsh_corpus` in `test/tlsh_corpus.cpp`; the C++
Catch2 bench (`test/bench_tlsh`) uses real hashed content for its seeds.

## Tests

`cargo test` checks the FFI surface: `SFHASH_HashValues` layout
(`size_of` must equal 624, the value printed by
`sizeof(SFHASH_HashValues)` in a C++ program compiled against
`include/hasher/hasher.h`), hex round trips, distances, a hashing vector
cross-checked against libhasher, and that the heap-based kNN agrees with
an exhaustive sort.
