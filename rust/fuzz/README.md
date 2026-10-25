# hset fuzz targets

cargo-fuzz (libFuzzer) targets over the `hset-testkit` checks. The crate is
outside the workspace (`exclude = ["fuzz"]`), so it builds into
`fuzz/target`. `just lint` runs clippy over it.

| target | input | check |
|---|---|---|
| `decode_bytes` | raw bytes | `exercise_loaded`: a file that loads survives every query path |
| `corrupt_doc` | `(Doc, Corruption)` | `check_corruption`: corruption never panics and never passes the digest unless it changed nothing |
| `lookup` | `LookupCase` | `check_lookup`: every lookup strategy agrees with the linear scan |
| `build_doc` | `Doc` | `check_doc_roundtrip`: build, decode, verify, look up, rebuild |
| `set_ops` | `(Doc, Doc, u8)` | `check_set_op` with the op chosen by `u8 % 3` |
| `hex` | raw bytes | `check_hex`, then `check_hex_rows` with width and separator taken from the first bytes |
| `text_input` | `&str` | `check_text_input`: `Builder::add_text` accepts exactly what the line oracle does |
| `tlsh_hex` | raw bytes | `TlshDigest::from_hex` accepts exactly `TNULL` and 70 hex digits (optional `T1`) and round-trips through `to_hex`; `from_bytes` enforces the reserved byte; `diff` is symmetric, `Some` iff neither digest is null and equals the kit's `ref_diff` |
| `bisect` | `BisectCase` (row specs, build options, queries) | `build_tlsh_ivf` over sorted rows (up to 256, or one cell just past `FLAT_MAX` when `big` is `0xB1`) succeeds and validates, medoids are members, `radius2` is exact, a flat cell has at most `ceil(s / T)` lists, threads do not change the index, the payload round-trips, `knn_ivf` equals `knn_brute`; unsorted rows are refused |

## Two corpora

- `fuzz/corpus/<target>/` holds the committed seeds: small, minimised and
  reviewed. `decode_bytes` is seeded from the `test/*.hset` fixtures
  under 64 KiB; the others from `just fuzz-seed`.
- `target/fuzz-corpus/<target>/` is the scratch corpus. `just fuzz` passes
  it first, so every new input libFuzzer finds lands there and the
  committed seeds stay clean. It is under `target/`, so it is never
  committed.

## Limits

Every run passes `-timeout=10 -rss_limit_mb=2048 -dict=fuzz/hset.dict`:
an input running over 10 s is reported as a hang, and one using over
2 GiB as an out-of-memory crash. `-max_len` is 1048576 for `lookup` (its
cases carry whole sorted hash sets) and 65536 for everything else.
`hset.dict` holds the chunk tags, hash-header prefixes, hint kinds and the
format version so mutations reach past the file header.

`cargo fuzz` builds with debug assertions on, so the crate's
`debug_assert!`s are checked as well as the kit's oracles.

## Running

```sh
just fuzz lookup                     # one target, until stopped
just fuzz hex -runs=100000           # extra arguments go to libFuzzer
just fuzz-ci                         # every target, FUZZ_SECONDS (60) each
FUZZ_SECONDS=20 just fuzz-ci
FUZZ_SANITIZER=address just fuzz-ci  # AddressSanitizer; Linux only
```

The default sanitizer is `none` (the crate has a single `unsafe`, a
prefetch hint), which keeps the build working on stable and on macOS.
Every recipe prints `SKIP:` and exits 0 when `cargo-fuzz` is not
installed.

## Replaying a crash

A crash or hang leaves its input in `fuzz/artifacts/<target>/`
(gitignored). Replay it with

```sh
cargo fuzz run <target> fuzz/artifacts/<target>/<file>
```

## Promoting a crash to a regression test

A crash is a finding; it becomes a named test before it is fixed.

1. Decode the artifact with the target's own `Arbitrary` type, for example
   for `build_doc`:

   ```rust
   use arbitrary::Arbitrary;
   let bytes = std::fs::read("fuzz/artifacts/build_doc/crash-...").unwrap();
   let u = arbitrary::Unstructured::new(&bytes);
   let doc = hset_testkit::doc::Doc::arbitrary_take_rest(u).unwrap();
   println!("{doc:#?}");
   ```

   (`(Doc, Corruption)` and `(Doc, Doc, u8)` decode the same way as
   tuples; `decode_bytes` and `hex` take the bytes as they are, and
   `text_input` the bytes as UTF-8.)
2. Paste the `Debug` output into a named `#[test]` in the matching
   `hset/tests/prop_*.rs` that calls the same check, and commit it.
3. Fix the bug in a separate commit.

## Growing the seeds

```sh
just fuzz-seed <target>
```

copies the scratch corpus into `fuzz/corpus/<target>/` and runs
`cargo fuzz cmin` over the result with `-set_cover_merge=1
-use_counters=0`: a greedy set cover over edge coverage, ignoring hit
counts, which keeps every edge the inputs reach in a few dozen files
(plain `-merge=1` keeps several hundred). Keep each target's seeds under
1 MiB and 200 files; check with

```sh
du -sh fuzz/corpus/<target>; ls fuzz/corpus/<target> | wc -l
```
