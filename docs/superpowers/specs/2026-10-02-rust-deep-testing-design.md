# Design: Deep Testing of the Rust `hset` Port

**Date:** 2026-10-02
**Branch:** `hashset-lookup-perf`
**Status:** Approved design, ready for implementation planning

## Problem

The Rust port under `rust/` (library crate `hset`, binary crate `hset-cli`)
has 90 unit, interop and CLI tests that run in about 9 s. They are example
based: fixed synthetic sets, fixed query lists, the C++ fixtures. The code they
cover is exactly the kind that hides bugs from example tests:

- integer position arithmetic (hull windows, block indices, key extraction)
  whose wrong answers are silent until a real file misses a hash;
- a three-stage software-pipelined batch search whose key ring already had an
  aliasing bug found twice during development;
- a chunked binary file format decoded from untrusted bytes;
- a sorted-row merge implementing set algebra;
- SIMD hex kernels with an overlapping last block.

The port needs property-based tests, mutation testing, coverage-guided
fuzzing and, where the code is amenable, bounded model checking with Kani,
driven by a `justfile` so each tier is one command.

## Goals

- `just test` and `cargo test --workspace` remain the commit gate and stay
  fast (target: under 30 s on the 4-core dev VM).
- Deeper tiers (`prop`, `fuzz-ci`, `verify`, `mutants`) run nightly, at
  release, and once now to root out bugs.
- Every tier compares against Rust-internal oracles only. No C++ or Python
  build is required.
- Everything runs on the Linux dev VM and on the user's Mac; Linux-only
  conveniences degrade to a warning.
- One shared vocabulary of generators and oracles, so fuzz findings replay as
  property-test regressions and oracle logic is written once.

## Non-goals

- Wiring the tiers into the repository's GitLab CI (that pipeline builds the
  C++ tree through an external project).
- Differential testing against the C++ `libhasher` or the Python utilities.
- Adopting the restriction lints (`indexing_slicing`, `unwrap_used`, ...) of
  the reference project; this is a performance-oriented crate and that is a
  separate decision.
- Verifying the SIMD hex kernels or the search strategies with Kani.

## Established facts (probed 2026-10-02 on the dev VM)

- Toolchain: stable `rustc 1.98.1` from nixpkgs, no `rustup`, no nightly.
- `just 1.51`, `cargo-mutants 27.1`, `cargo-fuzz 0.13.1`, `kani 0.68`
  (CBMC 6.11), `cargo-nextest 0.9.136` and `cargo-llvm-cov` are installed.
- `cargo fuzz build` works on this stable toolchain both with `-s none` and
  with AddressSanitizer; a trivial target ran at ~1 M exec/s.
- `cargo kani` proves a copy of the hull window formula (`lo <= hi <= n` for
  all inputs) in 0.6 s of verification, 7 s wall.
- `cargo mutants --list` reports about 2,100 mutants in the workspace, 571 of
  them in `hset/src/lookup/search.rs`.
- `cargo mutants` lists Kani proof harnesses as mutation targets unless they
  are excluded.
- The VM has 4 cores and 11 GB RAM; the root disk is small (synthetic
  benchmark files must live under `rust/target` or be deleted).

## Architecture

Approach: in-crate harnesses for private code, a shared dev-only test kit
crate for generators and oracles, and a separate fuzz crate.

```
rust/
  justfile                 # task runner; `just --list` is the menu
  Cargo.toml               # + member hset-testkit; exclude = ["fuzz"];
                           #   check-cfg for `kani` and `kani_slow`
  .cargo/mutants.toml      # cargo-mutants exclusions and timeouts
  hset/
    src/**                 # + #[cfg(test)] proptests on private functions
                           # + #[cfg(kani)] mod proofs per module
    tests/prop_*.rs        # integration proptests built on the test kit
  hset-testkit/            # dev crate: Doc model, strategies, oracles
  hset-cli/tests/          # + a test-kit-driven CLI round-trip proptest
  fuzz/                    # cargo-fuzz crate, outside the workspace
    Cargo.toml, Cargo.lock
    fuzz_targets/*.rs
    corpus/<target>/       # committed seed corpora (small)
    hset.dict              # libFuzzer dictionary
    README.md              # corpora, replay, promotion to proptest
```

Rationale for the split:

- Property tests on private functions (hull slope selection, row merge,
  chunk cursor) must live in `hset` under `#[cfg(test)]`; a separate crate
  cannot reach them.
- Kani proofs must live in-crate for the same reason, as
  `#[cfg(kani)] mod proofs` at the bottom of each module that has proofs.
- Generators and oracles live in `hset-testkit` so that `hset`'s integration
  tests, `hset-cli`'s tests and the fuzz targets share them, and so that
  `proptest` and `arbitrary` never enter the library's dependency graph.
  Because a crate cannot use a dev-dependency that depends on itself from
  inside its own `#[cfg(test)]` modules without type duplication, the kit is
  used only from `tests/` directories and the fuzz crate.
- No `internals` feature is needed: every entry point the fuzz targets want
  (`Hashset::load`, `format::decode`, `Builder`, `ops::apply`,
  `lookup::make_lookup_with`, `lookup::build_hint`, `hex::*`) is public.

## The `justfile`

Lives at `rust/justfile`, `set shell := ["sh", "-euc"]`, recipe names and
structure mirrored from the user's reference project (`justfile-example`,
not committed).

| Recipe | Runs | Tier |
|---|---|---|
| `default` | `just --list` | |
| `fmt` / `fmt-check` | `cargo fmt --all` / `-- --check` | gate |
| `lint` | `cargo clippy --workspace --all-targets -- -D warnings`, then the same over `fuzz/Cargo.toml` so targets never rot | gate |
| `test` | `cargo nextest run --workspace`; proptests at their default case count | gate |
| `check` | `fmt-check lint test` | gate |
| `prop` | `PROPTEST_CASES=${PROPTEST_CASES:-20000} cargo nextest run --workspace`; the whole suite, since in-crate proptests live in the unit-test binaries and the example tests cost only seconds | nightly |
| `mutants crate` | `cargo mutants -p crate -j $MUTANTS_JOBS` inside `systemd-run --user --scope -p MemoryMax=3G -p MemorySwapMax=0`; without `systemd-run` (macOS) run uncapped with a warning | nightly |
| `mutants-diff` | `git diff main... > target/mutants.diff; cargo mutants --workspace --in-diff target/mutants.diff` | on demand |
| `fuzz target` | `cargo fuzz run -s $FUZZ_SANITIZER target target/fuzz-corpus/target fuzz/corpus/target -- <limits>`; unbounded | on demand |
| `fuzz-ci` | every target from `cargo fuzz list`, `-max_total_time=$FUZZ_SECONDS` each | nightly |
| `fuzz-seed` | `cargo fuzz cmin target` merging the scratch corpus into `fuzz/corpus/target` | on demand |
| `verify` | `cargo kani -p hset` | nightly |
| `verify-slow` | `RUSTFLAGS="--cfg kani_slow" cargo kani -p hset` | release |
| `check-slow` | `prop fuzz-ci verify-slow` (the slow cfg adds to the fast harnesses, so `verify` is covered), then `just mutants` for `hset` and `hset-cli` | nightly |

Variables with environment overrides: `FUZZ_SECONDS` (default 60),
`FUZZ_SANITIZER` (default `none`; the crate has one `unsafe`, the prefetch
hint, and sanitizer-free builds are portable), `MUTANTS_JOBS` (default 2),
`PROPTEST_CASES` (default 20000 for `prop`).

Each `fuzz` invocation passes `-timeout=10 -rss_limit_mb=2048
-dict=fuzz/hset.dict` and a per-target `-max_len` (64 KiB for byte-level
targets, 1 MiB for `lookup`). Debug assertions stay on (cargo-fuzz default).

Recipes that depend on a missing optional tool (`cargo-fuzz`, `cargo kani`,
`systemd-run`) print `SKIP:` or `NOTE:` to stderr and exit 0, as in the
reference project, except that `cargo-mutants` and `cargo-nextest` are
required by the gate and their absence is an error.

## The `hset-testkit` crate

`publish = false`. Dependencies: `hset`, `proptest`, `arbitrary` (with
`derive`). Four parts.

### Document model

```rust
pub struct Doc {
    pub fields: Vec<Field>,            // htype (storable types only, not Fuzzy), name
    pub records: Vec<Vec<Option<Vec<u8>>>>, // per record, per field; value length = field length
    pub opts: Opts,                    // name, desc, timestamp, with_records,
                                       // with_hashsets, HintSpec, BitsPolicy
}
```

- `impl Arbitrary for Doc` caps sizes: at most 4 fields, 64 records, names
  of at most 32 bytes. Fuzz inputs can never ask the builder for gigabytes.
- `pub fn doc() -> impl Strategy<Value = Doc>` with knobs `max_fields`,
  `max_records`, hand-written with proptest combinators so shrinking yields
  readable minimal cases.
- `Doc::build(&self) -> hset::Result<Vec<u8>>` drives `hset::Builder` and is
  the system under test.
- `Doc::expected(&self) -> Expected` is the oracle, computed with plain `Vec`
  sort and dedup from the format's rules, not by calling the builder's
  `sorted_rows`:
  - records: rows in canonical field order, each field as a presence byte
    followed by the value (zeros when absent), sorted lexicographically and
    de-duplicated;
  - hash section for field `f`: the present values of `f` over the
    de-duplicated records, sorted; **de-duplicated only when records are not
    written** (with records, one entry per record, and the `RIDX` chunk maps
    entries back to record indices in `(hash, record index)` order);
  - hint chunk tag: `0x62` family for flat blocks, `0x68` for hull, absent
    for `HintSpec::None` and for non-digest fields; the bit count after
    `resolve_bits` with the document's `BitsPolicy`.

### Oracles

- `NaiveSet { rows, width }`: `contains`, `find` (first equal index) and
  `equal_range` by linear scan over sorted rows.
- `set_op_model(op, a, b) -> BTreeSet<Vec<u8>>` for union, intersection and
  left difference over canonical record rows.
- `hex_oracle::encode` via `format!("{:02x}")` and a matching `decode`,
  independent of `hset::hex::scalar`.

### Generators

- `queries(set, hlen)`: a mix of hits, random misses, one-bit near misses,
  and boundary hashes (all zero, all `0xFF`, first and last stored hash each
  plus and minus one).
- `hash_lengths()`: the eight dispatch lengths 4, 8, 16, 20, 28, 32, 48, 64
  plus one unsupported length (12) to reach the generic fallback.
- `search_configs()`: every `SingleMode` x `BatchMode`, with
  `window_prefetch_bytes` and `region_bytes` down to one hash and
  `passes_sub_batch` in 1..=256.
- `hint_specs(hlen)`: `None`, `Block { bits }` for 1..=12 (only when
  `hlen >= 4`), `Hull { bits }` for 0..=12; only `None` for the unsupported
  length, where `build_hint` returns an error by design.
- `sorted_rows(hlen, max_n)`: random sorted unique rows, including the
  adversarial clustered distribution from `hset::synth`.

### Corruption model

```rust
pub struct Corruption {
    pub truncate_to: Option<usize>,            // relative to the file length
    pub overwrites: Vec<(usize, u8)>,          // position modulo length
    pub chunk_edits: Vec<ChunkEdit>,           // parsed-TOC-aware
}
pub enum ChunkEdit { Offset(usize, u64), Length(usize, u64), Type(usize, u32) }
```

`Corruption::apply(&self, bytes) -> Vec<u8>` parses the table of contents
with `hset::format` to resolve chunk-targeted edits, and falls back to raw
positions if the file no longer parses. Used by the robustness proptest and
the `corrupt_doc` fuzz target; it replaces the hand-rolled loops in the
existing `hset/tests/robustness.rs`, whose three tests are kept as
deterministic smoke tests.

The kit has unit tests of its own that check the oracles against each other
(e.g. `NaiveSet` against `BTreeSet`, `hex_oracle` round trip). It is
excluded from mutation testing.

## Property tests

All are ordinary `#[test]` functions. `cargo test` runs them at proptest's
default 256 cases; `just prop` raises `PROPTEST_CASES`. Each case samples one
hash length, one hint spec and one search config rather than looping over
all combinations, so a case stays cheap and the combination space is covered
by case count. `proptest-regressions/` directories are committed.

### Integration (`hset/tests/prop_*.rs`, on the test kit)

| File | Property |
|---|---|
| `prop_lookup.rs` | `find`, `contains`, `equal_range`, `contains_batch` and `window` agree with `NaiveSet` on hits, misses, near misses and boundary queries; batch sizes include 0, 1, 7, 8, 9, 255, 256, 257; batch answers equal the single answers of the same strategy; every stored hash lies inside its own window. |
| `prop_format.rs` | `decode(build(doc))` matches `doc.expected()` (headers, sections, records, `RIDX`, hint tag, field layout); `verify()` is ok and the digest checks; rebuilding from the decoded file with the same options yields identical bytes. |
| `prop_ops.rs` | `ops::apply` matches `set_op_model`; union commutes; intersection is contained in both operands; difference is disjoint from the right operand; `(A ∪ B) − B == A − B`; the result builds and decodes; mismatched field sets give the documented error. |
| `prop_robustness.rs` | any `Corruption` of a built document either fails to load or loads into a value on which every query, record access and `verify()` is safe; if the digest still verifies, the bytes are unchanged. |
| `prop_hex.rs` | every SIMD level agrees with `hex_oracle`; decode inverts encode; any single non-hex byte at any position is rejected; uppercase accepted; odd length rejected; `encode_rows*`/`decode_rows` agree with the per-value functions for any width and separator. |
| `hset-cli/tests/prop_cli.rs` | a `Doc` rendered as text goes through `hset make`, `hset dump` and `hset query` and matches the oracle. Default 16 cases, since each spawns processes. |

### In-crate (`#[cfg(test)]`, plain proptest primitives)

| Module | Property |
|---|---|
| `lookup::hull` | for any sorted monotone point set, every point lies within the fitted `[rmin, rmax]`; the fitted width is no worse than the end-to-end chord fit and the zero slope; `from_bytes(to_bytes(e)) == e`. |
| `ops` | `merge` matches `BTreeSet` for widths 1..=8 on sorted unique rows. |
| `builder` | `sorted_rows` matches sort plus dedup; `parse_value`/`format_value` round-trip for every field type. |
| `format::chunk` | every `Out` primitive reads back through `Cursor`; `Cursor` never panics for any buffer and position; `pstring` round-trips. |
| `key` | `key64::<L>` equals `key64_dyn`; `cmp_hash::<L>` equals slice comparison for every supported `L`. |
| `lookup::model` | `block_index` is monotone in the key; `frac_of` is monotone within a block. |
| `hash_type` | `from_bits`, `from_log2`, `parse` and the display name round-trip over `ALL`. |

## Fuzz targets

Each target is a thin wrapper over the test kit.

| Target | Input | Checks |
|---|---|---|
| `decode_bytes` | `&[u8]` | `Hashset::load` never panics; on success every query, `verify()` and record access is safe. |
| `corrupt_doc` | `(Doc, Corruption)` | the same checks on a built-then-corrupted document. |
| `lookup` | hash length index, rows, `HintSpec`, `SearchConfig`, queries | every single, batch and `equal_range` answer matches `NaiveSet`. Aimed at the staged pipeline and the recursive search. |
| `build_doc` | `Doc` | build, decode, compare with `doc.expected()`, rebuild to identical bytes. |
| `set_ops` | `(Doc, Doc, SetOp)` | `ops::apply` matches `set_op_model` or returns the documented error. |
| `hex` | `&[u8]` | encode and decode at every SIMD level agree with the oracle; row APIs never panic for any width or separator. |
| `text_input` | `&str` | `Builder::add_text` and `parse_value` never panic and reject what the oracle rejects. |

Corpora: committed seeds in `fuzz/corpus/<target>/` (the small repository
fixtures for `decode_bytes`; a few built documents for the structured
targets), produced by `just fuzz-seed` and minimised with `cargo fuzz cmin`.
Runs write to `target/fuzz-corpus/<target>/` first so the seeds stay clean.
Crash artifacts land in `fuzz/artifacts/` (gitignored). `fuzz/README.md`
explains replay (`cargo fuzz run <target> <artifact>`) and how to turn an
artifact into a proptest regression: decode it with the same `Arbitrary`
type and paste the `Debug` output into a `#[test]`.

`fuzz/hset.dict` holds the magic, chunk tags, hint tag families and hash
type codes for the byte-level target.

## Kani harnesses

Kani is applied only to pure integer functions with small fixed-size inputs
and no data-dependent loops. Every harness is a `#[kani::proof]` with an
explicit `#[kani::unwind(N)]`, in `#[cfg(kani)] mod proofs` at the bottom of
its module. No function contracts or stubbing.

### Fast (`just verify`; each expected under a minute)

| Module | Harness |
|---|---|
| `lookup::hull` | `window` returns `lo <= hi <= n` for every entry, `frac` and `n`; `from_bytes(to_bytes(e)) == e`; `is_empty` iff `rmin > rmax`. |
| `lookup::model` | `FlatBlocks` window arithmetic returns `lo <= hi <= n`; `HullBlocks::window_batch` on a one-entry table equals `HullEntry::window`; for every key and `bits <= 32`, `block_index < 2^bits` and `(block_index << 32) | frac_of == key >> (32 - bits)` (with the `bits == 0` and `bits == 32` edges handled). |
| `key` | `key64::<L> == key64_dyn` and `cmp_hash::<L>` equals slice comparison, one harness per supported `L` via a macro; `expected_index(h, n) < n` for `n > 0`. |
| `format::chunk` | for any buffer up to 16 bytes and any position, each `Cursor` primitive consumes exactly its width or returns `Err` with the position unchanged, and never panics. |
| `hex::scalar` | over all two-byte inputs `decode_into` succeeds iff both bytes are hex digits; decode inverts encode for every byte. |
| `hash_type` | `from_log2` and `from_bits` invert the accessors for every variant and return `None` otherwise. |
| `lookup` | `BitsPolicy::choose` stays within `[min_bits, max_bits]`. |
| `synth` | `SplitMix64::below(b) < b` for `b > 0`. |

### Slow (`just verify-slow`, behind `--cfg kani_slow`)

- `lookup::hull`: `fit_block` on 3 and 4 points, every point within the
  fitted bounds (`Vec` and `f64` under CBMC).
- `ops::merge` on row sets of at most 3 rows of width 1 against a model.

The implementation plan times each slow harness; any that exceeds ten
minutes is removed rather than kept as a proof nobody runs.

### Not amenable (covered by proptest and fuzz instead)

The builder (sorting, SHA-256), whole-file decode (unbounded loop over the
table of contents), the search strategies (memory-bound loops, prefetch
intrinsics, trait objects) and the SIMD hex kernels (intrinsics).

## Mutation testing

`rust/.cargo/mutants.toml`, `test_tool = "nextest"`:

- `exclude_globs`: `hset-testkit/**`, `**/benches/**`, `**/examples/**`.
- `exclude_re`, each with a comment: `::proofs::` (not compiled under
  `cfg(test)`), `prefetch` and `prefetch_entry` (no observable result),
  `fn describe`, `fn table_bytes`, `fn mean_window`, `SetOp::name`
  (diagnostics). Nothing else up front.
- `minimum_test_timeout = 60`, `timeout_multiplier = 3`: a mutant that breaks
  a loop bound in the search or the merge runs until stopped. Memory is
  capped by the `systemd-run` scope on Linux.
- `MUTANTS_JOBS` defaults to 2. About 1,800 mutants after exclusions at
  20 to 40 s each puts a full `hset` run at 5 to 10 hours on the VM, hence
  `mutants-diff` for daily use.

Triage policy: every surviving mutant gets one of three outcomes: a new test
that kills it, an exclusion with a comment explaining why the mutation is
unobservable, or removal of dead code. `mutants.out/` is gitignored; a short
triage summary goes to `rust/experiments/results/mutants-<host>-<date>.md`.

## The first run

1. `just check` green with proptests at default cases; then `just prop`.
2. `FUZZ_SECONDS=600 just fuzz-ci`; then unbounded `just fuzz lookup` and
   `just fuzz corrupt_doc` for as long as the VM can be spared.
3. `just verify`; then `just verify-slow` with timings recorded.
4. `just mutants hset`, then `just mutants hset-cli`, with the triage summary.

Every bug found gets a regression test committed first, then a fix in its own
commit, separate from the test-infrastructure commits.

## Documentation

- `rust/README.md`, "Building and testing": the tier table and recipe names.
- `fuzz/README.md`: corpora, limits, replay, promotion to proptest.
- `rust/Cargo.toml` and `.cargo/mutants.toml` carry comments for every
  exclusion and cfg.

## Success criteria

- `just test` passes in under 30 s on the VM and is byte-for-byte the same
  test set as `cargo test --workspace`.
- `just prop` at 20,000 cases, `just fuzz-ci` at 600 s per target and
  `just verify` all pass on the current code or have produced a committed
  regression test and fix for each failure.
- `just mutants hset` completes with every survivor triaged.
- All recipes run on the Mac with at most `NOTE:`/`SKIP:` output for
  Linux-only tooling.
