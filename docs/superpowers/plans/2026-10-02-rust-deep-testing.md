# Deep Testing of the Rust `hset` Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Rust `hset` workspace property tests, mutation testing, coverage-guided fuzzing and Kani proofs, each runnable as one `just` recipe, then run every tier once and fix what it finds.

**Architecture:** A dev-only `hset-testkit` crate holds the document model, oracles, proptest strategies, `Arbitrary` impls and shared `check_*` functions; `hset/tests/prop_*.rs`, `hset-cli/tests/prop_cli.rs` and the out-of-workspace `fuzz/` crate are thin wrappers over it. Private code gets `#[cfg(test)]` proptests and `#[cfg(kani)] mod proofs` in its own module. `rust/justfile` is the menu; `.cargo/mutants.toml` configures cargo-mutants.

**Tech Stack:** Rust 1.98.1 stable (no rustup), `proptest 1.11`, `arbitrary 1.4` (derive), `libfuzzer-sys 0.4` via `cargo-fuzz 0.13.1`, `kani 0.68`, `cargo-mutants 27.1`, `cargo-nextest 0.9.136`, `just 1.51`.

**Spec:** `docs/superpowers/specs/2026-10-02-rust-deep-testing-design.md`

## Global Constraints

- All paths below are relative to `rust/` unless they start with `docs/` or `/work/`.
- `just test` and `cargo test --workspace` stay under 30 s on the 4-core VM and run the same test set (nextest skips doctests, so `test` also runs `cargo test --workspace --doc`). (Outcome 2026-10-03: measured on `just test`; the bare command runs the same set in about 44 s.)
- Oracles are Rust-internal only: no C++ or Python build, no differential tests against `libhasher`.
- `proptest` and `arbitrary` are never dependencies of `hset` or `hset-cli`, only dev-dependencies and `hset-testkit` dependencies.
- The test kit is used only from `tests/` directories and the fuzz crate, never from `#[cfg(test)]` modules inside `hset`.
- Every hint bit count a generator produces is at most 12 (a 12-bit hull table is 48 KiB; 24 bits would be 200 MiB).
- Kani harnesses: `#[kani::proof]` plus an explicit `#[kani::unwind(N)]`, in `#[cfg(kani)] mod proofs` at the bottom of the module, no function contracts, no stubbing. Slow harnesses are additionally under `#[cfg(kani_slow)]`; any slow harness over ten minutes is removed.
- Recipes needing an optional tool (`cargo-fuzz`, `cargo kani`, `systemd-run`) print `SKIP:` or `NOTE:` to stderr and exit 0; `cargo-mutants` and `cargo-nextest` missing is an error.
- Environment knobs: `FUZZ_SECONDS` (60), `FUZZ_SANITIZER` (`none`), `MUTANTS_JOBS` (2), `PROPTEST_CASES` (20000 for `prop`), plus `MUTANTS_MEMORY` (`3G`) for the `systemd-run` cap.
- libFuzzer flags on every run: `-timeout=10 -rss_limit_mb=2048 -dict=fuzz/hset.dict`, `-max_len=1048576` for `lookup`, `-max_len=65536` otherwise.
- `mutants.out/`, `fuzz/artifacts/`, `fuzz/target/` and `fuzz/coverage/` are gitignored; `proptest-regressions/` directories and `fuzz/corpus/` are committed.
- Every bug found gets its regression test in one commit and its fix in a separate commit, apart from the test-infrastructure commits.
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

Inputs the spec implies but does not name; each is pinned to a test in the task that owns the code.

1. A record whose every field is absent (all presence bytes zero) sorts first, contributes to no hash section and leaves other sections' `RIDX` correct. Pinned in Task 2 (`all_absent_record_is_a_row`).
2. A name, description or field name of exactly 65535 bytes builds and decodes; 65536 bytes is rejected by `build` with `Error::Input`, never a panic. Pinned in Task 6 (`pstring_length_boundary`).
3. A query hash longer than the section's hash length is answered by its prefix, for every strategy and for `contains_batch`, matching the exact-length answer. Pinned in Task 7 (inside `check_lookup`).
4. `SearchConfig::passes_sub_batch` of 0 or above 256 is clamped and gives the same answers as 1 or 256; the spec's generator range is 1..=256, so the edges are added to `search_configs()`. Pinned in Task 4 and exercised by Task 7.
5. Several records sharing one hash value: `records_for` returns exactly those records and `equal_range` spans all of them, including when the records differ only in another field. Pinned in Task 6 (inside `check_doc_roundtrip`).

---

### Task 1: Workspace scaffolding and the gate recipes

**Files:**
- Create: `justfile`
- Modify: `Cargo.toml` (workspace root), `hset/Cargo.toml`, `hset-cli/Cargo.toml`, `.gitignore`

**Interfaces:**
- Produces: `just fmt`, `just fmt-check`, `just lint`, `just test`, `just check`, `just prop`, `just default`; workspace `check-cfg` for `kani` and `kani_slow`; `exclude = ["fuzz"]`; workspace deps `proptest`, `arbitrary`, `hset-testkit`.

- [ ] **Step 1: Edit the workspace `Cargo.toml`**

Set `members = ["hset", "hset-cli", "hset-testkit"]`, add `exclude = ["fuzz"]`, and add to `[workspace.dependencies]`:

```toml
proptest = "1.11"
arbitrary = { version = "1.4", features = ["derive"] }
hset-testkit = { path = "hset-testkit" }
```

Add, with a comment that `hset` carries `#[cfg(kani)] mod proofs` and `#[cfg(kani_slow)]` harnesses:

```toml
[workspace.lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(kani)', 'cfg(kani_slow)'] }
```

Add `[lints]\nworkspace = true` to `hset/Cargo.toml` and `hset-cli/Cargo.toml`. (The `hset-testkit` member does not exist yet; `cargo metadata` will fail until Task 2's Step 1, so run Step 2 and Step 3 together with Task 2 Step 1 if working strictly in order, or create an empty `hset-testkit` with `cargo new --lib hset-testkit --vcs none` here and let Task 2 fill it.)

- [ ] **Step 2: Write `justfile`**

```just
# hset task runner. `just --list` for the menu.
#
# Recipes run through sh. Tiers: `check` is the commit gate; `check-slow`
# is nightly. Every deeper tier compares against Rust-internal oracles.

set shell := ["sh", "-euc"]

# Seconds each fuzz target runs under `just fuzz-ci`.
fuzz_seconds := env_var_or_default("FUZZ_SECONDS", "60")
# Sanitizer for fuzz builds. The crate has one `unsafe` (a prefetch hint);
# sanitizer-free builds are portable to the Mac.
fuzz_sanitizer := env_var_or_default("FUZZ_SANITIZER", "none")
# Parallel cargo-mutants jobs.
mutants_jobs := env_var_or_default("MUTANTS_JOBS", "2")
# Memory cap for the cargo-mutants scope (Linux only).
mutants_memory := env_var_or_default("MUTANTS_MEMORY", "3G")
# Proptest cases for `just prop`.
proptest_cases := env_var_or_default("PROPTEST_CASES", "20000")

# List the available recipes.
default:
    @just --list

# Format every crate in place.
fmt:
    cargo fmt --all

# Fail if anything is unformatted.
fmt-check:
    cargo fmt --all -- --check

# Clippy over the workspace with warnings fatal.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Commit gate: unit, interop, CLI and property tests at default case counts.
# nextest does not run doctests, so they run separately to keep this the
# same test set as `cargo test --workspace`.
test:
    cargo nextest run --workspace
    cargo test --workspace --doc

# Property tests at a high case count (the whole suite; example tests
# cost seconds and the in-crate proptests live in the unit-test binaries).
prop:
    PROPTEST_CASES={{ proptest_cases }} cargo nextest run --workspace

# Fast gate, run on every change.
check: fmt-check lint test
```

- [ ] **Step 3: Extend `.gitignore`**

Append:

```
/mutants.out
/fuzz/target
/fuzz/artifacts
/fuzz/coverage
```

- [ ] **Step 4: Run the gate**

Run: `cd rust && just check`
Expected: fmt, clippy and all 90 existing tests pass; `just test` wall time under 30 s (`time just test`).

- [ ] **Step 5: Commit**

```bash
git add rust/justfile rust/Cargo.toml rust/Cargo.lock rust/hset/Cargo.toml rust/hset-cli/Cargo.toml rust/.gitignore
git commit -m "build(rust): justfile with the commit gate; workspace cfgs for kani"
```

---

### Task 2: Test kit crate with the document model and its oracle

**Files:**
- Create: `hset-testkit/Cargo.toml`, `hset-testkit/src/lib.rs`, `hset-testkit/src/doc.rs`

**Interfaces:**
- Consumes: `hset::{Builder, BuildOptions, HashType, HintSpec, BitsPolicy}`, `hset::format::{FieldDescriptor, HsetFile, hint_tag_block, hint_tag_hull}`, `hset::lookup::resolve_bits`, `hset::builder::format_value`.
- Produces (all `pub`, all `#[derive(Debug, Clone, PartialEq)]`):

```rust
// hset-testkit/src/doc.rs
pub const STORABLE_TYPES: [HashType; 14];           // HashType::ALL minus Fuzzy
pub struct Field { pub htype: HashType, pub name: String }
impl Field {
    pub fn canonical(htype: HashType) -> Field;      // name = htype.field_name()
    pub fn length(&self) -> usize;                   // htype.length().unwrap()
    pub fn descriptor(&self) -> FieldDescriptor;
}
pub struct Opts {
    pub name: String, pub desc: String, pub timestamp: String,
    pub with_records: bool, pub with_hashsets: bool,
    pub hint: HintSpec, pub bits_policy: BitsPolicy,
}
impl Opts {
    pub fn default_for_tests() -> Opts;              // "t", "t", "2024-01-01T00:00:00Z", true, true, Hull{bits:u8::MAX}, BitsPolicy::default()
    pub fn build_options(&self) -> BuildOptions;     // always sets .timestamp(self.timestamp.clone())
}
pub struct Doc { pub fields: Vec<Field>, pub records: Vec<Vec<Option<Vec<u8>>>>, pub opts: Opts }
impl Doc {
    pub fn descriptors(&self) -> Vec<FieldDescriptor>;
    pub fn record_length(&self) -> usize;
    pub fn builder(&self) -> hset::Result<Builder>;  // Builder::with_fields + add_record per record
    pub fn build(&self) -> hset::Result<Vec<u8>>;    // builder()?.build(&opts.build_options())
    pub fn expected(&self) -> Expected;
    pub fn op_rows(&self, layout: &[FieldDescriptor]) -> BTreeSet<Vec<u8>>; // rows relaid to `layout` (fields matched by htype, zeros when missing); from deduped records when with_records, else from the present values of the single field wrapped as [1] ++ value
    pub fn to_text(&self) -> String;                 // one line per record in input order: format_value per field, "" when absent, joined by ' ', '\n' terminated
    pub fn type_list(&self) -> String;               // field_name()s joined by ',' for `hset make -t`
}
pub struct Expected { pub record_length: usize, pub records: Option<Vec<Vec<u8>>>, pub sections: Vec<ExpectedSection> }
pub struct ExpectedSection {
    pub htype: HashType, pub name: String, pub hash_length: usize,
    pub hashes: Vec<Vec<u8>>, pub ridx: Option<Vec<u64>>, pub hint_tag: Option<u16>,
}
impl Expected {
    /// Panics with a message naming the first mismatch.
    pub fn assert_matches(&self, file: &HsetFile<'_>);
}
```

- [ ] **Step 1: Create the crate**

`hset-testkit/Cargo.toml`: `name = "hset-testkit"`, `publish = false`, `version/edition/license` from workspace, `[lints] workspace = true`, dependencies `hset = { path = "../hset" }`, `proptest.workspace = true`, `arbitrary.workspace = true`. `src/lib.rs` declares `pub mod doc;` (later tasks add `oracle`, `strategies`, `arb`, `corrupt`, `checks`).

- [ ] **Step 2: Write the failing kit tests in `doc.rs`**

```rust
#[cfg(test)]
mod tests {
    fn two_field_doc() -> Doc  // fields Md5 ("md5"), Size ("sizes"); records:
        // r0: md5 = [0x11;16], size = 10
        // r1: md5 = [0x11;16], size = 20       (same md5, different size)
        // r2: md5 = None,      size = 7
        // r3: md5 = [0x11;16], size = 10       (exact duplicate of r0)
        // r4: md5 = None,      size = None     (all absent)
        // opts = Opts::default_for_tests()

    #[test] fn expected_dedups_and_sorts_records()
        // records == 4 rows (r3 dropped), sorted bytewise: r4 ([0,..0,0,..0]) first, then r2, then the two 0x11 rows ordered by size bytes (10 before 20).
    #[test] fn expected_hash_section_with_records_keeps_duplicates()
        // md5 section: hashes == [[0x11;16], [0x11;16]], ridx == Some([2, 3]) (indices of the two 0x11 rows in the sorted records)
        // sizes section: hashes == [7, 10, 20] as le bytes sorted bytewise ( [7,0,..], [10,0,..], [20,0,..] ), ridx == Some([1, 2, 3]), hint_tag == None (Size is not a digest)
    #[test] fn expected_hash_section_without_records_dedups()
        // opts.with_records = false: md5 hashes == [[0x11;16]], ridx == None
    #[test] fn expected_hint_tag_follows_resolve_bits()
        // Hull{bits: 3} -> Some(0x6803); Block{bits: 8} -> Some(0x6208); None -> None;
        // Hull{bits: u8::MAX} -> Some(hint_tag_hull(BitsPolicy::default().choose(2, 16, 12)))
    #[test] fn all_absent_record_is_a_row()
        // Review Focus 1: build() ok; decode() has 4 records; record(0) is all zeros; sizes section has 3 hashes.
    #[test] fn empty_doc_builds()
        // records = [] -> build() ok, decode() ok, record_count 0, each section empty, hint present for Md5 with Hull
    #[test] fn build_matches_expected_on_the_sample()
        // doc.expected().assert_matches(&decode(&doc.build().unwrap()).unwrap()) for with_records true and false
    #[test] fn op_rows_relayout_and_wrap()
        // two_field_doc().op_rows(&[Size desc, Md5 desc]) has 4 rows each 9 + 17 bytes with Size first;
        // a one-field hashes-only doc's op_rows == {[1] ++ value} per distinct present value
    #[test] fn to_text_renders_absent_as_empty()
        // r2 renders as " 7", r4 as " ", r0 as "11111111111111111111111111111111 10"; type_list() == "md5,sizes"
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p hset-testkit`
Expected: compile errors for the missing types.

- [ ] **Step 4: Implement `doc.rs`**

The oracle computes `Expected` from the format rules with plain `Vec` sort and dedup, not via `hset::builder::sorted_rows`: row = per field presence byte then value or zeros; records sorted lexicographically and deduped; per field over the deduped records collect `(value, index)` for present values, sort by `(value, index)`, dedup by value only when `!with_records`; `ridx` present only when `with_records`; `hint_tag` only when `with_hashsets && htype.is_digest()`, from `resolve_bits(opts.hint, hashes.len(), hlen, &opts.bits_policy)` mapped through `hint_tag_block` / `hint_tag_hull`, `None` for `HintSpec::None`. `assert_matches` checks, in order: `fhdr` version 2, name, desc, time; `rhdr` presence equals `with_records`; `rhdr.fields == descriptors`, `record_length`, `record_count`; `rdat` rows; `sections.len()` is `fields.len()` or 0; per section header fields, `data` equals the concatenated hashes, `ridx` decoded as `u64` LE, `hint.map(|h| h.tag())`, and that no hint is `Hint::Unknown`.

- [ ] **Step 5: Run the kit tests**

Run: `cargo test -p hset-testkit`
Expected: PASS (9 tests).

- [ ] **Step 6: Commit**

```bash
git add rust/hset-testkit rust/Cargo.lock
git commit -m "test(rust): hset-testkit with the Doc model and format oracle"
```

---

### Task 3: Test kit oracles: `NaiveSet`, `set_op_model`, `hex_oracle`

**Files:**
- Create: `hset-testkit/src/oracle.rs`
- Modify: `hset-testkit/src/lib.rs` (add `pub mod oracle;`)

**Interfaces:**
- Produces:

```rust
pub struct NaiveSet { pub rows: Vec<Vec<u8>>, pub width: usize }
impl NaiveSet {
    pub fn from_bytes(data: &[u8], width: usize) -> NaiveSet;  // chunks_exact(width)
    pub fn contains(&self, h: &[u8]) -> bool;                   // compares &h[..width]
    pub fn find(&self, h: &[u8]) -> Option<usize>;              // first equal index, linear scan
    pub fn equal_range(&self, h: &[u8]) -> Range<usize>;        // 0..0 when absent
}
pub fn set_op_model(op: SetOp, a: &BTreeSet<Vec<u8>>, b: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>>;
pub mod hex_oracle {
    pub fn encode(bytes: &[u8]) -> String;              // format!("{:02x}") per byte
    pub fn decode(s: &[u8]) -> Option<Vec<u8>>;         // None on odd length or any non-hex byte; accepts upper case
}
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn naive_set_matches_btreeset()
    // 200 rows of width 3 from SplitMix64(1) (hset::synth), sorted with duplicates kept: for each row and 50 random probes,
    // contains == BTreeSet::contains; find == rows.iter().position(..); equal_range covers every equal index and nothing else
#[test] fn naive_set_uses_prefix_of_longer_query()
    // width 2, query of 5 bytes: contains iff rows contains query[..2]
#[test] fn set_op_model_on_small_sets()
    // a = {1,2,3}, b = {2,3,4} as single-byte rows: Union {1,2,3,4}, Intersect {2,3}, Subtract {1}
#[test] fn hex_oracle_roundtrip_and_rejects()
    // encode([0x00,0xab,0xff]) == "00abff"; decode(b"00ABff") == Some([0,0xab,0xff]); decode(b"abc") == None; decode(b"zz") == None; decode(b"") == Some([])
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hset-testkit oracle`
Expected: compile errors.

- [ ] **Step 3: Implement `oracle.rs`**

- [ ] **Step 4: Run the tests**

Run: `cargo test -p hset-testkit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit
git commit -m "test(rust): NaiveSet, set-operation and hex oracles in the test kit"
```

---

### Task 4: Test kit generators and `Arbitrary` impls

**Files:**
- Create: `hset-testkit/src/strategies.rs`, `hset-testkit/src/arb.rs`
- Modify: `hset-testkit/src/lib.rs`

**Interfaces:**
- Produces:

```rust
// strategies.rs (proptest)
pub const SUPPORTED_LENGTHS: [usize; 8] = [4, 8, 16, 20, 28, 32, 48, 64];
pub const UNSUPPORTED_LENGTH: usize = 12;
pub fn hash_lengths() -> BoxedStrategy<usize>;                 // select from SUPPORTED_LENGTHS ++ [UNSUPPORTED_LENGTH]
pub fn hint_specs(hlen: usize) -> BoxedStrategy<HintSpec>;     // None; Block{1..=12} only if hlen >= 4; Hull{0..=12}; only None when hlen == UNSUPPORTED_LENGTH
pub fn search_configs() -> BoxedStrategy<SearchConfig>;        // every SingleMode x BatchMode; window_prefetch_bytes and region_bytes in 1..=4096 (so down to one hash); passes_sub_batch from prop_oneof![1..=256usize, Just(0), Just(1000)]
pub fn sorted_rows(hlen: usize, max_n: usize) -> BoxedStrategy<Vec<u8>>; // oneof: uniform random rows (vec of any::<u8>(), sorted+deduped via hset::synth::sort_unique_rows); synth::adversarial_hashes(count, hlen, seed) with count in 0..=max_n and any seed; rows from the alphabet {0x00, 0x80, 0xFF} (dense shared prefixes)
pub fn with_duplicates(rows: Vec<u8>, hlen: usize, dup_mask: &[bool]) -> Vec<u8>; // repeat row i once when dup_mask[i % len] (keeps order)
pub fn queries(set: &[u8], hlen: usize, seed: u64, m: usize) -> Vec<u8>; // deterministic: boundary hashes first (all 0x00, all 0xFF, and when set is non-empty first-1, first+1, last-1, last+1 as big-endian integers with carry), then m hashes mixing hits, random misses and one-bit near misses by SplitMix64(seed)
pub fn field(htype: HashType) -> BoxedStrategy<Field>;         // name oneof: canonical, "[a-zA-Z0-9_ -]{0,32}", "[a-zé]{0,16}"
pub fn fields(max_fields: usize) -> BoxedStrategy<Vec<Field>>; // 1..=max_fields distinct STORABLE_TYPES (shuffle then take)
pub fn value(htype: HashType) -> BoxedStrategy<Vec<u8>>;       // digests: oneof uniform bytes, bytes from {0x00, 0x80, 0xFF}; Size: any u64 LE; Entropy: finite f64 LE (filter is_finite) so text round-trips
pub fn record(fields: &[Field]) -> BoxedStrategy<Vec<Option<Vec<u8>>>>; // each field present with weight 3:1
pub fn opts() -> BoxedStrategy<Opts>;                           // name/desc "[ -~]{0,32}"; timestamp from ["2024-01-01T00:00:00Z", "1970-01-01T00:00:00Z", ""]; (with_records, with_hashsets) from {(true,true),(true,false),(false,true)}; hint oneof hint_specs(8), Just(Hull{bits:u8::MAX}), Just(Block{bits:0}); bits_policy budget from [0.0, 0.02, 1.0], min_bits 0..=4, max_bits min..=12
pub fn doc_with(max_fields: usize, max_records: usize) -> BoxedStrategy<Doc>;
pub fn doc() -> BoxedStrategy<Doc>;                             // doc_with(4, 64)
pub fn doc_pair() -> BoxedStrategy<(Doc, Doc)>;                 // b has a's field types (order kept or reversed), a subset of a's records (bool mask, values permuted to b's field order) plus 0..=16 fresh records, fresh opts
pub fn doc_pair_mismatched() -> BoxedStrategy<(Doc, Doc)>;      // two docs whose type sets differ (prop_filter)
pub fn cli_doc() -> BoxedStrategy<Doc>;                         // doc() with canonical field names, with_records = with_hashsets = true, bits_policy = BitsPolicy::default() except budget
pub fn set_op() -> BoxedStrategy<SetOp>;
pub fn lookup_case() -> BoxedStrategy<LookupCase>;              // hlen from hash_lengths(); rows sorted_rows(hlen, 2000) then with_duplicates over a mask of up to 8 bools; hint hint_specs(hlen); cfg search_configs(); queries(set, hlen, any seed, m in 0..=300)
pub fn corruption() -> BoxedStrategy<Corruption>;               // Task 10 adds this once Corruption exists

// Shared case types live in strategies.rs so arb.rs and checks.rs agree:
#[derive(Debug, Clone, PartialEq)]
pub struct LookupCase { pub hlen: usize, pub data: Vec<u8>, pub hint: HintSpec, pub cfg: SearchConfig, pub queries: Vec<u8> }

// arb.rs: hand-written impls with the same caps as the strategies
impl<'a> Arbitrary<'a> for Doc        // at most 4 fields, 64 records, names at most 32 bytes; Entropy values finite; if both with_records and with_hashsets come out false, set with_hashsets = true
impl<'a> Arbitrary<'a> for LookupCase // hlen index 0..=8 into SUPPORTED_LENGTHS ++ [12]; up to 2000 rows via u.bytes then sort_unique_rows, or adversarial_hashes from a seed; duplicates via a mask; hint/cfg as the strategies; queries via queries(set, hlen, seed, m <= 300)
```

- [ ] **Step 1: Write the failing tests in `strategies.rs` and `arb.rs`**

```rust
// strategies.rs tests (use proptest! with default cases)
#[test] fn hint_specs_for_unsupported_length_is_none()          // 50 samples from hint_specs(12) via TestRunner are all HintSpec::None
#[test] fn hint_specs_bits_stay_at_most_12()                    // 200 samples from hint_specs(20): bits <= 12; Block bits >= 1
#[test] fn sorted_rows_are_sorted()                             // proptest: rows in sorted_rows(20, 500) -> chunks are non-decreasing and unique
#[test] fn with_duplicates_keeps_order()                        // [a,b,c] with mask [true,false,true] -> [a,a,b,c,c]
#[test] fn queries_start_with_boundaries()                      // set of 3 rows width 4: first 6 queries are [0;4], [0xff;4], first-1, first+1, last-1, last+1; total length (6 + m) * hlen; empty set -> only the two constant boundaries
#[test] fn queries_carry_across_bytes()                         // first = [0x00,0x00,0x01,0x00] -> first-1 == [0,0,0,0xff]; last = [0xff,0xff,0xff,0xff] -> last+1 == [0xff;4] (saturates)
#[test] fn doc_pair_shares_types()                              // proptest over doc_pair(): type sets equal, and every b record's present values appear in a or in the fresh tail (just check equal type sets and b.records.len() <= a.records.len() + 16)
#[test] fn doc_pair_mismatched_differs()                        // proptest: type sets differ
#[test] fn cli_doc_is_canonical()                               // proptest: names == field_name(), with_records && with_hashsets
#[test] fn entropy_values_are_finite()                          // proptest over value(HashType::Entropy): f64::from_le_bytes(..).is_finite()

// arb.rs tests
#[test] fn arbitrary_doc_respects_caps()                        // for 200 seeds of 4 KiB from SplitMix64: Doc::arbitrary_take_rest ok -> fields.len() in 1..=4 distinct types, records.len() <= 64, names <= 32 bytes, every value length == field length, with_records || with_hashsets
#[test] fn arbitrary_lookup_case_is_well_formed()               // 200 seeds: data.len() % hlen == 0, rows sorted, hint None when hlen == 12, bits <= 12, queries.len() % hlen == 0
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hset-testkit strategies arb`
Expected: compile errors.

- [ ] **Step 3: Implement `strategies.rs` and `arb.rs`**

Hand-write the strategies with proptest combinators (`prop_oneof!`, `prop_flat_map`, `prop::collection::vec`, `prop::sample::select`, `prop_shuffle`) so shrinking stays readable; no `#[derive(Arbitrary)]` on `Doc` or `LookupCase` because `HintSpec`, `SearchConfig` and `BitsPolicy` are foreign types.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p hset-testkit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit
git commit -m "test(rust): proptest strategies and Arbitrary impls in the test kit"
```

---

### Task 5: Shared checks module and the robustness smoke tests on it

**Files:**
- Create: `hset-testkit/src/checks.rs`
- Modify: `hset-testkit/src/lib.rs`, `hset/Cargo.toml` (dev-dependencies: `hset-testkit.workspace = true`, `proptest.workspace = true`), `hset/tests/robustness.rs`

**Interfaces:**
- Produces:

```rust
/// Load `bytes`; if that succeeds, run every query, record access and
/// `verify()` the kit knows (panics are the failure signal). Returns whether it loaded.
pub fn exercise_loaded(bytes: &[u8]) -> bool;
```

`exercise_loaded` does what `hset/tests/robustness.rs::exercise` does today plus, per section: `find`, `contains`, `equal_range`, `records_for` and `window` for the six boundary hashes from `strategies::queries` and for up to 64 stored hashes; `contains_batch` over the first 64 stored hashes; `verify()`; and over up to 64 records `record_fields` and `field_value` for every `HashType::ALL`.

- [ ] **Step 1: Replace the local `exercise` in `hset/tests/robustness.rs` with `hset_testkit::checks::exercise_loaded`**

Keep the three tests (`truncations_never_panic`, `random_corruption_never_panics`, `hostile_lengths_are_rejected`) and their assertions unchanged; `truncations_never_panic` counts loads via the return value.

- [ ] **Step 2: Run**

Run: `cargo test -p hset --test robustness`
Expected: PASS, 3 tests.

- [ ] **Step 3: Commit**

```bash
git add rust/hset-testkit rust/hset/Cargo.toml rust/hset/tests/robustness.rs rust/Cargo.lock
git commit -m "test(rust): shared exercise_loaded check; robustness smoke tests use it"
```

---

### Task 6: `prop_format.rs`: build, decode, verify, rebuild

**Files:**
- Modify: `hset-testkit/src/checks.rs`
- Create: `hset/tests/prop_format.rs`

**Interfaces:**
- Produces: `pub fn check_doc_roundtrip(doc: &Doc)` in `checks.rs`.

- [ ] **Step 1: Write `hset/tests/prop_format.rs`**

```rust
use hset_testkit::{checks::check_doc_roundtrip, strategies::doc};
proptest! {
    #[test] fn build_decode_matches_oracle(d in doc()) { check_doc_roundtrip(&d); }
}
#[test] fn pstring_length_boundary() {
    // Review Focus 2: Builder::new(&[HashType::Md5]) with BuildOptions name of 65535 'a' bytes builds and decode().fhdr.name has 65535 bytes;
    // name of 65536 bytes -> Err(Error::Input(_)); same for desc and for a Field named 65536 bytes via Builder::with_fields.
}
#[test] fn both_outputs_disabled_is_an_error() {
    // Doc with with_records = with_hashsets = false: build() is Err(Error::Input(_)).
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hset --test prop_format`
Expected: compile error, `check_doc_roundtrip` missing.

- [ ] **Step 3: Implement `check_doc_roundtrip`**

Order of checks, each a panic with the doc's `Debug` in the message on failure:
1. `bytes = doc.build().unwrap()`; `file = decode(&bytes).unwrap()`; `doc.expected().assert_matches(&file)`.
2. `hs = Hashset::load(&bytes).unwrap()`; `hs.verify_digest()`; `hs.verify().is_ok()`.
3. Review Focus 5: for each section and each distinct stored hash, `hs.records_for(idx, h)` as a set of record bytes equals the records whose field value is `h` per `expected.ridx`; `hs.equal_range(idx, h).len()` equals the hash's multiplicity.
4. `doc.build().unwrap() == bytes` (determinism).
5. When `with_records`: `Builder::with_fields(file.rhdr.fields.clone())` plus `add_raw_record` for every `file.record(i)`, built with `doc.opts.build_options()`, equals `bytes`.

- [ ] **Step 4: Run**

Run: `cargo test -p hset --test prop_format`
Expected: PASS (if the proptest fails, that is a finding: commit the minimal case as a `#[test]` first, then fix in its own commit).

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit rust/hset/tests/prop_format.rs rust/hset/tests/proptest-regressions
git commit -m "test(rust): property test of build/decode/verify/rebuild against the Doc oracle"
```

---

### Task 7: `prop_lookup.rs`: every strategy agrees with `NaiveSet`

**Files:**
- Modify: `hset-testkit/src/checks.rs`
- Create: `hset/tests/prop_lookup.rs`

**Interfaces:**
- Consumes: `LookupCase` from Task 4.
- Produces: `pub fn check_lookup(case: &LookupCase)`.

- [ ] **Step 1: Write `hset/tests/prop_lookup.rs`**

```rust
proptest! {
    #[test] fn strategies_match_naive(case in lookup_case()) { check_lookup(&case); }
}
```

- [ ] **Step 2: Run to verify it fails to compile**

Run: `cargo test -p hset --test prop_lookup`

- [ ] **Step 3: Implement `check_lookup`**

1. `hint = build_hint(case.hlen, &case.data, case.hint)`: when `hlen == UNSUPPORTED_LENGTH && hint != HintSpec::None` assert `is_err()` and return; otherwise unwrap.
2. `lk = make_lookup_with(hlen, &data, hint.as_ref().map(|(t, b)| hint_from_parts(*t, b)).as_ref(), case.cfg).unwrap()`; `naive = NaiveSet::from_bytes(&data, hlen)`.
3. For every query `q`: `lk.find(q) == naive.find(q)`, `lk.contains(q) == naive.contains(q)`, `lk.equal_range(q) == naive.equal_range(q)`; when found, `lk.window(q).contains(&i)`.
4. For every stored hash `i`: `lk.window(h).contains(&i)`, `lk.find(h) == naive.find(h)`.
5. Batches: for `size` in `[0, 1, 7, 8, 9, 255, 256, 257, m]` with `size <= m`: `contains_batch(&queries[..size * hlen], &mut out)` equals per-query `naive.contains`.
6. Review Focus 3: for the first 8 queries, append 5 extra `0xA5` bytes and assert `contains`, `find` and `equal_range` equal the exact-length answers; `contains_batch` is only defined for exact widths, so it is not called here.

- [ ] **Step 4: Run**

Run: `cargo test -p hset --test prop_lookup`
Expected: PASS at 256 cases in under 5 s. Then `PROPTEST_CASES=5000 cargo test -p hset --test prop_lookup` to smoke the deeper tier; findings follow the regression-then-fix rule.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit rust/hset/tests/prop_lookup.rs rust/hset/tests/proptest-regressions
git commit -m "test(rust): property test of every lookup strategy against a naive set"
```

---

### Task 8: `prop_ops.rs`: set algebra against the model

**Files:**
- Modify: `hset-testkit/src/checks.rs`
- Create: `hset/tests/prop_ops.rs`

**Interfaces:**
- Produces:

```rust
/// Build both docs, decode, `ops::apply`. Returns the result rows in the
/// canonical layout (fields ascending by `(htype, length)`) or `None` when
/// `apply` returned an error.
pub fn apply_rows(op: SetOp, a: &Doc, b: &Doc) -> Option<BTreeSet<Vec<u8>>>;
pub fn canonical_layout(doc: &Doc) -> Vec<FieldDescriptor>;   // descriptors sorted by (htype, length), names from `doc`
/// apply_rows == set_op_model over op_rows in the canonical layout, or the documented error:
/// error iff type sets differ, or an operand has `!with_records && fields.len() != 1`.
pub fn check_set_op(op: SetOp, a: &Doc, b: &Doc);
```

- [ ] **Step 1: Write `hset/tests/prop_ops.rs`**

```rust
proptest! {
    #[test] fn apply_matches_model((a, b) in doc_pair(), op in set_op()) { check_set_op(op, &a, &b); }
    #[test] fn union_commutes((a, b) in doc_pair()) {
        prop_assert_eq!(apply_rows(SetOp::Union, &a, &b), apply_rows(SetOp::Union, &b, &a));
    }
    #[test] fn intersection_within_both((a, b) in doc_pair()) {
        // if all three succeed: i ⊆ union(a,a) and i ⊆ union(b,b) (self-union == the operand's rows)
    }
    #[test] fn difference_disjoint_from_right((a, b) in doc_pair()) {
        // if both succeed: (a - b) ∩ rows(b) == ∅ where rows(b) = apply_rows(Union, &b, &b)
    }
    #[test] fn union_minus_right_is_difference((a, b) in doc_pair()) {
        // (A ∪ B) − B == A − B, computed via apply_rows on docs where that is expressible: compare set_op_model(Subtract, union_rows, b_rows) with apply_rows(Subtract, &a, &b)
    }
    #[test] fn result_builds_and_decodes((a, b) in doc_pair(), op in set_op()) {
        // apply(..) Ok -> .build(&Opts::default_for_tests().build_options()) Ok -> Hashset::load Ok and verify().is_ok()
    }
    #[test] fn mismatched_types_error((a, b) in doc_pair_mismatched()) {
        // apply_rows(Union, &a, &b).is_none() and the error Display contains "mismatch"
    }
}
```

- [ ] **Step 2: Run to verify it fails to compile**

Run: `cargo test -p hset --test prop_ops`

- [ ] **Step 3: Implement `apply_rows`, `canonical_layout`, `check_set_op`**

`check_set_op` also asserts the error kind is `Error::Input` and that the Display contains `"mismatch"` for type mismatches or `"no records"` / `"set operations need records"` for the records-less case.

- [ ] **Step 4: Run**

Run: `cargo test -p hset --test prop_ops`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit rust/hset/tests/prop_ops.rs rust/hset/tests/proptest-regressions
git commit -m "test(rust): property tests of union, intersection and difference against a set model"
```

---

### Task 9: `prop_hex.rs`: SIMD levels, row APIs and rejection

**Files:**
- Modify: `hset-testkit/src/checks.rs`
- Create: `hset/tests/prop_hex.rs`

**Interfaces:**
- Produces:

```rust
pub fn simd_levels() -> Vec<fearless_simd::Level>;   // [Level::baseline(), Level::new()] (hset-testkit gains `fearless_simd.workspace = true`)
pub fn check_hex(bytes: &[u8]);                       // per level: encode_into_at == hex_oracle::encode; decode_into_at inverts; uppercase accepted; for up to 64 positions, replacing one digit by each of b'g', b'/', b':', 0xC3 is rejected by decode_into_at and by hex::decode; hex::decode of the string minus its last char is Err when non-empty (odd length)
pub fn check_hex_rows(data: &[u8], width: usize, sep: &[u8]); // precondition data.len() % width == 0: encode_rows and encode_rows_to_writer equal the oracle's per-row hex + sep; decode_rows of the oracle strings returns data and the row count; a row of the wrong length and a row with a bad digit both return Err and leave `out` unchanged
```

- [ ] **Step 1: Write `hset/tests/prop_hex.rs`**

```rust
proptest! {
    #[test] fn levels_agree_with_oracle(bytes in vec(any::<u8>(), 0..=300)) { check_hex(&bytes); }
    #[test] fn rows_agree_with_oracle(rows in vec(any::<u8>(), 0..=400), width in 1usize..=70, sep in vec(any::<u8>(), 0..=3)) {
        let data = &rows[..rows.len() / width * width];
        check_hex_rows(data, width, &sep);
    }
    #[test] fn odd_length_rejected(s in "[0-9a-fA-F]*") {
        prop_assert_eq!(hset::hex::decode(&s).is_ok(), s.len() % 2 == 0);
    }
}
```

- [ ] **Step 2: Run to verify it fails to compile**

- [ ] **Step 3: Implement `simd_levels`, `check_hex`, `check_hex_rows`**

- [ ] **Step 4: Run**

Run: `cargo test -p hset --test prop_hex`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-testkit rust/hset/tests/prop_hex.rs rust/hset/tests/proptest-regressions rust/Cargo.lock
git commit -m "test(rust): property tests of the hex codec at every SIMD level"
```

---

### Task 10: Corruption model and `prop_robustness.rs`

**Files:**
- Create: `hset-testkit/src/corrupt.rs`, `hset/tests/prop_robustness.rs`
- Modify: `hset-testkit/src/lib.rs`, `hset-testkit/src/strategies.rs` (add `corruption()`), `hset-testkit/src/arb.rs` (add `impl Arbitrary for Corruption`), `hset-testkit/src/checks.rs`

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkEdit { Offset(usize, u64), Length(usize, u64), Type(usize, u32) }
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Corruption { pub truncate_to: Option<usize>, pub overwrites: Vec<(usize, u8)>, pub chunk_edits: Vec<ChunkEdit> }
impl Corruption {
    /// Chunk edits, then overwrites, then truncation. Chunk edits resolve
    /// through `hset::format::decode(bytes).toc`; `Offset(i, v)` rewrites FTOC
    /// entry `i % toc.len()`'s offset (bytes `52 + 12 * i ..+8`, LE); `Length(i, v)`
    /// rewrites the length field of chunk `i` (at `toc[i].0 + 4 ..+12`, LE);
    /// `Type(i, v)` rewrites the chunk's own header type (`toc[i].0 ..+4`, BE)
    /// leaving the FTOC entry alone. If the file does not decode, each edit
    /// falls back to writing its value's LE bytes at `i % len`. Overwrites
    /// land at `pos % len`; `truncate_to` truncates to `t % (len + 1)`.
    pub fn apply(&self, bytes: &[u8]) -> Vec<u8>;
}
pub fn strategies::corruption() -> BoxedStrategy<Corruption>; // truncate_to any Option<usize>; 0..=16 overwrites; 0..=4 chunk edits with index any usize and values from prop_oneof![any, Just(0), Just(u64::MAX), Just(1), 0..=8192]
pub fn checks::check_corruption(doc: &Doc, c: &Corruption);   // bytes = build; m = c.apply(&bytes); exercise_loaded(&m); if Hashset::load(&m) is Ok and verify_digest(): assert m == bytes
```

- [ ] **Step 1: Write the kit tests in `corrupt.rs`**

```rust
#[test] fn apply_identity()                 // Corruption::default().apply(b) == b
#[test] fn truncate_is_modulo_len_plus_one() // len 10, truncate_to Some(10) -> 10 bytes; Some(11) -> 0 bytes; Some(3) -> 3
#[test] fn offset_edit_hits_the_toc_entry()  // on a built two_field_doc: Offset(1, 7): bytes[52..60] == 7u64.to_le_bytes(); rest unchanged
#[test] fn length_edit_hits_the_chunk_header() // Length(2, 5): at toc[2].0 + 4 the 8 bytes are 5 LE
#[test] fn type_edit_leaves_toc_alone()      // Type(1, 0x46454E44): chunk header at toc[1].0 reads "FEND"; FTOC entry type unchanged; Hashset::load errors mentioning "FTOC says"
#[test] fn falls_back_to_raw_on_garbage()    // apply on b"not a file" with Offset(3, 1): byte 3.. == 1u64 LE truncated to the buffer
```

- [ ] **Step 2: Write `hset/tests/prop_robustness.rs`**

```rust
proptest! {
    #[test] fn corruption_is_safe(d in doc(), c in corruption()) { check_corruption(&d, &c); }
}
```

- [ ] **Step 3: Run to verify failure**, **Step 4: Implement**, **Step 5: Run**

Run: `cargo test -p hset-testkit corrupt && cargo test -p hset --test prop_robustness`
Expected: PASS. A panic inside `exercise_loaded` is a bug in the decoder or lookup: regression test first, fix second.

- [ ] **Step 6: Commit**

```bash
git add rust/hset-testkit rust/hset/tests/prop_robustness.rs rust/hset/tests/proptest-regressions
git commit -m "test(rust): corruption model and robustness property test"
```

---

### Task 11: `prop_cli.rs`: make, dump, query round trip

**Files:**
- Create: `hset-cli/tests/prop_cli.rs`
- Modify: `hset-cli/Cargo.toml` (dev-dependencies `hset-testkit.workspace = true`, `proptest.workspace = true`)

**Interfaces:**
- Consumes: `strategies::cli_doc()`, `Doc::to_text`, `Doc::type_list`, `Doc::expected`, `hset::builder::format_value`.
- Produces: in the test file, `fn hint_args(spec: HintSpec) -> Vec<String>`: `None` → `--hint none`; `Block{0}` → `--hint block`; `Block{b}` → `--hint block --bits b`; `Hull{255}` → `--hint hull`; `Hull{b}` → `--hint hull --bits b`.

- [ ] **Step 1: Write the test**

```rust
proptest! {
    #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]
    #[test] fn make_dump_query_match_oracle(d in cli_doc(), seed in any::<u64>()) {
        // out = temp_dir()/hset-prop-<pid>-<AtomicUsize counter>.hset
        // hset make -t d.type_list() -n d.opts.name -d d.opts.desc --timestamp d.opts.timestamp --budget d.opts.bits_policy.budget <hint_args> -o out   (stdin = d.to_text()) -> success
        // hset dump out -> stdout lines == expected records rendered: for each row of d.expected().records, fields split per descriptor, format_value or "" joined by ' '
        // hset info out --chunks -> contains "(ok)"
        // first field f: up to 8 query values: present values from records plus 4 random values of the field type (SplitMix64(seed)); rendered via format_value
        // hset query out -t f.htype.field_name() <values> -> each stdout line "<value>\tfound" or "\tmissing" per NaiveSet over the expected section; exit code 0 iff all found else 1
        // remove out
    }
}
```

- [ ] **Step 2: Run to verify it fails** (dev-dep missing) **Step 3: Add dev-dependencies, implement helpers** **Step 4: Run**

Run: `cargo test -p hset-cli --test prop_cli`
Expected: PASS in under 3 s.

- [ ] **Step 5: Commit**

```bash
git add rust/hset-cli rust/Cargo.lock
git commit -m "test(rust): CLI make/dump/query property test on the Doc oracle"
```

---

### Task 12: In-crate proptests: `lookup::hull`, `lookup::model`, `key`, `hash_type`

**Files:**
- Modify: `hset/src/lookup/hull.rs`, `hset/src/lookup/model.rs`, `hset/src/key.rs`, `hset/src/hash_type.rs` (each gains `#[cfg(test)] mod proptests` using `proptest::prelude::*` only)

- [ ] **Step 1: Write the tests**

```rust
// hull.rs
#[test] fn fitted_bounds_cover_points(xs in vec(any::<u32>(), 1..=64))
    // sort xs; e = fit_block(0..n, |i| xs[i]); for each i: rmin <= i - e.predict(xs[i]) <= rmax
#[test] fn fit_is_no_worse_than_chord_or_zero_slope(xs in vec(any::<u32>(), 2..=64))
    // width(e) <= width(entry with slope 0) + 1 and <= width(entry with the rounded chord slope) + 1, where width(entry) is the residual span measured with `predict` over the same points; the +1 is the integer rounding of the chosen slope
#[test] fn entry_bytes_roundtrip(slope in any::<u32>(), rmin in any::<i32>(), rmax in any::<i32>())
#[test] fn table_sound_on_random_rows(rows in vec(any::<[u8; 20]>(), 0..=300), bits in 0u8..=10)
    // sort+dedup rows; build_table::<20>; for each i: window(frac_of(key, bits), n) contains i

// model.rs
#[test] fn block_index_monotone(a in any::<u64>(), b in any::<u64>(), bits in 0u8..=32)
    // a <= b implies block_index(a, bits) <= block_index(b, bits)
#[test] fn frac_monotone_within_block(a in any::<u64>(), b in any::<u64>(), bits in 0u8..=32)
    // a <= b && block_index(a) == block_index(b) implies frac_of(a, bits) <= frac_of(b, bits)

// key.rs (macro over L in 4, 8, 16, 20, 28, 32, 48, 64)
#[test] fn key64_const_matches_dyn_L(h in any::<[u8; L]>())           // key64::<L>(&h) == key64_dyn(&h)
#[test] fn cmp_hash_matches_slice_cmp_L(a in any::<[u8; L]>(), flip in prop::option::of(0usize..L))
    // b = a with byte `flip` xored by 1 when Some, else a fresh any::<[u8; L]>: cmp_hash::<L>(&a, &b) == a.cmp(&b); tail_eq::<L> == (a[8.min(L)..] == b[8.min(L)..])

// hash_type.rs
#[test] fn roundtrip_over_all(t in prop::sample::select(&HashType::ALL[..]))
    // from_bits(t.bits()) == Some(t); from_log2(t.log2()) == Some(t); parse(t.name()) == Ok(t); parse(t.field_name()) == Ok(t); parse(&t.to_string()) == Ok(t)
#[test] fn from_bits_rejects_non_members(bits in any::<u32>())
    // from_bits(bits).is_some() == HashType::ALL.iter().any(|t| t.bits() == bits)
#[test] fn from_log2_rejects_out_of_range(v in 15u16..)
    // from_log2(v) == None
```

- [ ] **Step 2: Run to verify compile failure** (`proptest` import) then **Step 3: add nothing but the modules** (dev-dependency already present from Task 5) **Step 4: Run**

Run: `cargo test -p hset --lib proptests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/hset/src
git commit -m "test(rust): in-crate proptests for hull fitting, block arithmetic, keys and hash types"
```

---

### Task 13: In-crate proptests: `ops::merge`, `builder`, `format::chunk`

**Files:**
- Modify: `hset/src/ops.rs`, `hset/src/builder.rs`, `hset/src/format/chunk.rs`

- [ ] **Step 1: Write the tests**

```rust
// ops.rs
#[test] fn merge_matches_btreeset(width in 1usize..=8, a in btree_set(vec(any::<u8>(), 1), 0..=40), b in btree_set(.., 0..=40))
    // rows of exactly `width` bytes: use vec(any::<u8>(), width) via prop_flat_map; for each SetOp: merge(op, &a_bytes, &b_bytes, width) == concat of set_op over the BTreeSets (union/intersection/difference)

// builder.rs
#[test] fn sorted_rows_matches_sort_dedup(width in 1usize..=8, rows in vec(any::<u8>(), ..), dedup in any::<bool>())
    // data truncated to a multiple of width; sorted_rows(data, width, dedup) == rows sorted (and deduped when dedup) by Vec sort
#[test] fn parse_format_roundtrip(t in select(STORABLE types), raw in vec(any::<u8>(), 0..=64), f in any::<f64>().prop_filter("finite", |f| f.is_finite()))
    // value = Entropy: f.to_le_bytes(); Size/digests: raw resized to t.length(); parse_value(&FieldDescriptor::for_type(t), &format_value(&fd, &value)) == Ok(value)
#[test] fn add_text_line_rejects_wrong_column_count(cols in 0usize..=5)
    // Builder::new(&[Md5, Size]); line = " ".repeat(cols.saturating_sub(1)) (cols empty columns): add_text_line is Ok iff cols <= 2
    // (cols 0 or 1 give "" which is skipped; cols == 2 gives " ", a record with both fields absent; more columns is Err(Error::Input))

// format/chunk.rs
#[derive(Debug, Clone)] enum Prim { U8(u8), LeU16(u16), LeU32(u32), LeU64(u64), BeU16(u16), BeU32(u32), Bytes(Vec<u8>), PString(String), Zeros(usize) }
#[test] fn out_primitives_read_back(prims in vec(prim(), 0..=32))
    // write all with Out, read back with Cursor::new(&buf, 0) in order, each equal; cursor.is_empty() at the end (PString strings up to 100 chars; Zeros up to 16 read back via bytes(n) all zero)
#[test] fn cursor_never_panics(buf in vec(any::<u8>(), 0..=64), pos in prop_oneof![0usize..=70, any::<usize>()])
    // Cursor::new(&buf, pos).is_ok() == (pos <= buf.len()); when Ok, each of u8/le_u16/le_u32/le_u64/be_u16/be_u32/pstring/bytes(n in 0..=70) returns Ok having advanced exactly its width, or Err with position unchanged
#[test] fn read_chunk_never_panics(buf in vec(any::<u8>(), 0..=64), off in prop_oneof![0usize..=70, any::<usize>()])
    // read_chunk(&buf, off) is Ok iff off + 12 <= len and the length fits in the remaining bytes
#[test] fn pstring_roundtrip(s in "\\PC{0,300}")
    // Out::pstring then Cursor::pstring == s
```

- [ ] **Step 2: Run to verify compile failure**, **Step 3: implement the strategies and tests**, **Step 4: Run**

Run: `cargo test -p hset --lib proptests`
Expected: PASS.

- [ ] **Step 5: Verify the gate still fits**

Run: `cd rust && time just test`
Expected: all green, under 30 s. If over, lower per-file cases with `#![proptest_config(ProptestConfig { cases: 64, .. })]` on the slowest files first (`prop_lookup`, `prop_robustness`) and record the choice in a comment.

- [ ] **Step 6: Commit**

```bash
git add rust/hset/src
git commit -m "test(rust): in-crate proptests for row merge, builder parsing and chunk cursors"
```

---

### Task 14: Fuzz crate, dictionary, seeds and fuzz recipes

**Files:**
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/{decode_bytes,corrupt_doc,lookup,build_doc,set_ops,hex,text_input}.rs`, `fuzz/hset.dict`, `fuzz/README.md`, `fuzz/corpus/<target>/*`, `fuzz/.gitignore`
- Modify: `justfile` (`lint`, `fuzz`, `fuzz-ci`, `fuzz-seed`), `hset-testkit/src/checks.rs` (`check_text_input`)

**Interfaces:**
- Consumes: `checks::{exercise_loaded, check_corruption, check_lookup, check_doc_roundtrip, check_set_op, check_hex, check_hex_rows}`, `Arbitrary for Doc, LookupCase, Corruption`.
- Produces: `pub fn checks::check_text_input(text: &str)`: for each field set in `[[Md5], [Sha1, Size], [Entropy], [Md5, Sha1, Size]]`, `Builder::add_text(text)` never panics and `is_ok()` equals an oracle over `text.lines()` (after stripping one trailing `'\r'`: empty line accepted; else exactly `fields.len()` columns split on `' '`; each non-empty column accepted when digest: `len == 2 * length` and all `is_ascii_hexdigit`; Size: `u64::from_str` ok; Entropy: `f64::from_str` ok); also `parse_value` on each column never panics.

- [ ] **Step 1: Write `fuzz/Cargo.toml`**

```toml
[package]
name = "hset-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1.4", features = ["derive"] }
hset = { path = "../hset" }
hset-testkit = { path = "../hset-testkit" }

# One [[bin]] per target, each with test = false, doc = false, bench = false:
# decode_bytes, corrupt_doc, lookup, build_doc, set_ops, hex, text_input
```

`fuzz/.gitignore`: `target/`, `artifacts/`, `coverage/`, `Cargo.lock` is committed (not ignored).

- [ ] **Step 2: Write the seven targets**

Each is `#![no_main]` plus one `fuzz_target!`:

| target | signature | body |
|---|---|---|
| `decode_bytes` | `\|data: &[u8]\|` | `exercise_loaded(data);` |
| `corrupt_doc` | `\|input: (Doc, Corruption)\|` | `check_corruption(&input.0, &input.1)` |
| `lookup` | `\|case: LookupCase\|` | `check_lookup(&case)` |
| `build_doc` | `\|doc: Doc\|` | `check_doc_roundtrip(&doc)` |
| `set_ops` | `\|input: (Doc, Doc, u8)\|` | op from `input.2 % 3` → Union/Intersect/Subtract; `check_set_op(op, &input.0, &input.1)` |
| `hex` | `\|data: &[u8]\|` | `check_hex(data)`; then if `data.len() >= 2`: `width = 1 + data[0] as usize % 64`, `sep = &data[1..1 + (data[1] % 4) as usize]` (bounded by len), `rows = &data[rest..]` truncated to a multiple of `width`, `check_hex_rows(rows, width, sep)` |
| `text_input` | `\|text: &str\|` | `check_text_input(text)` |

- [ ] **Step 3: Write `fuzz/hset.dict`**

Entries: `magic="SetOHash"`, `ftoc="FTOC"`, `fhdr="FHDR"`, `rhdr="RHDR"`, `rdat="RDAT"`, `hdat="HDAT"`, `hint="HINT"`, `ridx="RIDX"`, `fltr="FLTR"`, `fend="FEND"`, `hh_md5="HH\x00\x00"`, `hh_sha1="HH\x00\x01"`, `hh_sha256="HH\x00\x03"`, `hh_size="HH\x00\x0d"`, `hull8="h\x08"`, `hull0="h\x00"`, `block8="b\x08"`, `block1="b\x01"`, `version2="\x02\x00\x00\x00\x00\x00\x00\x00"`, `len0="\x00\x00\x00\x00\x00\x00\x00\x00"`.

- [ ] **Step 4: Add recipes to `justfile`**

Append to `lint` a second line: `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`, and add:

```just
# Fuzz one target without a time limit: `just fuzz lookup`. Extra arguments
# go to libFuzzer. New inputs land in target/fuzz-corpus so the committed
# seeds stay clean (fuzz/README.md).
fuzz target *extra:
    #!/bin/sh
    set -eu
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        echo "SKIP: cargo-fuzz not installed; cargo install cargo-fuzz" >&2
        exit 0
    fi
    case "{{ target }}" in lookup) max_len=1048576 ;; *) max_len=65536 ;; esac
    mkdir -p "target/fuzz-corpus/{{ target }}" "fuzz/corpus/{{ target }}"
    cargo fuzz run -s {{ fuzz_sanitizer }} "{{ target }}" \
        "target/fuzz-corpus/{{ target }}" "fuzz/corpus/{{ target }}" -- \
        -timeout=10 -rss_limit_mb=2048 -dict=fuzz/hset.dict -max_len=$max_len {{ extra }}

# Bounded fuzzing: every target, FUZZ_SECONDS each.
fuzz-ci:
    #!/bin/sh
    set -eu
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        echo "SKIP: cargo-fuzz not installed; cargo install cargo-fuzz" >&2
        exit 0
    fi
    targets=$(cargo fuzz list)
    if [ -z "$targets" ]; then
        echo "no fuzz targets found under fuzz/fuzz_targets/" >&2
        exit 1
    fi
    for target in $targets; do
        echo "fuzzing $target for {{ fuzz_seconds }}s"
        just fuzz "$target" -max_total_time={{ fuzz_seconds }}
    done

# Fold the scratch corpus of one target into the committed seeds, minimised.
fuzz-seed target:
    #!/bin/sh
    set -eu
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        echo "SKIP: cargo-fuzz not installed; cargo install cargo-fuzz" >&2
        exit 0
    fi
    mkdir -p "fuzz/corpus/{{ target }}"
    cargo fuzz cmin -s {{ fuzz_sanitizer }} "{{ target }}" "fuzz/corpus/{{ target }}" "target/fuzz-corpus/{{ target }}"
```

- [ ] **Step 5: Build and smoke every target**

Run: `cd rust && cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings && FUZZ_SECONDS=20 just fuzz-ci`
Expected: all seven targets build and run 20 s each without a crash. A crash is a finding: `cargo fuzz run <target> fuzz/artifacts/<target>/<file>` reproduces it; decode the artifact with the same `Arbitrary` type (`arbitrary::Unstructured::new(&bytes)` then `Doc::arbitrary_take_rest`) and paste its `Debug` output into a `#[test]` in the matching `prop_*.rs`, commit, then fix.

- [ ] **Step 6: Seed the corpora**

For `decode_bytes`: copy every committed `/work/test/*.hset` fixture smaller than 64 KiB into `fuzz/corpus/decode_bytes/` (check with `ls -l /work/test/*.hset`). For the other six: `just fuzz-seed <target>` after the smoke run, then keep the result only if it is under 1 MiB and 200 files per target (`du -sh fuzz/corpus/<target>; ls fuzz/corpus/<target> | wc -l`); otherwise `cargo fuzz cmin` again with `-- -max_len=4096` to shrink.

- [ ] **Step 7: Write `fuzz/README.md`**

Sections: the two-corpus arrangement (`fuzz/corpus` committed seeds, `target/fuzz-corpus` scratch), limits (`-timeout=10 -rss_limit_mb=2048`, `max_len` per target, debug assertions on), running (`just fuzz <target>`, `just fuzz-ci`, `FUZZ_SANITIZER=address` needs Linux), replay (`cargo fuzz run <target> fuzz/artifacts/<target>/<file>`), promotion to a proptest regression (decode with the `Arbitrary` type, paste the `Debug` into a `#[test]`), and `just fuzz-seed`.

- [ ] **Step 8: Commit**

```bash
git add rust/fuzz rust/justfile rust/hset-testkit
git commit -m "test(rust): cargo-fuzz targets over the test kit, dictionary, seed corpora and recipes"
```

---

### Task 15: Kani fast harnesses and `just verify`

**Outcome (2026-10-03):** the eight `format::chunk` Cursor harnesses and
`synth::below_is_below` were pulled from the "Fast" table below and
reclassified as "not amenable" (covered by proptest and fuzz instead): the
Cursor error path's `format!` and `below`'s 128-bit product do not converge
under Kani without stubbing or production changes (commit 8b4d434).

**Files:**
- Modify: `hset/src/lookup/hull.rs`, `hset/src/lookup/model.rs`, `hset/src/key.rs`, `hset/src/format/chunk.rs`, `hset/src/hex.rs`, `hset/src/hash_type.rs`, `hset/src/lookup/mod.rs`, `hset/src/synth.rs` (each gains `#[cfg(kani)] mod proofs` at the bottom), `justfile`

**Interfaces:**
- Produces: `just verify` = `cargo kani -p hset` guarded by a `SKIP:` when `cargo kani --version` fails.

- [ ] **Step 1: Add the `verify` recipe**

```just
# Model-check the pure integer functions of hset with Kani, if installed.
verify:
    #!/bin/sh
    set -eu
    if ! cargo kani --version >/dev/null 2>&1; then
        echo "SKIP: kani not installed. cargo install kani-verifier && cargo kani setup" >&2
        exit 0
    fi
    cargo kani -p hset
```

- [ ] **Step 2: Write the harnesses**

Each takes its inputs from `kani::any()`, states assumptions with `kani::assume`, and asserts with `assert!`:

| module | harness | unwind | assumption → assertion |
|---|---|---|---|
| `lookup::hull` | `window_within_bounds` | 1 | `e: HullEntry` (fields any), `frac`, `n` → `(lo, hi) = e.window(frac, n)`; `lo <= hi && hi <= n` |
| | `entry_bytes_roundtrip` | 16 | `HullEntry::from_bytes(&e.to_bytes()) == e` |
| | `is_empty_iff_rmin_gt_rmax` | 1 | `e.is_empty() == (e.rmin > e.rmax)` |
| `lookup::model` | `flat_window_within_bounds` | 2 | `FlatBlocks { bits: 0, table: vec![(dmin, dmax)] }`, `hash: [u8; 4]`, `n` → `lo <= hi <= n` |
| | `hull_batch_of_one_matches_window` | 2 | `HullBlocks { bits: 0, table: vec![e] }`, `k`, `n`; `window_batch(&[k], &[], 0, n, lo, hi)` → `(lo[0], hi[0]) == e.window(frac_of(k, 0), n)` |
| | `block_index_and_frac_split_the_key` | 1 | `bits <= 32` → `block_index(key, bits) < 1usize << bits` and `((block_index as u64) << 32) \| u64::from(frac_of(key, bits)) == key >> (32 - bits)` |
| `key` | `key64_matches_dyn_L` for L in 4, 8, 16, 20, 28, 32, 48, 64 (macro) | L + 1 | `h: [u8; L]` → `key64::<L>(&h) == key64_dyn(&h)` |
| | `cmp_hash_matches_slice_cmp_L` (same macro) | L + 1 | `cmp_hash::<L>(&a, &b) == a.cmp(&b)` |
| | `expected_index_below_n` | 1 | `n > 0` → `expected_index(&h, n) < n` for `h: [u8; 4]` |
| `format::chunk` | `cursor_new_rejects_past_end` | 17 | `buf: [u8; 16]`, `len <= 16`, `pos` any → `Cursor::new(&buf[..len], pos).is_ok() == (pos <= len)` |
| | `cursor_P_consumes_or_fails` for P in u8, le_u16, le_u32, le_u64, be_u16, be_u32 (macro, width W) | 17 | `pos <= len` → after `c.P()`: `Ok` implies `position == pos + W`; `Err` implies `position == pos && pos + W > len` |
| | `cursor_bytes_consumes_or_fails` | 17 | `n <= 32` → `c.bytes(n)` `Ok` iff `n <= len - pos`, position accordingly |
| `hex::scalar` | `decode_pair_iff_hex_digits` | 2 | `src: [u8; 2]` → `scalar::decode_into(&src, &mut [0u8; 1]) == (src[0].is_ascii_hexdigit() && src[1].is_ascii_hexdigit())` |
| | `decode_inverts_encode_byte` | 3 | `b: u8` → encode into 2 bytes, decode back → `== b` |
| `hash_type` | `from_log2_and_from_bits_invert_accessors` | 16 | for `t in HashType::ALL`: `from_log2(t.log2()) == Some(t)`, `from_bits(t.bits()) == Some(t)` |
| | `from_log2_none_out_of_range` | 16 | `v >= 15` → `from_log2(v) == None` |
| | `from_bits_none_for_non_members` | 16 | `bits.count_ones() != 1 \|\| bits >= 1 << 15` → `from_bits(bits) == None` |
| `lookup` | `bits_policy_choose_within_bounds` | 26 | `min_bits <= max_bits <= 24`, `budget.is_finite() && budget >= 0.0` → `(min..=max).contains(&choose(n, hash_length, entry_len))` |
| `synth` | `below_is_below` | 1 | `b > 0` → `SplitMix64(any).below(b) < b` |

Error paths in `chunk` build a `String` with `format!`; if a `cursor_*` harness exceeds five minutes, keep its `Ok` half (assume `pos + W <= len`) and prove the `Err` half as `c.P().is_err()` only, noting the split in the harness comment. If `BitsPolicy::choose` fails under Kani because `f64::powi` is unsupported, rewrite `choose` to `(entry_len as f64) * ((1u64 << (bits + 1)) as f64)` in its own commit (identical for `bits <= 24`; the existing `bits_policy_scales_with_size` test guards it).

- [ ] **Step 3: Run**

Run: `cd rust && time just verify`
Expected: every harness `SUCCESSFUL`; note any harness over one minute in its doc comment. `cargo test -p hset` still passes (the proofs modules are not compiled under test). `just lint` passes (`check-cfg` from Task 1 keeps `cfg(kani)` from warning).

- [ ] **Step 4: Commit**

```bash
git add rust/hset/src rust/justfile
git commit -m "verify(rust): Kani proofs for hull windows, block arithmetic, keys, cursors, hex and hash types"
```

---

### Task 16: Kani slow harnesses and `just verify-slow`

**Outcome (2026-10-03): done, every harness removed.** All three ran past 3 GiB
within five minutes under a cgroup cap, and so did two-point `fit_block` and
two-byte `merge` variants; an uncapped `just verify-slow` was OOM-killed at
~10 GiB on the 11 GiB VM, taking the tmux session with it. `fit_block` dies in
SAT on `choose_slope`'s symbolic `f64`; `merge` dies in symex on symbolic-length
`memcmp`/`memcpy`. The `kani_slow` cfg and `verify-slow` recipe were dropped
with them (nothing would remain under them); the covering proptests carry a
note. Run Kani only as `systemd-run --user --scope -p MemoryMax=3G -p
MemorySwapMax=0 -- timeout 600 cargo kani ...` from now on.

**Files:**
- Modify: `hset/src/lookup/hull.rs`, `hset/src/ops.rs`, `justfile`

- [ ] **Step 1: Add the recipe**

```just
# The harnesses `verify` skips because they run past what the fast gate
# allows (`#[cfg(kani_slow)]`). RUSTFLAGS carries the cfg into cargo kani.
verify-slow:
    #!/bin/sh
    set -eu
    if ! cargo kani --version >/dev/null 2>&1; then
        echo "SKIP: kani not installed. cargo install kani-verifier && cargo kani setup" >&2
        exit 0
    fi
    RUSTFLAGS="--cfg kani_slow" cargo kani -p hset
```

- [ ] **Step 2: Write the harnesses, each under `#[cfg(kani_slow)]` inside the module's `proofs`**

| module | harness | unwind | property |
|---|---|---|---|
| `lookup::hull` | `fit_block_three_points_covers_them` | 8 | `xs: [u32; 3]` assumed non-decreasing → `e = fit_block(0..3, \|i\| xs[i])`; for each i `rmin <= i - e.predict(xs[i]) <= rmax` |
| | `fit_block_four_points_covers_them` | 10 | same with `[u32; 4]` |
| `ops` | `merge_matches_model_width_one` | 8 | `a: [u8; 3]`, `b: [u8; 3]` with lengths `na, nb <= 3` assumed strictly increasing → for each `SetOp`, `merge(op, &a[..na], &b[..nb], 1)` equals the model: byte `x` present iff (`in_a \|\| in_b`) / (`in_a && in_b`) / (`in_a && !in_b`), output sorted |

- [ ] **Step 3: Time each**

Run: `cd rust && time just verify-slow`, then each harness alone with `RUSTFLAGS="--cfg kani_slow" cargo kani -p hset --harness <name>`.
Expected: record wall time per harness in its doc comment. Remove any harness over ten minutes (delete it, say so in the commit message). `fit_block` goes through `Vec`, `f64` division and `round`; if CBMC rejects a float operation, remove those two harnesses the same way.

- [ ] **Step 4: Commit**

```bash
git add rust/hset/src rust/justfile
git commit -m "verify(rust): slow Kani harnesses for hull fitting and row merge behind --cfg kani_slow"
```

---

### Task 17: Mutation testing configuration, `check-slow`, and the README tier table

**Outcome (2026-10-03):** the base commit (205a170) already diverged from
the draft recipes below in two places: `mutants-diff`'s `git diff` gained
`--relative` (cargo-mutants expects diff paths rooted at `rust/`; without
it every path is prefixed with `rust/` and nothing matches), and the
`exclude_re` pattern is `\bproofs::`, not `::proofs::` (cargo-mutants prints
mutant locations as bare paths with no leading `::`). Three follow-up fixes
landed after: 8a4ef6c and fc760dc add `HSET_FIXTURES_DIR` (cargo-mutants
copies only the `rust/` workspace into its per-mutant tempdir, so the C++
fixtures under `test/`, outside the workspace, were missing until the
`mutants`/`mutants-diff` recipes exported it) and harden the guard against
a missing `../test`; 574f3c9 adds `OOMPolicy=continue` to the `mutants`
systemd-run scope (the scope's default policy stopped the whole run on the
first OOM kill from one runaway mutant).

**Files:**
- Create: `.cargo/mutants.toml`
- Modify: `justfile`, `README.md` ("Building and testing"), `.gitignore` (already has `/mutants.out`)

- [ ] **Step 1: Write `.cargo/mutants.toml`**

```toml
# cargo-mutants configuration. Every exclusion says why the mutation is
# unobservable; anything else that survives gets a test or is removed.
test_tool = "nextest"

# Test infrastructure and benchmarks are not the system under test.
exclude_globs = ["hset-testkit/**", "**/benches/**", "**/examples/**"]

exclude_re = [
    "::proofs::",            # Kani harnesses: not compiled under cfg(test), no test can see them
    "\\bprefetch\\b",        # cache hint with no observable result
    "\\bprefetch_entry\\b",  # same, on the Model trait
    "::describe\\b",         # diagnostics text
    "::table_bytes\\b",      # diagnostics
    "::mean_window\\b",      # diagnostics; only steers which batch path runs, answers are identical
    "SetOp::name\\b",        # diagnostics
]

# A mutant that breaks a loop bound in the search or the merge runs until
# stopped; memory is capped by the systemd-run scope in `just mutants`.
minimum_test_timeout = 60
timeout_multiplier = 3
```

Verify the patterns: `cargo mutants --list -p hset | grep -c -E 'describe|table_bytes|mean_window|prefetch|proofs'` prints `0`, and `cargo mutants --list --workspace | grep -c testkit` prints `0`.

- [ ] **Step 2: Add the recipes**

```just
# Mutation-test one crate: `just mutants hset`. A runaway mutant eats memory
# first, so on Linux the run sits in a systemd scope with a hard cap.
mutants crate:
    #!/bin/sh
    set -eu
    if ! command -v cargo-mutants >/dev/null 2>&1; then
        echo "mutants: cargo-mutants is required (cargo install cargo-mutants)" >&2
        exit 1
    fi
    if ! command -v systemd-run >/dev/null 2>&1; then
        echo "NOTE: systemd-run not found; running cargo-mutants without a memory cap" >&2
        cargo mutants --package {{ crate }} -j {{ mutants_jobs }}
        exit 0
    fi
    systemd-run --user --scope -q -p MemoryMax={{ mutants_memory }} -p MemorySwapMax=0 \
        cargo mutants --package {{ crate }} -j {{ mutants_jobs }}

# Mutants only in code changed since main: the daily form.
mutants-diff:
    #!/bin/sh
    set -eu
    mkdir -p target
    git diff main... > target/mutants.diff
    cargo mutants --workspace --in-diff target/mutants.diff -j {{ mutants_jobs }}

# Slow gate, run on a cadence: high-count proptests, bounded fuzzing, the
# Kani harnesses, then mutation testing.
check-slow: prop fuzz-ci verify
    #!/bin/sh
    set -eu
    for crate in hset hset-cli; do
        just mutants "$crate"
    done
```

Also require nextest in `test` the same way: a `command -v cargo-nextest` check that exits 1 with `test: cargo-nextest is required (cargo install cargo-nextest)`.

- [ ] **Step 3: Smoke the mutants recipe**

Run: `cd rust && echo "// touch" >> hset/src/synth.rs && just mutants-diff; git checkout hset/src/synth.rs`
Expected: cargo-mutants runs over the diff (a comment-only change yields zero mutants; that is fine, the point is the plumbing). Then `cargo mutants -p hset --list | wc -l` reports roughly 1,800.

- [ ] **Step 4: Update `README.md` "Building and testing"**

Replace the four-line shell block with the recipe table from the spec (recipe, what it runs, tier), the environment knobs, and one sentence each on the test kit, the fuzz crate (pointing at `fuzz/README.md`), Kani and the mutants triage policy.

- [ ] **Step 5: Run the gate**

Run: `cd rust && just check`
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add rust/.cargo/mutants.toml rust/justfile rust/README.md
git commit -m "test(rust): cargo-mutants configuration, mutants recipes, check-slow and the tier table"
```

---

### Task 18: The first run and triage

**Files:**
- Create: `experiments/results/mutants-$(hostname -s)-2026-10-02.md`
- Modify: whatever the findings require (regression tests first, fixes second, exclusions in `.cargo/mutants.toml` with comments)

- [ ] **Step 1: High-count property tests**

Run: `cd rust && just prop`
Expected: green at 20,000 cases. Each failure: proptest writes the seed to `proptest-regressions/`; commit that file plus a named `#[test]` of the shrunk case, then the fix.

- [ ] **Step 2: Fuzzing**

Run: `FUZZ_SECONDS=600 just fuzz-ci`, then `just fuzz lookup` and `just fuzz corrupt_doc` for as long as the VM can be spared (stop with Ctrl-C; libFuzzer leaves the scratch corpus in `target/fuzz-corpus/`). Afterwards `just fuzz-seed lookup` and `just fuzz-seed corrupt_doc`, keeping corpora under the Task 14 size caps.
Expected: no artifacts in `fuzz/artifacts/`. Each artifact: replay, decode to a `#[test]`, commit, fix.

- [ ] **Step 3: Verification**

Run: `just verify` (under a memory cap, see Task 16 outcome).
Expected: all harnesses successful.

- [ ] **Step 4: Mutation testing**

Run: `just mutants hset` (expect 5 to 10 hours; use `run_in_background` or `nohup` and check `mutants.out/outcomes.json`), then `just mutants hset-cli`.
For each entry in `mutants.out/missed.txt`, one of: a new test that kills it (run `cargo mutants -p hset -F '<function>' ` to confirm), an `exclude_re` line with a comment saying why the mutation is unobservable, or removal of dead code.

- [ ] **Step 5: Write the triage summary**

`experiments/results/mutants-<host>-2026-10-02.md`: header with machine, toolchain, commit; totals (tested, caught, missed, timeout, unviable) per crate; one table of surviving mutants with the outcome chosen for each; the list of bugs found by every tier with their commits.

- [ ] **Step 6: Final gate and commit**

Run: `cd rust && just check`
Expected: green, under 30 s for `just test`.

```bash
git add rust/experiments/results rust/.cargo/mutants.toml rust/fuzz/corpus
git commit -m "test(rust): first deep-testing run; mutants triage summary and promoted corpora"
```

---

## Self-review notes

- Spec coverage: justfile recipes (Tasks 1, 14, 15, 16, 17), test kit four parts (Tasks 2, 3, 4, 10) plus shared checks (5 to 10, 14), six integration prop files (6 to 11), seven in-crate proptest modules (12, 13), seven fuzz targets with dictionary, corpora and README (14), fast and slow Kani harnesses (15, 16), mutation config and triage (17, 18), documentation (14, 17), first run (18).
- Names used across tasks: `Doc`, `Field`, `Opts`, `Expected`, `ExpectedSection`, `NaiveSet`, `set_op_model`, `hex_oracle`, `LookupCase`, `Corruption`, `ChunkEdit`, `exercise_loaded`, `check_doc_roundtrip`, `check_lookup`, `check_set_op`, `apply_rows`, `canonical_layout`, `check_hex`, `check_hex_rows`, `check_corruption`, `check_text_input`, `simd_levels`, `strategies::{doc, doc_with, doc_pair, doc_pair_mismatched, cli_doc, lookup_case, corruption, queries, sorted_rows, with_duplicates, hint_specs, search_configs, hash_lengths, set_op}`.
- Deviations from the spec, each deliberate: `test` also runs doctests so the set matches `cargo test`; `search_configs()` adds `passes_sub_batch` edges 0 and 1000 (Review Focus 4); `MUTANTS_MEMORY` knob added so a build OOM under the 3G cap can be raised without editing the justfile; the hull "no worse than chord or zero slope" property allows +1 for slope rounding; `queries()` is a deterministic function so the fuzz `lookup` target and the proptest share it.
