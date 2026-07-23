# Design: Convex-Hull-Bounded Hash-Set Lookup

**Date:** 2026-07-23
**Branch:** `hashset-lookup-perf`
**Status:** Approved design, ready for implementation planning

## Problem

`libhasher`'s hash-set lookup has a dormant algorithmic win. The active strategy
(`BlockLookupStrategy<L,8>`, hint `0x6208`) predicts a hash's position with
`expected_index()` and widens it by a **per-block flat min/max delta** (keyed on
the leading byte) to form a search window, then runs a branchless `lower_bound`
with an integer primary-key compare. The recent perf work optimized this *flat*
block strategy well (1.35x single / 3.2x batch on a Xeon E5645), but it left the
main algorithmic improvement unused:

- `include/hashset/convex_hull.h` computes upper/lower convex hulls. It is tested
  (`test/test_convex_hull.cpp`) but wired into nothing.
- `include/hashset/block_linear_ls.h` (`BlockLinearLookupStrategy`) uses per-block
  **linear** bounds (`slope*exp + intercept`) — exactly what convex-hull
  supporting lines produce, i.e. far tighter than a flat per-block constant — but
  it is disabled: the decoder's `BLOCK_LINEAR` case is `// TODO: implement this`,
  the encoder only ever computes flat min/max (`make_block_bounds`), and the
  strategy still uses a plain `std::binary_search` inside.

Separately, Daniel Lemire observed (private correspondence) that the
dictionary/interpolation search can be made recursive: convex hulls establish
tight bounds *once* (recursive hulls would be too much overhead), and within
those bounds an interpolation ("dictionary") search can eliminate memory
accesses versus binary search — potentially reaching Abseil/Swiss-table
territory. Because these are cryptographic hashes, their bit-randomness gives a
fairly uniform distribution, which makes interpolation search's pathological
O(n) worst case impossible on real data.

## Goal

Re-enable and optimize the convex-hull-bounded lookup, prove it against defined,
cheat-proof benchmarks, and wire the proven winner end-to-end into the `.hset`
format as a new hint type.

**Win condition (both first-class, no regression):** the new strategy must beat,
or at least not regress, the current branchless `block256` on **both** single
`contains()` and batch `contains_batch()`, across the full workload matrix, with
an Abseil-equivalent (`phmap::flat_hash_set`) column as the north-star for
single-lookup memory-access count.

## Guiding principle

**Build and freeze a trustworthy eval harness before touching any algorithm.**
Every candidate — mine or a subagent's — must pass the harness *and* a code
review before it counts. Only a benchmark-proven winner is wired into the
on-disk format. Hash sets are immutable and long-lived, so query performance is
the whole game; build cost is a linear-and-reasonable sanity check, not a tuning
axis.

## Environment constraints (verified 2026-07-23)

- **CPU:** Xeon E5645 (Westmere, 4 cores, SSE4.2, **no AVX2**) — the same box the
  README baselines came from. SIMD candidates are SSE4.2-limited here.
- **`perf`:** assumed available after a VM reboot. The implementation plan must
  verify `perf stat` works (check `perf_event_paranoid`; request a `guest.nix`
  change if not) before relying on counters.
- **`gprof`** available; **`valgrind`** not; **`taskset`** available.
- **Abseil** not present, but **`vendors/parallel-hashmap` (phmap)** is — a
  Swiss-table equivalent, used as the "Abseil territory" baseline.
- **Data:** `/data/nsrl/2.47/nsrl-sha1` is 40,406,763 raw sorted 20-byte SHA-1
  digests (verified: first digest matches `NSRLFile.txt` row 1), mmap'd with zero
  parsing. MD5 (16-byte) can be derived once from `NSRLFile.txt` and cached to
  `$HOME/build`. Scratch artifacts live in `$HOME/build`, never in `/work`.

## Phases

### Phase 1 — The eval harness & anti-cheat gate (foundation, built and frozen first)

Extends the existing standalone `bench/` harness (built with the current
`g++ -O3 -march=native -std=c++17 -Iinclude -Ibench` one-liner pattern, plus an
optional autotools `check_PROGRAM` hook).

**Datasets (multiple, to prevent overfitting):**
- Real NSRL SHA-1 (`nsrl-sha1`, 40.4M x 20B, mmap'd).
- Real NSRL MD5 (16B), derived once from `NSRLFile.txt`, cached.
- Synthetic uniform at several sizes (1M -> 100M) and multiple seeds, for
  scaling curves.
- Adversarial/clustered distributions (non-uniform leading bytes, dense runs) to
  stress the bound-tightness assumption and to prove correctness never *depends*
  on uniformity (only speed does).
- **Tuning set vs. held-out eval set are distinct** (different seeds / disjoint
  NSRL halves). Final leaderboard numbers come only from the held-out set.

**Anti-cheat contract:**
1. *Correctness oracle:* every candidate is validated against `std::binary_search`
   ground truth on a large mixed query stream (guaranteed hits, guaranteed
   misses, near-misses at present-hash +/-1 bit, and boundary hashes with
   all-0x00 / all-0xFF leading bytes) **before** it is timed. Any mismatch =
   disqualified, no time reported.
2. *Timing contract:* build/index construction happens in an untimed setup phase,
   reported separately as a budget; only the query loop is timed; results are
   consumed into a checksum sink (defeats dead-code elimination); queries are
   all-unique and streamed (no warm-cache memoization); set sizes exceed LLC; no
   heap allocation in the timed region (review + optional allocator-hook assert);
   N reps reporting min + median + stddev; candidates run interleaved in one
   process on a `taskset`-pinned core.

**Metrics (four):**
1. ns/lookup — single `contains()` and batch `contains_batch()`, across the
   matrix (4K/1M queries x miss/mix/hit).
2. `perf stat` counters per candidate — `cycles`, `instructions`, IPC,
   `L1-dcache-load-misses`, `LLC-load-misses`, `branch-misses` — isolated to the
   timed query region.
3. In-code probe instrumentation — array-touch + comparison counters in an
   instrumented build; the machine-independent cross-check. Disagreement between
   perf counters and probe counts is itself a red flag.
4. `gprof` call-graph time on hot candidates.

**Baseline/reference columns (the bar):** `std::binary_search` (basic), current
`block256` branchless (single + batch), `phmap::flat_hash_set`,
`std::unordered_set`. Shipped in the harness so every run reproduces the bar.

**Reproducibility:** fixed seeds, pinned core, documented CPU, a single
`bench/eval` driver and a results table checked into the branch.

### Phase 2 — Candidate interface & initial candidate set

**Interface** (`bench/candidates/`): a `Candidate` exposes
- `build(const HashSet&)` — untimed setup (hulls, block tables, auxiliary
  layouts); its wall-time and extra bytes/hash are reported as a budget.
- `contains(hash)` and `contains_batch(hashes, n, stride, out)` — the timed query
  surface, identical to the shipping `LookupStrategy`, so the winner drops
  straight into production with no divergence between benchmarked and shipped
  code (an anti-cheat property).

A candidate is a self-contained struct registered into the suite. Subagents add
files here and touch nothing else in the harness.

**Initial reference candidates (branchless inner loops by default):**
- **C0 `basic`** — `std::binary_search` (floor).
- **C1 `block256`** — current shipping branchless block strategy (the bar).
- **C2 `block-linear`** — per-block hull-derived lower/upper *lines* (revive
  `BlockLinearLookupStrategy` with true convex-hull supporting lines, not fudged
  coefficients).
- **C3 `global-hull`** — full upper/lower hulls + segment search for the tightest
  linear envelope.
- **C4 `fine-block`** — 12-16 leading bits, simple bounds, no query-time hull
  search.
- **C5 `interp`** — Lemire's recursive interpolation/dictionary search within
  hull-established bounds. Depends on cryptographic-hash uniformity (the same
  invariant `expected_index` uses), so no defensive perf fallback; correctness
  stays guaranteed by the search invariant regardless.
- **C6 `hull+interp+branchless-tail`** — the likely synthesis: hull bound -> one
  interpolation probe -> branchless binary on the short tail, batch-pipelined.
- **phmap / unordered** — external reference columns.

Wilder ideas reserved for the subagent round: Eytzinger/BFS layout within the
window, a two-level RMI/learned index replacing the hull, SSE4.2 SIMD-batched
comparison, prefetch-depth tuning for the batch pipeline.

### Phase 3 — Subagent challenge & code-review gate

Once the harness is frozen, each subagent gets the frozen harness + `Candidate`
interface, the current leaderboard and bar, the anti-cheat contract, and a
challenge ("beat C1/C6 on the held-out matrix"), and returns candidate files.

**A submission is accepted only if it passes, in order:**
1. **Correctness** — exact match to the oracle on every dataset including
   adversarial + held-out. One mismatch = rejected.
2. **Anti-cheat code review (me):** no work hidden in captured per-query state; no
   per-query heap alloc; no benchmark-/seed-/dataset-specific constants; no
   tuning on the eval set; no UB that merely happens to pass; the
   `contains`/`contains_batch` surface is the same code that would ship (no
   benchmark-only fast path).
3. **Real win** — beats the bar on the **held-out** set on ns/lookup, *consistent
   with* its perf counters and probe counts. A ns win contradicted by higher LLC
   misses or probe counts is treated as noise and rejected pending explanation.
4. **Generality** — no bad regression on any dataset or on either single/batch
   axis.

Accepted candidates join the leaderboard with a short rationale (why it
won/lost, what the profile showed). Subagents run in parallel (independent
files, no shared mutable state); I review sequentially.

### Phase 4 — Profiling loop

For the top candidates: `perf stat` for counter deltas, `perf record`/`report`
for hot instructions, `gprof` (`-pg` build) for call-graph time, and the
probe-instrumented build to attribute memory accesses to search phases (hull
eval vs. interpolation vs. tail). Findings feed the next subagent round as
concrete targets.

### Phase 5 — Production format wiring (the winner)

- **New hint type** in the `.hset` format alongside `0x6208`, documented in
  `HASHSET_FORMAT`, carrying the winner's parameters (per-block hull lines or
  global-hull vertices) in a versioned, endian-defined layout.
- **Encoder** (`hset_encoder.cpp`) computes the winner's parameters at build time
  (the convex-hull supporting-line computation, currently absent). Linear in
  input.
- **Decoder** (`hset_decoder.cpp`) dispatches the new hint to the winning
  `LookupStrategy` subclass — the same code the harness benchmarked.
- **Round-trip tests:** encode -> decode -> `contains`/`contains_batch` agreement
  vs. oracle; existing batch-agreement tests extended to the new strategy; a real
  NSRL-derived `.hset` built and checked end-to-end.
- **Backward compatibility:** old hint types still decode; the new one is
  additive.

## Cross-cutting constraint: preserve the sorted layout

The canonical hset array is sorted, which makes union/intersection/difference
trivial linear merges, keeps the format mmap-friendly, and is the basis for
`expected_index` + hull bounds. Therefore:

- **"Preserves sorted layout" is a first-class leaderboard dimension.** Any
  data-reordering candidate (Eytzinger, learned-index permutations) is flagged as
  sacrificing it. To keep set-ops trivial it must carry an *auxiliary* reordered
  copy (e.g. ~+800 MB for NSRL SHA-1, reported in the build budget as a real
  cost) or forfeit cheap set-ops. Either way it is not free, and the leaderboard
  records that so a lookup-only ns win cannot externalize the cost.
- Eytzinger is still benchmarked (as an auxiliary-structure candidate) but judged
  with that trade-off visible, against candidates like C6 that leave the sorted
  array untouched.

## Deliverables

Frozen eval harness + datasets + anti-cheat contract; reference candidates
C0-C6 + phmap; a leaderboard with perf/probe/gprof evidence; reviewed subagent
challenge results; the winning strategy wired end-to-end into the format with
round-trip tests; a results write-up (before/after vs. `block256` and phmap,
single + batch).

## Out of scope (YAGNI)

- Set-operation benchmarks (union/intersection/difference) — trivial on sorted
  data and none exist yet; but "keeps the canonical sorted array intact" is a
  protected soft constraint so we do not optimize lookups into a corner that
  breaks them later.
- New hash-length support; on-disk format changes beyond the one new hint type;
  anything requiring AVX2 (this box is SSE4.2).
- Multi-threaded lookup — not a feature to build: the data is immutable and
  read-only, so concurrent reads are inherently thread-safe. Noted as a property,
  not a deliverable.

## Key files

- `include/hashset/convex_hull.h` — hull computation (exists, unused in pipeline).
- `include/hashset/block_linear_ls.h` — per-block linear bounds (disabled).
- `include/hashset/block_ls.h` — current shipping block strategy.
- `include/hashset/hash_compare.h` — fast integer primary-key compare, prefetch.
- `src/lib/hashset/hset_encoder.cpp` — `make_block_bounds` (flat min/max today).
- `src/lib/hashset/hset_decoder.cpp` — `make_lookup_strategy` (hint dispatch).
- `src/lib/hashset/util.cpp` — `expected_index`.
- `bench/` — existing standalone harness to extend.
- `HASHSET_FORMAT` — on-disk format doc to update.
