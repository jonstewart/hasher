# Convex-Hull-Bounded Hash-Set Lookup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and freeze a trustworthy, anti-cheat eval harness for `libhasher`'s hash-set lookup, prove convex-hull-bounded lookup strategies against it, and wire the benchmark-proven winner end-to-end into the `.hset` format as a new hint type.

**Architecture:** A standalone `bench/eval` harness (extending the existing `bench/`) defines a polymorphic `eval::Candidate` interface whose timed `contains`/`contains_batch` surface is identical to the shipping `LookupStrategy`. Every candidate passes a correctness oracle (vs. `std::binary_search`) before it is timed, and is measured with ns/lookup + `perf` counters + in-code probe counters across a dataset matrix (synthetic multi-seed, real NSRL SHA-1/MD5, adversarial). Reference/bar columns (`basic`, `block256`, `phmap::flat_hash_set`, `std::unordered_set`) ship in the harness. New algorithmic candidates (block-linear with true convex-hull supporting lines, global-hull, fine-block, interpolation, and their synthesis) are added as self-contained files. Subagents extend the candidate set against the frozen harness; a review gate accepts only reviewed, benchmark-proven winners. The winner is wired into the format as a new hint type additive to the existing `0x6208`.

**Tech Stack:** C++17, `g++ -O3 -march=native` (Xeon E5645 / Westmere / SSE4.2, **no AVX2**), Catch2 (existing test suite), autotools (`check_PROGRAMS`), `vendors/parallel-hashmap` (phmap), boost (endian/interprocess, already used), `perf`/`gprof`/`taskset` (no valgrind).

## Global Constraints

- **C++ standard: C++17.** Build flags for the harness: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench` (extended per task). `-march=native` on the target box means SSE4.2, **not** AVX2 — no candidate may require AVX2.
- **Target CPU: Xeon E5645 (Westmere, 4 cores, SSE4.2).** All leaderboard numbers come from this box, single-threaded, pinned with `taskset`.
- **Scratch artifacts live in `$HOME/build`, never in `/work`.** Derived datasets (MD5, cached synthetic sets, `.hset` files built by the harness) go under `$HOME/build`. `/data` is read-only.
- **Real data paths (verified 2026-07-24):** NSRL SHA-1 = `/data/nsrl/2.47/nsrl-sha1` (40,406,763 × 20 B = 808,135,260 B, raw sorted digests, mmap with zero parsing). `NSRLFile.txt` = `/data/nsrl/2.47/NSRLFile.txt` (19 GB; source for the derived MD5 set).
- **Anti-cheat contract is non-negotiable** (see Task 3 / Task 16): correctness-before-timing against a `std::binary_search` oracle; untimed build phase reported as a budget; checksum sink to defeat DCE; all-unique streamed queries; set size exceeds LLC; no heap allocation in the timed region; N reps report min + median + stddev; candidates run interleaved on one pinned core.
- **Preserve the canonical sorted array.** "Preserves sorted layout" is a first-class leaderboard dimension. Any candidate that reorders data (Eytzinger, learned-index permutations) must carry an auxiliary reordered copy and report its extra bytes/hash in the build budget, or forfeit cheap set-ops. The sorted array itself is never mutated.
- **Backward compatibility:** old hint types (`0x6208`) must still decode. The new hint type is additive.
- **Probe/perf cross-check:** an ns win contradicted by higher `perf` LLC misses or higher probe counts is treated as noise and rejected pending explanation.
- **Correctness must never depend on uniformity.** Interpolation/hull candidates may depend on cryptographic-hash uniformity for *speed* only; the search invariant must keep results exact on adversarial/clustered data.

---

## File Structure

**New files (harness core, Phase 1):**
- `include/hashset/probe.h` — probe-counter macros (`HASHER_PROBE_TOUCH` / `HASHER_PROBE_CMP`), no-ops unless `HASHER_PROBE` is defined. Included by strategy headers.
- `bench/eval/candidate.h` — `eval::Candidate` abstract base + `eval::Budget`. The polymorphic candidate surface.
- `bench/eval/oracle.h` — strengthened correctness oracle: hard-case query builders (guaranteed hit/miss, ±1-bit near-miss, all-0x00/all-0xFF boundary) + `validate()` vs `std::binary_search`.
- `bench/eval/timing.h` — the timing contract: streamed unique queries, checksum sink, no-alloc timed region, min/median/stddev over N reps.
- `bench/eval/datasets.h` — dataset builders: synthetic multi-size/seed, adversarial/clustered, tuning vs held-out split, NSRL SHA-1 mmap loader, NSRL MD5 derive+cache.
- `bench/eval/suite.h` — leaderboard runner: validate → time → assemble ns + probe columns into a table; budget reporting.
- `bench/eval.cpp` — the frozen `main` driver.
- `bench/run_perf.sh` — `perf stat` wrapper isolating the timed region per candidate.
- `bench/RESULTS.md` — checked-in leaderboard (the bar + accepted candidates).

**New files (candidates, Phase 2):**
- `include/hashset/hull_lines.h` — convex-hull supporting-line ("min-width slab") computation per block, with verify-and-widen for float-rounding safety. Shared by C2 and Phase 5's encoder.
- `include/hashset/fine_block_ls.h` — `FineBlockLookupStrategy<L, BlockBits>` bucketing on 12–16 leading bits (C4).
- `include/hashset/global_hull_ls.h` — `GlobalHullLookupStrategy<L>` (C3).
- `include/hashset/interp_ls.h` — `InterpLookupStrategy<L>` (C5) and `HullInterpLookupStrategy<L>` (C6).
- `bench/candidates/c0_basic.h`, `c1_block256.h`, `c2_block_linear.h`, `c3_global_hull.h`, `c4_fine_block.h`, `c5_interp.h`, `c6_hull_interp.h`, `ext_phmap.h`, `ext_unordered.h` — one `eval::Candidate` subclass each.
- `bench/candidates/registry.h` — assembles the full candidate list for the driver; the single place a new candidate is registered.
- `bench/candidates/TEMPLATE.h` — copy-me stub for subagents (Phase 3).

**New files (process/profiling, Phases 3–4):**
- `bench/CHALLENGE.md` — subagent challenge packet + acceptance checklist (the review gate).
- `bench/profile.sh` — profiling driver (`perf stat`/`perf record`/`gprof`/probe build) for top candidates.
- `bench/PROFILE.md` — profiling findings log.

**Modified files (probe wiring + Phase 5):**
- `include/hashset/block_ls.h`, `include/hashset/basic_ls.h`, `include/hashset/block_linear_ls.h` — add probe hooks (no-op in production).
- `include/hashset/hset_structs.h` — new hint constant `BLOCK_LINEAR_HULL = 0x6209` semantics (see Task 18).
- `src/lib/hashset/hset_encoder_chunks.cpp`, `.h` — `write_hint_linear` + `length_hint` accommodating the new payload.
- `src/lib/hashset/hset_encoder.cpp` — compute hull lines at build time (`make_block_hull_lines<8>`); select hint type.
- `src/lib/hashset/hset_decoder.cpp` — dispatch `0x6209` to the revived block-linear strategy; keep `0x6208`; relax `handle_hint`.
- `HASHSET_FORMAT` — document the new hint type and its payload layout.
- `Makefile.am` — add `test_test_SOURCES` entries for new tests; add `bench/eval` as an optional `check_PROGRAM`.
- `test/test_hset_round_trip.cpp` (extend) + `test/test_hull_lines.cpp` (new) — round-trip and hull-line unit tests.

**Winner-dependency note (Phase 5):** the spec's win condition is decided by benchmarks, so the *exact* winner is not known at planning time. This plan wires the **per-block convex-hull supporting-line** strategy (revived `BlockLinearLookupStrategy`, hint `0x6209`) as the representative winner, because it is the one fully-specified algorithmic revive and its payload (per-block lines) has a fixed, small, endian-defined layout. If a global-hull or synthesis candidate wins instead, Tasks 18–21 change only in the hint *payload* (hull vertices instead of per-block lines) and the decoded strategy class; the task structure (new additive hint, encoder computes params, decoder dispatches, round-trip tests) is identical. Task 15 records the actual winner; if it is not C2, revise Tasks 18–21's payload code to match before executing them.

---

## Phase 1 — The eval harness & anti-cheat gate (built and frozen first)

### Task 1: Probe-counter instrumentation (no-op in production)

**Files:**
- Create: `include/hashset/probe.h`
- Modify: `include/hashset/block_ls.h` (add hooks in `search_window` and `staged_batch`), `include/hashset/basic_ls.h`
- Test: `test/test_probe.cpp` (new), registered in `Makefile.am`

**Interfaces:**
- Produces: macros `HASHER_PROBE_TOUCH(addr)` and `HASHER_PROBE_CMP()`; globals `hasher_probe_touches` and `hasher_probe_cmps` (`extern` `uint64_t`, defined only under `HASHER_PROBE`); `hasher_probe_reset()`. All expand to nothing unless the translation unit is compiled with `-DHASHER_PROBE`. The shipped library is never compiled with `HASHER_PROBE`, so production code is byte-identical.

- [ ] **Step 1: Write the failing test**

```cpp
// test/test_probe.cpp
#include <catch2/catch_test_macros.hpp>

#include "hashset/probe.h"

TEST_CASE("probe_counters_noop_by_default") {
  // Without -DHASHER_PROBE the macros must compile to nothing and the
  // accessor must report zero, so instrumented and shipped code share source.
  hasher_probe_reset();
  HASHER_PROBE_TOUCH(nullptr);
  HASHER_PROBE_CMP();
  CHECK(hasher_probe_touches() == 0);
  CHECK(hasher_probe_cmps() == 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Add `test/test_probe.cpp` to `test_test_SOURCES` in `Makefile.am` (alphabetically near `test_convex_hull.cpp`), then:

Run: `./autogen.sh >/dev/null 2>&1; ./configure >/dev/null && make check TESTS=test/test 2>&1 | tail -20`
Expected: FAIL to compile — `hashset/probe.h` does not exist.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/hashset/probe.h
#pragma once

#include <cstdint>

// In-code probe instrumentation. Array-touch and comparison counters compiled
// in ONLY under -DHASHER_PROBE; otherwise every macro is a no-op and these
// accessors return 0, so the instrumented build and the shipped build are the
// same source. Used by the eval harness as a machine-independent cross-check
// against perf counters (disagreement is itself a red flag).

#ifdef HASHER_PROBE

extern uint64_t g_hasher_probe_touches;
extern uint64_t g_hasher_probe_cmps;

#define HASHER_PROBE_TOUCH(addr) (++g_hasher_probe_touches, (void)(addr))
#define HASHER_PROBE_CMP()       (++g_hasher_probe_cmps)

inline void hasher_probe_reset() { g_hasher_probe_touches = 0; g_hasher_probe_cmps = 0; }
inline uint64_t hasher_probe_touches() { return g_hasher_probe_touches; }
inline uint64_t hasher_probe_cmps() { return g_hasher_probe_cmps; }

#else

#define HASHER_PROBE_TOUCH(addr) ((void)0)
#define HASHER_PROBE_CMP()       ((void)0)

inline void hasher_probe_reset() {}
inline uint64_t hasher_probe_touches() { return 0; }
inline uint64_t hasher_probe_cmps() { return 0; }

#endif
```

The two globals need one definition. Add to `bench/eval.cpp` later (Task 6); for the test, add a definition guarded the same way in a tiny TU. Simplest: define them in `include/hashset/probe.h` behind an `HASHER_PROBE_DEFINE` include-once guard is fragile — instead define them in `src/lib/hashset/util.cpp` under `#ifdef HASHER_PROBE`:

```cpp
// append to src/lib/hashset/util.cpp
#ifdef HASHER_PROBE
uint64_t g_hasher_probe_touches = 0;
uint64_t g_hasher_probe_cmps = 0;
#endif
```

- [ ] **Step 4: Add the probe hooks to the shipping search (no-op in prod)**

In `include/hashset/block_ls.h`, add `#include "hashset/probe.h"` near the other includes, then instrument the branchless inner loop in `search_window` (each probe load is one array touch + one comparison):

```cpp
    while (len > 0) {
      const size_t half = len >> 1;
      const size_t probe = pos + half;
      HASHER_PROBE_TOUCH(b + probe * HashLength);
      HASHER_PROBE_CMP();
      const uint64_t pk = primary_key<HashLength>(b + probe * HashLength);
      const bool lt = pk < hk;
      pos = lt ? probe + 1 : pos;
      len = lt ? len - half - 1 : half;
    }
```

Add the same two hook lines before the `fast_hash_cmp` call inside `staged_batch`'s per-lane step. In `basic_ls.h`, `std::binary_search` cannot be instrumented internally; leave `BasicLookupStrategy` uninstrumented (it is the floor, not a tuned candidate) and note that in `bench/RESULTS.md`.

- [ ] **Step 5: Run test to verify it passes**

Run: `make check TESTS=test/test 2>&1 | tail -20`
Expected: PASS — `probe_counters_noop_by_default` passes; existing tests still pass.

- [ ] **Step 6: Verify instrumented build compiles and counts**

Run: `g++ -O3 -march=native -std=c++17 -DHASHER_PROBE -Iinclude -c bench/eval_probe_smoke.cpp -o /dev/null` — *(skip; covered end-to-end in Task 6's instrumented build)*. For now just confirm the no-op path builds clean:

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -fsyntax-only test/test_probe.cpp`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add include/hashset/probe.h include/hashset/block_ls.h include/hashset/basic_ls.h src/lib/hashset/util.cpp test/test_probe.cpp Makefile.am
git commit -m "feat(bench): add no-op-in-prod probe counters for lookup instrumentation"
```

### Task 2: Candidate interface

**Files:**
- Create: `bench/eval/candidate.h`
- Test: `bench/eval/test_candidate.cpp` (compiled by the standalone one-liner in Step 2)

**Interfaces:**
- Produces: `namespace eval { struct Budget; class Candidate; }`.
  - `struct Budget { double build_ns = 0.0; double aux_bytes_per_hash = 0.0; bool preserves_sorted = true; };`
  - `class Candidate` (abstract): `virtual std::string name() const = 0;` `virtual void build(const HashSet& hs) = 0;` (untimed) `virtual bool contains(const uint8_t* hash) const = 0;` `virtual void contains_batch(const uint8_t* hashes, size_t n, size_t stride, bool* out) const = 0;` `virtual Budget budget() const = 0;` `virtual ~Candidate() = default;`
  - `HashSet` is the existing struct from `bench/harness.h` (reused verbatim).
- Consumes: `bench/harness.h` (`HashSet`).

- [ ] **Step 1: Write the failing test**

```cpp
// bench/eval/test_candidate.cpp
#include "eval/candidate.h"
#include "harness.h"

#include <cassert>
#include <cstdio>

// A trivial candidate that answers via linear scan, to prove the interface
// compiles and dispatches polymorphically.
struct ScanCandidate : eval::Candidate {
  const HashSet* hs = nullptr;
  std::string name() const override { return "scan"; }
  void build(const HashSet& h) override { hs = &h; }
  bool contains(const uint8_t* hash) const override {
    for (size_t i = 0; i < hs->count; ++i)
      if (std::memcmp(hs->at(i), hash, hs->hlen) == 0) return true;
    return false;
  }
  void contains_batch(const uint8_t* q, size_t n, size_t stride, bool* out) const override {
    for (size_t i = 0; i < n; ++i) out[i] = contains(q + i * stride);
  }
  eval::Budget budget() const override { return {}; }
};

int main() {
  HashSet hs = make_sorted_set(1000, 20, 42);
  ScanCandidate c;
  c.build(hs);
  assert(c.contains(hs.at(0)));
  eval::Candidate& base = c;         // polymorphic use
  assert(base.name() == "scan");
  std::printf("ok\n");
  return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_candidate.cpp src/lib/hashset/util.cpp -o /tmp/tc && /tmp/tc`
Expected: FAIL — `eval/candidate.h` not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// bench/eval/candidate.h
#pragma once

#include "harness.h"   // HashSet

#include <cstddef>
#include <cstdint>
#include <string>

namespace eval {

// Untimed build cost, reported alongside every leaderboard row. aux_bytes_per_hash
// is memory used BEYOND the canonical sorted array (an auxiliary reordered copy,
// hull tables, etc.). preserves_sorted is false for any candidate that needs the
// sorted array reordered (it must then carry the copy, counted above).
struct Budget {
  double build_ns = 0.0;
  double aux_bytes_per_hash = 0.0;
  bool preserves_sorted = true;
};

// A benchmark candidate. build() is untimed setup; contains()/contains_batch()
// are the timed query surface and MUST be the same code path that would ship
// (an anti-cheat property: no benchmark-only fast path).
class Candidate {
public:
  virtual ~Candidate() = default;
  virtual std::string name() const = 0;
  virtual void build(const HashSet& hs) = 0;
  virtual bool contains(const uint8_t* hash) const = 0;
  virtual void contains_batch(const uint8_t* hashes, size_t n, size_t stride,
                              bool* out) const = 0;
  virtual Budget budget() const = 0;
};

} // namespace eval
```

- [ ] **Step 4: Run test to verify it passes**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_candidate.cpp src/lib/hashset/util.cpp -o /tmp/tc && /tmp/tc`
Expected: prints `ok`, exit 0.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/candidate.h bench/eval/test_candidate.cpp
git commit -m "feat(bench): add polymorphic eval::Candidate interface + Budget"
```

### Task 3: Strengthened correctness oracle (anti-cheat gate part 1)

**Files:**
- Create: `bench/eval/oracle.h`
- Test: `bench/eval/test_oracle.cpp`

**Interfaces:**
- Consumes: `bench/harness.h` (`HashSet`, `Queries`, `ground_truth_contains`, splitmix helpers), `bench/eval/candidate.h`.
- Produces:
  - `Queries eval::make_hard_queries(const HashSet& hs, size_t m, uint64_t seed);` — a mixed stream of guaranteed hits (sampled from the set), guaranteed misses (random), ±1-bit near-misses of present hashes, and boundary hashes (all-0x00 and all-0xFF leading bytes). All queries distinct.
  - `struct OracleResult { bool ok; size_t mismatches; size_t checked; };`
  - `OracleResult eval::validate(const HashSet& hs, eval::Candidate& c, uint64_t seed = 777);` — builds `c`, runs both `contains()` and `contains_batch()` over `make_hard_queries`, compares every answer to `ground_truth_contains`. `ok` is false on any single mismatch; a candidate that fails is disqualified (never timed).

- [ ] **Step 1: Write the failing test**

```cpp
// bench/eval/test_oracle.cpp
#include "eval/oracle.h"
#include "harness.h"
#include "hashset/block_ls.h"

#include <cassert>
#include <cstdio>
#include <memory>

// Wrap the shipping block strategy so we can validate the oracle against a known-good candidate.
struct BlockCand : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<20, 8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  std::string name() const override { return "block256"; }
  void build(const HashSet& hs) override {
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      size_t e = expected_index(hs.at(i), hs.count);
      int64_t d = (int64_t)i - (int64_t)e;
      size_t bi = hs.at(i)[0];
      b[bi].first = std::min(b[bi].first, d);
      b[bi].second = std::max(b[bi].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<20,8>>(hs.beg(), hs.end(), b);
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    ls->contains_batch(q, n, s, o);
  }
  eval::Budget budget() const override { return {}; }
};

// A deliberately broken candidate that always says "not present" — the oracle
// MUST catch it (proves the gate actually rejects).
struct BrokenCand : BlockCand {
  std::string name() const override { return "broken"; }
  bool contains(const uint8_t*) const override { return false; }
  void contains_batch(const uint8_t*, size_t n, size_t, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = false;
  }
};

int main() {
  HashSet hs = make_sorted_set(200000, 20, 7);

  BlockCand good;
  eval::OracleResult r = eval::validate(hs, good);
  assert(r.ok);
  assert(r.mismatches == 0);
  assert(r.checked > 0);

  BrokenCand bad;
  eval::OracleResult rb = eval::validate(hs, bad);
  assert(!rb.ok);
  assert(rb.mismatches > 0);

  std::printf("ok checked=%zu\n", r.checked);
  return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_oracle.cpp src/lib/hashset/util.cpp -o /tmp/to && /tmp/to`
Expected: FAIL — `eval/oracle.h` not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// bench/eval/oracle.h
#pragma once

#include "eval/candidate.h"
#include "harness.h"           // HashSet, Queries, ground_truth_contains

#include <cstring>
#include <vector>

namespace eval {

struct OracleResult { bool ok; size_t mismatches; size_t checked; };

// Build a hard, all-distinct query stream: guaranteed hits, guaranteed misses,
// +/-1-bit near-misses of present hashes, and boundary hashes (all-0x00 and
// all-0xFF leading bytes). Distinctness is enforced by construction; exact
// duplicates across categories are astronomically unlikely for L>=16 random
// hashes and harmless to the oracle (they only re-check an answer).
inline Queries make_hard_queries(const HashSet& hs, size_t m, uint64_t seed) {
  Queries q; q.hlen = hs.hlen; q.count = m; q.data.assign(m * hs.hlen, 0);
  uint64_t x = seed ? seed : 0x1234567;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull; uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  for (size_t k = 0; k < m; ++k) {
    uint8_t* dst = q.data.data() + k * hs.hlen;
    const int kind = static_cast<int>(next() % 5);
    if (hs.count && kind == 0) {                       // guaranteed hit
      std::memcpy(dst, hs.at(next() % hs.count), hs.hlen);
    } else if (hs.count && kind == 1) {                // +/-1-bit near-miss
      std::memcpy(dst, hs.at(next() % hs.count), hs.hlen);
      dst[next() % hs.hlen] ^= static_cast<uint8_t>(1u << (next() & 7));
    } else if (kind == 2) {                            // all-0x00 leading bytes
      for (size_t j = 0; j < hs.hlen; ++j) dst[j] = (j < 2) ? 0x00 : static_cast<uint8_t>(next());
    } else if (kind == 3) {                            // all-0xFF leading bytes
      for (size_t j = 0; j < hs.hlen; ++j) dst[j] = (j < 2) ? 0xFF : static_cast<uint8_t>(next());
    } else {                                           // random (guaranteed miss, almost surely)
      for (size_t j = 0; j + 8 <= hs.hlen; j += 8) { uint64_t v = next(); std::memcpy(dst + j, &v, 8); }
      for (size_t j = (hs.hlen / 8) * 8; j < hs.hlen; ++j) dst[j] = static_cast<uint8_t>(next());
    }
  }
  return q;
}

inline OracleResult validate(const HashSet& hs, Candidate& c, uint64_t seed = 777) {
  c.build(hs);
  Queries q = make_hard_queries(hs, 60000, seed);

  std::vector<uint8_t> truth(q.count);
  for (size_t i = 0; i < q.count; ++i)
    truth[i] = ground_truth_contains(hs, q.at(i)) ? 1 : 0;

  size_t mism = 0;
  for (size_t i = 0; i < q.count; ++i)
    if ((c.contains(q.at(i)) ? 1 : 0) != truth[i]) ++mism;

  std::vector<uint8_t> batch(q.count, 0xEE);
  c.contains_batch(q.data.data(), q.count, q.hlen, reinterpret_cast<bool*>(batch.data()));
  for (size_t i = 0; i < q.count; ++i)
    if ((batch[i] ? 1 : 0) != truth[i]) ++mism;

  return { mism == 0, mism, q.count * 2 };
}

} // namespace eval
```

- [ ] **Step 4: Run test to verify it passes**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_oracle.cpp src/lib/hashset/util.cpp -o /tmp/to && /tmp/to`
Expected: prints `ok checked=120000`, exit 0 (good passes, broken is caught).

- [ ] **Step 5: Commit**

```bash
git add bench/eval/oracle.h bench/eval/test_oracle.cpp
git commit -m "feat(bench): add hard-case correctness oracle (hit/miss/near-miss/boundary)"
```

### Task 4: Timing contract (anti-cheat gate part 2)

**Files:**
- Create: `bench/eval/timing.h`
- Test: `bench/eval/test_timing.cpp`

**Interfaces:**
- Consumes: `bench/eval/candidate.h`, `bench/harness.h` (`Queries`).
- Produces:
  - `struct Timing { double ns_min; double ns_median; double ns_stddev; uint64_t checksum; };`
  - `Timing eval::time_single(const Candidate& c, const Queries& q, int reps = 7);` — times the `contains()` loop; folds every answer into a running checksum (sink) that is written to a `volatile` so the compiler cannot elide the loop; **no heap allocation inside the timed region** (the results are consumed directly into the checksum, not stored); returns min + median + stddev of ns/lookup across reps.
  - `Timing eval::time_batch(const Candidate& c, const Queries& q, std::vector<uint8_t>& scratch, int reps = 7);` — `scratch` is sized once by the caller (untimed); the timed region only calls `contains_batch` into it and checksums the result.

- [ ] **Step 1: Write the failing test**

```cpp
// bench/eval/test_timing.cpp
#include "eval/timing.h"
#include "eval/oracle.h"      // reuses BlockCand-style wrapper via a local def
#include "harness.h"
#include "hashset/block_ls.h"

#include <cassert>
#include <cstdio>
#include <memory>

struct BlockCand : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<20,8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  std::string name() const override { return "block256"; }
  void build(const HashSet& hs) override {
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      size_t e = expected_index(hs.at(i), hs.count);
      int64_t d = (int64_t)i - (int64_t)e;
      b[hs.at(i)[0]].first = std::min(b[hs.at(i)[0]].first, d);
      b[hs.at(i)[0]].second = std::max(b[hs.at(i)[0]].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<20,8>>(hs.beg(), hs.end(), b);
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return {}; }
};

int main() {
  HashSet hs = make_sorted_set(1000000, 20, 3);
  BlockCand c; c.build(hs);
  Queries q = make_random_queries(4096, 20, 11);

  eval::Timing ts = eval::time_single(c, q, 5);
  assert(ts.ns_min > 0.0);
  assert(ts.ns_median >= ts.ns_min);

  std::vector<uint8_t> scratch(q.count);
  eval::Timing tb = eval::time_batch(c, q, scratch, 5);
  assert(tb.ns_min > 0.0);
  // Single and batch must agree on the checksum (same answers).
  assert(ts.checksum == tb.checksum);
  std::printf("ok single=%.1f batch=%.1f\n", ts.ns_min, tb.ns_min);
  return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_timing.cpp src/lib/hashset/util.cpp -o /tmp/tt && /tmp/tt`
Expected: FAIL — `eval/timing.h` not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// bench/eval/timing.h
#pragma once

#include "eval/candidate.h"
#include "harness.h"          // Queries

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <vector>

namespace eval {

struct Timing { double ns_min; double ns_median; double ns_stddev; uint64_t checksum; };

namespace detail {
inline Timing summarize(std::vector<double>& samples, uint64_t checksum) {
  std::sort(samples.begin(), samples.end());
  const double mn = samples.front();
  const double med = samples[samples.size() / 2];
  double mean = 0; for (double s : samples) mean += s; mean /= samples.size();
  double var = 0; for (double s : samples) var += (s - mean) * (s - mean);
  var /= samples.size();
  return { mn, med, std::sqrt(var), checksum };
}
} // namespace detail

// Times contains() over ALL queries. Every answer folds into `sink`; `sink` is
// written to a volatile after the loop so the optimizer cannot delete the work.
// No heap allocation occurs inside the timed region.
inline Timing time_single(const Candidate& c, const Queries& q, int reps = 7) {
  volatile uint64_t keep = 0;
  std::vector<double> samples;
  samples.reserve(reps);
  uint64_t checksum = 0;
  using clk = std::chrono::steady_clock;
  for (int r = 0; r < reps; ++r) {
    uint64_t sink = 0;
    auto t0 = clk::now();
    for (size_t i = 0; i < q.count; ++i)
      sink = sink * 1000003ull + (c.contains(q.at(i)) ? 1u : 0u);
    auto t1 = clk::now();
    keep = sink;
    checksum = sink;
    samples.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / q.count);
  }
  (void)keep;
  return detail::summarize(samples, checksum);
}

// Times contains_batch(). `scratch` is sized by the caller (untimed); the timed
// region only fills it and checksums it — no allocation inside timing.
inline Timing time_batch(const Candidate& c, const Queries& q,
                         std::vector<uint8_t>& scratch, int reps = 7) {
  volatile uint64_t keep = 0;
  std::vector<double> samples;
  samples.reserve(reps);
  uint64_t checksum = 0;
  using clk = std::chrono::steady_clock;
  for (int r = 0; r < reps; ++r) {
    auto t0 = clk::now();
    c.contains_batch(q.data.data(), q.count, q.hlen, reinterpret_cast<bool*>(scratch.data()));
    uint64_t sink = 0;
    for (size_t i = 0; i < q.count; ++i)
      sink = sink * 1000003ull + (scratch[i] ? 1u : 0u);
    auto t1 = clk::now();
    keep = sink;
    checksum = sink;
    samples.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / q.count);
  }
  (void)keep;
  return detail::summarize(samples, checksum);
}

} // namespace eval
```

Note: `time_single` and `time_batch` fold answers with the same `sink * 1000003 + bit` recurrence in query order, so their checksums are equal iff every answer matches — a built-in single/batch agreement check. The batch checksum includes fill time in its timed region by design (batch's whole point is the fill); the checksum fold after `contains_batch` is cheap and identical to single's fold.

- [ ] **Step 4: Run test to verify it passes**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_timing.cpp src/lib/hashset/util.cpp -o /tmp/tt && /tmp/tt`
Expected: prints `ok single=... batch=...` with the two checksums equal, exit 0.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/timing.h bench/eval/test_timing.cpp
git commit -m "feat(bench): add timing contract (checksum sink, no-alloc region, min/median/stddev)"
```

### Task 5: Dataset matrix (synthetic multi-seed, adversarial, real NSRL, tuning/held-out split)

**Files:**
- Create: `bench/eval/datasets.h`
- Test: `bench/eval/test_datasets.cpp`

**Interfaces:**
- Consumes: `bench/harness.h` (`HashSet`, `make_sorted_set`), boost.interprocess (already a dependency).
- Produces:
  - `HashSet eval::make_adversarial_set(size_t count, size_t hlen, uint64_t seed);` — non-uniform leading bytes (skewed toward a few first-byte values) and dense runs, still sorted. Used to prove correctness never *depends* on uniformity and to stress bound tightness.
  - `struct MmapSet { HashSet_view view; ... };` — actually returns `HashSetView` (a non-owning view so the 808 MB NSRL file is not copied). Define `struct HashSetView { size_t hlen, count; const uint8_t* data; const uint8_t* at(size_t i) const; const uint8_t* beg() const; const uint8_t* end() const; };` and a variant of the candidate `build`/oracle that accepts a view. To keep the interface uniform, provide `HashSet eval::load_nsrl_sha1(const char* path, size_t max_count = 0);` that mmaps and, when `max_count==0`, wraps the mapping in a `HashSet` whose `data` vector is replaced by a borrowed span — but `HashSet.data` is a `std::vector`, which owns. To avoid an 808 MB copy, add `HashSetView eval::mmap_nsrl_sha1(const char* path);` returning a view over the mapping, plus overloads `validate(view,...)`/`time_single(view,...)`. **Simpler, chosen approach:** templatize the oracle/timing on a `HashSetLike` concept (anything with `hlen/count/at/beg/end`). See Step 3.
  - `HashSet eval::derive_nsrl_md5(const char* nsrlfile_path, const char* cache_path);` — parses column-appropriate MD5 hex from `NSRLFile.txt` once, writes raw 16-byte digests sorted+deduped to `cache_path` under `$HOME/build`, and on subsequent runs loads the cache. Returns an owning `HashSet` (MD5 set is ~650 MB, acceptable; or mmap the cache and return a view — provide `mmap_raw(path, 16)`).
  - `struct Split { HashSet tune; HashSet held_out; };` `Split eval::split_disjoint(size_t count, size_t hlen, uint64_t tune_seed, uint64_t held_seed);` — two independently-seeded synthetic sets; **final leaderboard numbers come only from `held_out`.**

- [ ] **Step 1: Write the failing test**

```cpp
// bench/eval/test_datasets.cpp
#include "eval/datasets.h"
#include "harness.h"

#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
  // Adversarial set is still sorted and correct as a set.
  HashSet a = eval::make_adversarial_set(50000, 20, 5);
  assert(a.count == 50000);
  for (size_t i = 1; i < a.count; ++i)
    assert(std::memcmp(a.at(i-1), a.at(i), a.hlen) <= 0);   // sorted

  // Tuning and held-out are disjoint seeds and distinct.
  eval::Split s = eval::split_disjoint(10000, 20, 1, 2);
  assert(s.tune.count == 10000 && s.held_out.count == 10000);
  assert(std::memcmp(s.tune.at(0), s.held_out.at(0), 20) != 0);

  std::printf("ok\n");
  return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_datasets.cpp src/lib/hashset/util.cpp -o /tmp/td && /tmp/td`
Expected: FAIL — `eval/datasets.h` not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// bench/eval/datasets.h
#pragma once

#include "harness.h"   // HashSet, make_sorted_set, splitmix pattern

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace eval {

// Non-owning view so the 808 MB NSRL mapping is never copied. The oracle and
// timing helpers are templated on "HashSetLike" (hlen/count/at/beg/end), so a
// view works everywhere a HashSet does.
struct HashSetView {
  size_t hlen = 0;
  size_t count = 0;
  const uint8_t* data = nullptr;
  const uint8_t* at(size_t i) const { return data + i * hlen; }
  const uint8_t* beg() const { return data; }
  const uint8_t* end() const { return data + count * hlen; }
};

// Adversarial: leading bytes skewed to a handful of values, with dense runs.
// Correctness must hold here; only speed may degrade.
inline HashSet make_adversarial_set(size_t count, size_t hlen, uint64_t seed) {
  HashSet hs; hs.hlen = hlen; hs.count = count; hs.data.resize(count * hlen);
  uint64_t x = seed ? seed : 0xABC;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull; uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  static const uint8_t lead[] = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
  std::vector<std::vector<uint8_t>> rows(count, std::vector<uint8_t>(hlen));
  for (size_t k = 0; k < count; ++k) {
    rows[k][0] = lead[next() % (sizeof(lead))];        // skewed leading byte
    for (size_t j = 1; j < hlen; ++j) rows[k][j] = static_cast<uint8_t>(next());
  }
  std::sort(rows.begin(), rows.end(), [&](const auto& p, const auto& q) {
    return std::memcmp(p.data(), q.data(), hlen) < 0;
  });
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  hs.count = rows.size();
  hs.data.resize(hs.count * hlen);
  for (size_t k = 0; k < hs.count; ++k) std::memcpy(hs.at(k), rows[k].data(), hlen);
  return hs;
}

struct Split { HashSet tune; HashSet held_out; };
inline Split split_disjoint(size_t count, size_t hlen, uint64_t tune_seed, uint64_t held_seed) {
  return { make_sorted_set(count, hlen, tune_seed), make_sorted_set(count, hlen, held_seed) };
}

// mmap a raw file of fixed-width sorted digests as a view (zero copy, zero parse).
inline HashSetView mmap_raw(const std::string& path, size_t hlen,
                            std::shared_ptr<boost::interprocess::mapped_region>& keepalive) {
  namespace bip = boost::interprocess;
  bip::file_mapping fm(path.c_str(), bip::read_only);
  keepalive = std::make_shared<bip::mapped_region>(fm, bip::read_only);
  HashSetView v;
  v.hlen = hlen;
  v.data = static_cast<const uint8_t*>(keepalive->get_address());
  v.count = keepalive->get_size() / hlen;
  return v;
}

inline HashSetView mmap_nsrl_sha1(const std::string& path,
                                  std::shared_ptr<boost::interprocess::mapped_region>& keepalive) {
  return mmap_raw(path, 20, keepalive);
}

} // namespace eval
```

- [ ] **Step 4: Templatize oracle + timing on HashSetLike**

Change `bench/eval/oracle.h` and `bench/eval/timing.h` so the functions that read the set accept any type with `hlen/count/at/beg/end`. Concretely, in `oracle.h` make `make_hard_queries` and `validate` templates:

```cpp
template <class SetT>
inline Queries make_hard_queries(const SetT& hs, size_t m, uint64_t seed) { /* body unchanged, uses hs.count/hs.at/hs.hlen */ }

template <class SetT>
inline OracleResult validate(const SetT& hs, Candidate& c, uint64_t seed = 777) { /* body unchanged */ }
```

`ground_truth_contains` in `harness.h` currently takes `const HashSet&`; add a template overload alongside it:

```cpp
// append to harness.h, after ground_truth_contains(const HashSet&, ...)
template <class SetT>
inline bool ground_truth_contains_v(const SetT& hs, const uint8_t* h) {
  size_t lo = 0, hi = hs.count;
  while (lo < hi) { size_t mid = lo + (hi - lo) / 2;
    int c = std::memcmp(hs.at(mid), h, hs.hlen);
    if (c < 0) lo = mid + 1; else if (c > 0) hi = mid; else return true; }
  return false;
}
```

and have the templated `validate` call `ground_truth_contains_v`. Update the Task 3 test to still pass (it uses `HashSet`, which satisfies the concept).

- [ ] **Step 5: Add the NSRL MD5 derivation (run once, cache to $HOME/build)**

`NSRLFile.txt` rows begin with `"SHA-1","MD5",...` quoted CSV. Derive MD5 once:

```cpp
// append to bench/eval/datasets.h
#include <cstdio>
#include <cstdlib>
// Parse MD5 (2nd quoted column) from NSRLFile.txt, write raw 16-byte digests
// sorted+deduped to cache_path. On re-run, if cache exists, skip parsing.
inline void derive_nsrl_md5_cache(const std::string& nsrlfile, const std::string& cache_path) {
  { FILE* c = std::fopen(cache_path.c_str(), "rb"); if (c) { std::fclose(c); return; } }
  FILE* in = std::fopen(nsrlfile.c_str(), "rb");
  if (!in) { std::fprintf(stderr, "cannot open %s\n", nsrlfile.c_str()); std::exit(1); }
  std::vector<std::array<uint8_t,16>> md5s;
  char line[512];
  auto hexval = [](char c)->int { if (c>='0'&&c<='9') return c-'0'; if (c>='A'&&c<='F') return c-'A'+10; if (c>='a'&&c<='f') return c-'a'+10; return -1; };
  std::fgets(line, sizeof line, in); // header row
  while (std::fgets(line, sizeof line, in)) {
    // columns are quoted: "sha1","md5",...  find the 2nd quoted field.
    char* p = std::strchr(line, '"'); if (!p) continue;         // open q1
    p = std::strchr(p+1, '"'); if (!p) continue;                // close q1
    p = std::strchr(p+1, '"'); if (!p) continue;                // open q2
    char* q = std::strchr(p+1, '"'); if (!q) continue;          // close q2
    if (q - (p+1) != 32) continue;
    std::array<uint8_t,16> d; bool ok = true;
    for (int i = 0; i < 16; ++i) { int hi = hexval(p[1+2*i]), lo = hexval(p[2+2*i]); if (hi<0||lo<0){ok=false;break;} d[i]=(uint8_t)((hi<<4)|lo); }
    if (ok) md5s.push_back(d);
  }
  std::fclose(in);
  std::sort(md5s.begin(), md5s.end());
  md5s.erase(std::unique(md5s.begin(), md5s.end()), md5s.end());
  FILE* out = std::fopen(cache_path.c_str(), "wb");
  std::fwrite(md5s.data(), 16, md5s.size(), out);
  std::fclose(out);
}
```

The driver (Task 6) calls `derive_nsrl_md5_cache` with `cache_path = std::string(getenv("HOME")) + "/build/nsrl-md5"`, then `mmap_raw(cache_path, 16, ...)`.

- [ ] **Step 6: Run test to verify it passes**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench bench/eval/test_datasets.cpp src/lib/hashset/util.cpp -lrt -o /tmp/td && /tmp/td`
Expected: prints `ok`, exit 0. (Adversarial set sorted; tune/held-out distinct.)

- [ ] **Step 7: Commit**

```bash
git add bench/eval/datasets.h bench/eval/oracle.h bench/eval/timing.h bench/harness.h bench/eval/test_datasets.cpp
git commit -m "feat(bench): add dataset matrix (adversarial, NSRL mmap, MD5 derive, tune/held-out split)"
```

### Task 6: Leaderboard suite + frozen driver + build hooks

**Files:**
- Create: `bench/eval/suite.h`, `bench/eval.cpp`, `bench/RESULTS.md`
- Modify: `Makefile.am` (optional `check_PROGRAM` hook), `bench/README.md`

**Interfaces:**
- Consumes: everything above (`candidate.h`, `oracle.h`, `timing.h`, `datasets.h`) + `bench/candidates/registry.h` (Task 8 onward; for this task, register only C0/C1).
- Produces:
  - `struct Row { std::string cand; double single_min, single_med, single_sd; double batch_min, batch_med, batch_sd; uint64_t probe_touches; eval::Budget budget; bool ok; };`
  - `template <class SetT> std::vector<Row> eval::run_leaderboard(const std::string& title, const SetT& hs, std::vector<std::unique_ptr<Candidate>>& cands, const std::vector<Workload>& wls);` — for each candidate: `validate()` (skip timing + mark `ok=false` on failure), else `time_single`/`time_batch` per workload and (if `HASHER_PROBE`) capture probe touches for one representative workload. Prints a table and returns the rows.

- [ ] **Step 1: Write `bench/eval/suite.h`**

```cpp
// bench/eval/suite.h
#pragma once

#include "eval/candidate.h"
#include "eval/oracle.h"
#include "eval/timing.h"
#include "harness.h"          // Workload, default_workloads, make_random_queries, make_mixed_queries
#include "hashset/probe.h"

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace eval {

struct Row {
  std::string cand;
  bool ok = false;
  double single_min = 0, single_med = 0, single_sd = 0;
  double batch_min = 0, batch_med = 0, batch_sd = 0;
  uint64_t probe_touches = 0;
  Budget budget;
};

template <class SetT>
inline Queries queries_for(const SetT& hs, const Workload& wl) {
  return (wl.hit == 0.0) ? make_random_queries(wl.m, hs.hlen, 90001 + wl.m)
                         : make_mixed_queries_v(hs, wl.m, wl.hit, 90001 + wl.m);
}

template <class SetT>
inline std::vector<Row> run_leaderboard(const std::string& title, const SetT& hs,
                                        std::vector<std::unique_ptr<Candidate>>& cands,
                                        const std::vector<Workload>& wls = default_workloads()) {
  std::printf("=== %s (hlen=%zu, count=%zu) ===\n", title.c_str(), hs.hlen, hs.count);
  std::vector<Row> rows;
  for (auto& up : cands) {
    Candidate& c = *up;
    Row row; row.cand = c.name();
    OracleResult val = validate(hs, c);   // builds c; DISQUALIFY on any mismatch
    row.ok = val.ok;
    row.budget = c.budget();
    if (!row.ok) {
      std::printf("  %-16s DISQUALIFIED (%zu/%zu mismatches)\n", row.cand.c_str(), val.mismatches, val.checked);
      rows.push_back(row); continue;
    }
    // Held-out timing: use the largest workload for the headline number.
    for (auto& wl : wls) {
      Queries q = queries_for(hs, wl);
      std::vector<uint8_t> scratch(q.count);
      Timing ts = time_single(c, q);
      Timing tb = time_batch(c, q, scratch);
      std::printf("  %-16s %-8s single %8.1f (med %8.1f sd %6.1f)  batch %8.1f (med %8.1f sd %6.1f)\n",
                  row.cand.c_str(), wl.tag, ts.ns_min, ts.ns_median, ts.ns_stddev,
                  tb.ns_min, tb.ns_median, tb.ns_stddev);
      // Keep the last workload's numbers as the row headline.
      row.single_min = ts.ns_min; row.single_med = ts.ns_median; row.single_sd = ts.ns_stddev;
      row.batch_min = tb.ns_min;  row.batch_med = tb.ns_median;  row.batch_sd = tb.ns_stddev;
    }
    // Probe cross-check (only meaningful under -DHASHER_PROBE).
    hasher_probe_reset();
    for (size_t i = 0; i < std::min<size_t>(hs.count, 4096); ++i) (void)c.contains(hs.at(i));
    row.probe_touches = hasher_probe_touches();
    std::printf("    budget: build=%.1fms aux=%.2fB/hash sorted=%d probe_touch/lookup~%.2f\n",
                row.budget.build_ns / 1e6, row.budget.aux_bytes_per_hash,
                row.budget.preserves_sorted ? 1 : 0,
                row.probe_touches / 4096.0);
    rows.push_back(row);
  }
  std::printf("\n");
  return rows;
}

} // namespace eval
```

This needs `make_mixed_queries_v` (templated on `SetT`). Add a templated overload to `harness.h` mirroring `make_mixed_queries` but using `hs.at`/`hs.count`/`hs.hlen` (the existing one takes `const HashSet&`; copy its body under a template name `make_mixed_queries_v`).

- [ ] **Step 2: Write the frozen driver `bench/eval.cpp`**

```cpp
// bench/eval.cpp
// Frozen eval driver. Runs the bar + all registered candidates across the
// dataset matrix. Held-out numbers are authoritative. Pin with taskset:
//   taskset -c 2 bench/eval [n]
#include "eval/suite.h"
#include "eval/datasets.h"
#include "candidates/registry.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

// Probe globals live here for the standalone (non-library) build under -DHASHER_PROBE.
#ifdef HASHER_PROBE
uint64_t g_hasher_probe_touches = 0;
uint64_t g_hasher_probe_cmps = 0;
#endif

int main(int argc, char** argv) {
  const size_t n = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 10000000;
  std::printf("libhasher eval harness — held-out numbers are authoritative\n\n");

  // Synthetic held-out (disjoint seed from any tuning done in candidates).
  eval::Split s20 = eval::split_disjoint(n, 20, 0xTUNE1, 0xHELD1);
  {
    auto cands = candidates::all<20>();
    eval::run_leaderboard("SHA-1 L=20 synthetic held-out", s20.held_out, cands);
  }

  // Adversarial (correctness + tightness stress).
  {
    HashSet adv = eval::make_adversarial_set(n / 10, 20, 0xADVE);
    auto cands = candidates::all<20>();
    eval::run_leaderboard("SHA-1 L=20 adversarial", adv, cands);
  }

  // Real NSRL SHA-1 (mmap, zero copy). Optional: only if present.
  {
    std::shared_ptr<boost::interprocess::mapped_region> keep;
    const char* p = "/data/nsrl/2.47/nsrl-sha1";
    if (FILE* f = std::fopen(p, "rb")) { std::fclose(f);
      eval::HashSetView v = eval::mmap_nsrl_sha1(p, keep);
      auto cands = candidates::all<20>();
      eval::run_leaderboard("NSRL SHA-1 (real, mmap)", v, cands);
    }
  }

  // Real NSRL MD5 (derived+cached once under $HOME/build).
  {
    std::string cache = std::string(std::getenv("HOME")) + "/build/nsrl-md5";
    eval::derive_nsrl_md5_cache("/data/nsrl/2.47/NSRLFile.txt", cache);
    std::shared_ptr<boost::interprocess::mapped_region> keep;
    eval::HashSetView v = eval::mmap_raw(cache, 16, keep);
    auto cands = candidates::all<16>();
    eval::run_leaderboard("NSRL MD5 (real, derived)", v, cands);
  }
  return 0;
}
```

Replace the `0xTUNE1`/`0xHELD1`/`0xADVE` placeholders with real 64-bit literals, e.g. `0x7ACE7357C0FFEE01ull`, `0xHELD1 -> 0xDEADBEEF5A5A0002ull`, `0xADVE -> 0xADFEEDFACE0003ull`. (These are fixed reproducibility seeds; document them in `RESULTS.md`.)

- [ ] **Step 3: Register only C0/C1 for now**

Create a minimal `bench/candidates/registry.h` that returns C0 basic + C1 block256 (the bar). Full registry is completed in Task 8; this keeps the driver compiling now.

```cpp
// bench/candidates/registry.h
#pragma once
#include "eval/candidate.h"
#include "candidates/c0_basic.h"
#include "candidates/c1_block256.h"
#include <memory>
#include <vector>
namespace candidates {
template <size_t L>
std::vector<std::unique_ptr<eval::Candidate>> all() {
  std::vector<std::unique_ptr<eval::Candidate>> v;
  v.push_back(std::make_unique<C0Basic<L>>());
  v.push_back(std::make_unique<C1Block256<L>>());
  return v;
}
} // namespace candidates
```

(`c0_basic.h`/`c1_block256.h` are written in Task 8. To keep this task independently green, Task 8 is a prerequisite of building `bench/eval.cpp`; if executing strictly in order, defer Step 4's run until Task 8. Mark that dependency here.)

- [ ] **Step 4: Build the driver (after Task 8) and the autotools hook**

Add to `Makefile.am`, near the other `check_PROGRAMS`:

```make
check_PROGRAMS = test/test test/bench_hex test/bench_hsd bench/eval

bench_eval_SOURCES = bench/eval.cpp src/lib/hashset/util.cpp
bench_eval_CPPFLAGS = -Iinclude -Ibench -Ivendors/parallel-hashmap
bench_eval_CXXFLAGS = $(AM_CXXFLAGS) -O3 -march=native
```

Also keep the standalone one-liner documented in `bench/README.md`:

```sh
g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap \
    bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval
taskset -c 2 bench/eval 10000000
```

- [ ] **Step 5: Seed `bench/RESULTS.md`**

Create `bench/RESULTS.md` with: the fixed seeds, the CPU (Xeon E5645, SSE4.2), the pinned core, the workload matrix, and an empty leaderboard table with columns: candidate | single ns (min/med/sd) | batch ns | preserves_sorted | aux B/hash | build ms | probe touches/lookup | notes. This is the checked-in reproducibility artifact.

- [ ] **Step 6: Commit**

```bash
git add bench/eval/suite.h bench/eval.cpp bench/candidates/registry.h bench/RESULTS.md bench/README.md Makefile.am bench/harness.h
git commit -m "feat(bench): add leaderboard suite, frozen eval driver, results scaffold"
```

### Task 7: perf-counter wrapper + perf availability check

**Files:**
- Create: `bench/run_perf.sh`
- Modify: `bench/README.md` (perf/gprof usage)

**Interfaces:**
- Produces: `bench/run_perf.sh <n>` — verifies `perf` works (checks `/proc/sys/kernel/perf_event_paranoid`, prints a `guest.nix` request if counters are denied), then runs `taskset -c 2 perf stat -e cycles,instructions,L1-dcache-load-misses,LLC-load-misses,branch-misses bench/eval <n>`. Note: `perf stat` wraps the whole process; per-candidate isolation comes from running the driver with a single candidate selected via an env var `EVAL_ONLY=<name>` (add that filter to the driver's `candidates::all`).

- [ ] **Step 1: Add an `EVAL_ONLY` filter to the driver**

In `bench/candidates/registry.h`, after building `v`, drop candidates whose name != `getenv("EVAL_ONLY")` when that env var is set:

```cpp
  if (const char* only = std::getenv("EVAL_ONLY")) {
    std::vector<std::unique_ptr<eval::Candidate>> f;
    for (auto& c : v) if (c->name() == only) f.push_back(std::move(c));
    return f;
  }
```

- [ ] **Step 2: Write `bench/run_perf.sh`**

```sh
#!/bin/sh
# perf stat isolated to one candidate's query region (via EVAL_ONLY).
# Usage: bench/run_perf.sh <candidate-name> [n]
set -e
CAND="$1"; N="${2:-10000000}"
PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 3)
if [ "$PARANOID" -gt 1 ]; then
  echo "perf_event_paranoid=$PARANOID — counters likely denied."
  echo "Request in vm/guest.nix: boot.kernel.sysctl.\"kernel.perf_event_paranoid\" = 1;"
fi
EVAL_ONLY="$CAND" taskset -c 2 perf stat \
  -e cycles,instructions,L1-dcache-load-misses,LLC-load-misses,branch-misses \
  bench/eval "$N"
```

- [ ] **Step 3: Verify (best-effort; perf may be denied pre-reboot)**

Run: `chmod +x bench/run_perf.sh; ./bench/run_perf.sh block256 1000000 2>&1 | tail -20`
Expected: either a `perf stat` counter block, or the `perf_event_paranoid` guidance message (both acceptable; the script must not crash the bench).

- [ ] **Step 4: Document gprof build in README**

Add to `bench/README.md`: build with `-pg` for call-graph time on a hot candidate: `g++ -O3 -march=native -std=c++17 -pg -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -o bench/eval_pg && EVAL_ONLY=c6 taskset -c 2 bench/eval_pg 10000000 && gprof bench/eval_pg gmon.out | head -40`. And the instrumented probe build: add `-DHASHER_PROBE`.

- [ ] **Step 5: Commit**

```bash
git add bench/run_perf.sh bench/candidates/registry.h bench/README.md
git commit -m "feat(bench): add perf stat wrapper, EVAL_ONLY filter, gprof/probe build docs"
```

---

## Phase 2 — Candidate interface & initial candidate set

Every candidate is a self-contained `eval::Candidate` subclass in `bench/candidates/`. The build phase measures its own wall-time into `Budget.build_ns` (using `std::chrono::steady_clock`) so the leaderboard shows the untimed setup cost. All candidates keep the sorted array intact (`preserves_sorted = true`) except where noted.

### Task 8: The bar — C0 basic, C1 block256, phmap, unordered

**Files:**
- Create: `bench/candidates/c0_basic.h`, `bench/candidates/c1_block256.h`, `bench/candidates/ext_phmap.h`, `bench/candidates/ext_unordered.h`
- Modify: `bench/candidates/registry.h` (register all four)

**Interfaces:**
- Consumes: `eval::Candidate`, `BasicLookupStrategy<L>`, `BlockLookupStrategy<L,8>`, `phmap::flat_hash_set`, `std::unordered_set`.
- Produces: `C0Basic<L>`, `C1Block256<L>`, `ExtPhmap<L>`, `ExtUnordered<L>` — each an `eval::Candidate`.

- [ ] **Step 1: Write `c0_basic.h` and `c1_block256.h`**

```cpp
// bench/candidates/c0_basic.h
#pragma once
#include "eval/candidate.h"
#include "hashset/basic_ls.h"
#include <chrono>
#include <memory>

template <size_t L>
struct C0Basic : eval::Candidate {
  std::unique_ptr<BasicLookupStrategy<L>> ls;
  double build_ns = 0;
  std::string name() const override { return "c0-basic"; }
  void build(const HashSet& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    ls = std::make_unique<BasicLookupStrategy<L>>(hs.beg(), hs.end());
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  // Works for a HashSetView too: build() only needs beg()/end().
  template <class SetT> void build_v(const SetT& hs) {
    ls = std::make_unique<BasicLookupStrategy<L>>(hs.beg(), hs.end());
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return { build_ns, 0.0, true }; }
};
```

**Note on views:** `eval::Candidate::build` takes `const HashSet&`, but the NSRL columns are `HashSetView`. Resolve by making `build` accept a lightweight `SetRef` that both `HashSet` and `HashSetView` convert to. Add to `bench/eval/candidate.h`:

```cpp
// non-owning reference any set-like exposes; used by build()
struct SetRef {
  size_t hlen, count; const uint8_t* data;
  const uint8_t* beg() const { return data; }
  const uint8_t* end() const { return data + count * hlen; }
  const uint8_t* at(size_t i) const { return data + i * hlen; }
  template <class SetT> SetRef(const SetT& s) : hlen(s.hlen), count(s.count), data(s.beg()) {}
};
```

and change `Candidate::build`'s signature to `virtual void build(const SetRef& hs) = 0;`. Update every candidate's `build` to take `const eval::SetRef&`. Update `oracle.h`/`suite.h` calls (they already pass a set-like, which converts). Update the Task 2/3/4 tests' inline candidates to `build(const eval::SetRef&)`.

```cpp
// bench/candidates/c1_block256.h
#pragma once
#include "eval/candidate.h"
#include "hashset/block_ls.h"
#include "hashset/util.h"
#include <array>
#include <chrono>
#include <memory>

template <size_t L>
struct C1Block256 : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<L,8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  double build_ns = 0;
  std::string name() const override { return "c1-block256"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      const size_t e = expected_index(hs.at(i), static_cast<uint32_t>(hs.count));
      const int64_t d = (int64_t)i - (int64_t)e;
      const size_t bi = hs.at(i)[0];
      b[bi].first  = std::min(b[bi].first, d);
      b[bi].second = std::max(b[bi].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<L,8>>(hs.beg(), hs.end(), b);
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return { build_ns, 0.0, true }; }
};
```

- [ ] **Step 2: Write `ext_phmap.h` and `ext_unordered.h`**

```cpp
// bench/candidates/ext_phmap.h
#pragma once
#include "eval/candidate.h"
#include <array>
#include <chrono>
#include <cstring>
#include <parallel_hashmap/phmap.h>

// Swiss-table reference (the "Abseil territory" north star). NOT sorted:
// it stores a full hashed copy, so preserves_sorted=false and aux bytes are
// reported (the extra table + key copies beyond the canonical array).
template <size_t L>
struct ExtPhmap : eval::Candidate {
  phmap::flat_hash_set<std::array<uint8_t,L>> set;
  double build_ns = 0; size_t nhash = 0;
  std::string name() const override { return "phmap"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    nhash = hs.count; set.reserve(hs.count);
    std::array<uint8_t,L> k;
    for (size_t i = 0; i < hs.count; ++i) { std::memcpy(k.data(), hs.at(i), L); set.insert(k); }
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override {
    std::array<uint8_t,L> k; std::memcpy(k.data(), h, L); return set.contains(k);
  }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);
  }
  eval::Budget budget() const override {
    // ~sizeof(key)+1 control byte per slot at ~1.4 load factor, all auxiliary.
    return { build_ns, (double)(L + 1) * 1.4, false };
  }
};
```

```cpp
// bench/candidates/ext_unordered.h
#pragma once
#include "eval/candidate.h"
#include <array>
#include <chrono>
#include <cstring>
#include <unordered_set>

template <size_t L>
struct ArrHash { size_t operator()(const std::array<uint8_t,L>& a) const {
  size_t h = 1469598103934665603ull;
  for (uint8_t c : a) { h ^= c; h *= 1099511628211ull; } return h; } };

template <size_t L>
struct ExtUnordered : eval::Candidate {
  std::unordered_set<std::array<uint8_t,L>, ArrHash<L>> set;
  double build_ns = 0;
  std::string name() const override { return "unordered"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    set.reserve(hs.count);
    std::array<uint8_t,L> k;
    for (size_t i = 0; i < hs.count; ++i) { std::memcpy(k.data(), hs.at(i), L); set.insert(k); }
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override {
    std::array<uint8_t,L> k; std::memcpy(k.data(), h, L); return set.find(k) != set.end();
  }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);
  }
  eval::Budget budget() const override { return { build_ns, (double)(L + 24), false }; }
};
```

- [ ] **Step 3: Register the bar in `registry.h`**

```cpp
// bench/candidates/registry.h  (extend all<L>())
#include "candidates/ext_phmap.h"
#include "candidates/ext_unordered.h"
// ... inside all<L>():
  v.push_back(std::make_unique<C0Basic<L>>());
  v.push_back(std::make_unique<C1Block256<L>>());
  v.push_back(std::make_unique<ExtPhmap<L>>());
  v.push_back(std::make_unique<ExtUnordered<L>>());
```

- [ ] **Step 4: Build the frozen driver and run the bar**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | head -40`
Expected: a table with `c0-basic`, `c1-block256`, `phmap`, `unordered` rows, all validated (no DISQUALIFIED), single + batch ns printed. `c1-block256` batch should be several× faster than its single (matches README's 3.2×).

- [ ] **Step 5: Commit**

```bash
git add bench/candidates/c0_basic.h bench/candidates/c1_block256.h bench/candidates/ext_phmap.h bench/candidates/ext_unordered.h bench/candidates/registry.h bench/eval/candidate.h
git commit -m "feat(bench): add bar candidates (basic, block256, phmap, unordered)"
```

### Task 9: Convex-hull supporting-line ("min-width slab") computation

**Files:**
- Create: `include/hashset/hull_lines.h`
- Test: `test/test_hull_lines.cpp` (Catch2), registered in `Makefile.am`

**Interfaces:**
- Consumes: `include/hashset/convex_hull.h` (`Point<T>`, `upper_ch`, `lower_ch`), `expected_index`.
- Produces:
  - `struct BlockLine { float s; float c_lo; float c_hi; bool empty; };` — for a block, `lo_index(e) = e + floor(s*e + c_lo)`, `hi_index(e) = e + ceil(s*e + c_hi) + 1`. `empty` marks a block with no stored hash.
  - `template <class SetT> std::array<BlockLine,256> make_block_hull_lines(const SetT& hs);` — for each leading-byte block, gathers points `(e_i, d_i)` with `d_i = i - e_i`, computes the min-width single-slope slab from convex-hull edge slopes, then **verifies and widens**: it re-evaluates `floor`/`ceil` with the chosen float `s,c_lo,c_hi` against every point and widens `c_lo`/`c_hi` by 1 until every point's actual index lies within `[lo_index(e_i), hi_index(e_i))`. This guarantees correctness despite float rounding.
  - **Correctness invariant (document in the header):** for any stored hash with expected index `e` and actual index `i` in block `b`, `lo_index(e) <= i < hi_index(e)`. A query equal to a stored hash shares its `e` and block, so its window contains it. Misses need no window guarantee (absent ⇒ `false` regardless). Correctness therefore never depends on uniformity — only window *tightness* does.

- [ ] **Step 1: Write the failing test**

```cpp
// test/test_hull_lines.cpp
#include <catch2/catch_test_macros.hpp>
#include "hashset/hull_lines.h"
#include "hashset/util.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <random>
#include <vector>

namespace {
template <size_t L>
struct Set {
  size_t hlen = L, count;
  std::vector<uint8_t> d;
  const uint8_t* at(size_t i) const { return d.data() + i * L; }
  const uint8_t* beg() const { return d.data(); }
  const uint8_t* end() const { return d.data() + count * L; }
};
template <size_t L>
Set<L> make(size_t n, uint64_t seed) {
  std::mt19937_64 re(seed);
  std::vector<std::array<uint8_t,L>> rows(n);
  for (auto& r : rows) for (auto& x : r) x = (uint8_t)re();
  std::sort(rows.begin(), rows.end(), [](auto&a,auto&b){return std::memcmp(a.data(),b.data(),L)<0;});
  Set<L> s; s.count = n; s.d.resize(n*L);
  for (size_t k=0;k<n;++k) std::memcpy(s.d.data()+k*L, rows[k].data(), L);
  return s;
}
} // namespace

TEST_CASE("hull_lines_bound_every_stored_hash") {
  auto s = make<20>(200000, 1);
  auto lines = make_block_hull_lines(s);
  for (size_t i = 0; i < s.count; ++i) {
    const uint8_t* h = s.at(i);
    const size_t e = expected_index(h, (uint32_t)s.count);
    const BlockLine& bl = lines[h[0]];
    REQUIRE(!bl.empty);
    const int64_t lo = (int64_t)e + (int64_t)std::floor(bl.s * (double)e + bl.c_lo);
    const int64_t hi = (int64_t)e + (int64_t)std::ceil (bl.s * (double)e + bl.c_hi) + 1;
    REQUIRE(lo <= (int64_t)i);
    REQUIRE((int64_t)i < hi);
  }
}

TEST_CASE("hull_lines_empty_block_flagged") {
  auto s = make<20>(50, 2);              // tiny: most first-byte blocks empty
  auto lines = make_block_hull_lines(s);
  size_t empties = 0;
  for (auto& bl : lines) if (bl.empty) ++empties;
  REQUIRE(empties > 200);                // vast majority of 256 blocks empty
}
```

- [ ] **Step 2: Run test to verify it fails**

Add `test/test_hull_lines.cpp` to `test_test_SOURCES`. Run: `make check TESTS=test/test 2>&1 | tail -20`
Expected: FAIL — `hashset/hull_lines.h` not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/hashset/hull_lines.h
#pragma once

#include "hashset/convex_hull.h"
#include "hashset/util.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>

// Per-block linear bound lines derived from the convex hull of (expected_index,
// deviation) points. lo_index(e) = e + floor(s*e + c_lo);
// hi_index(e) = e + ceil(s*e + c_hi) + 1.  See the correctness invariant in the
// plan: every stored hash in the block lies inside its window, so lookups stay
// exact on ANY distribution; uniformity only affects window tightness.
struct BlockLine { float s = 0.0f; float c_lo = 0.0f; float c_hi = 0.0f; bool empty = true; };

namespace hull_detail {

// For a fixed slope s, the tightest slab of that slope containing all points is
// c_lo = min(d - s*e), c_hi = max(d - s*e). Returns width and fills c_lo/c_hi.
inline double slab_for_slope(const std::vector<Point<double>>& pts, double s,
                             double& c_lo, double& c_hi) {
  c_lo = std::numeric_limits<double>::max();
  c_hi = std::numeric_limits<double>::lowest();
  for (const auto& p : pts) {
    const double r = p.y - s * p.x;
    if (r < c_lo) c_lo = r;
    if (r > c_hi) c_hi = r;
  }
  return c_hi - c_lo;
}

// Candidate slopes = edge slopes of the upper and lower convex hulls, plus 0
// (which recovers the flat block bound as a safe baseline). The min-width slab's
// slope is achieved by a hull edge, so this finds the optimum.
inline void collect_slopes(const std::vector<Point<double>>& hull, std::vector<double>& out) {
  for (size_t i = 1; i < hull.size(); ++i) {
    const double dx = hull[i].x - hull[i-1].x;
    if (std::fabs(dx) > 1e-9) out.push_back((hull[i].y - hull[i-1].y) / dx);
  }
}

} // namespace hull_detail

template <class SetT>
std::array<BlockLine,256> make_block_hull_lines(const SetT& hs) {
  std::array<BlockLine,256> lines;
  std::array<std::vector<Point<double>>,256> pts;

  for (size_t i = 0; i < hs.count; ++i) {
    const uint8_t* h = hs.at(i);
    const size_t e = expected_index(h, static_cast<uint32_t>(hs.count));
    const double d = static_cast<double>((int64_t)i - (int64_t)e);
    pts[h[0]].emplace_back(static_cast<double>(e), d);
  }

  for (int b = 0; b < 256; ++b) {
    auto& P = pts[b];
    BlockLine& bl = lines[b];
    if (P.empty()) { bl.empty = true; continue; }
    bl.empty = false;

    // points already grouped; sort by x (expected index) for the hull.
    std::sort(P.begin(), P.end(), [](const Point<double>& a, const Point<double>& b){
      return a.x < b.x || (a.x == b.x && a.y < b.y);
    });

    std::vector<double> slopes{0.0};
    if (P.size() >= 3) {
      hull_detail::collect_slopes(upper_ch(P), slopes);
      hull_detail::collect_slopes(lower_ch(P), slopes);
    }

    double best_w = std::numeric_limits<double>::max(), bs = 0, blo = 0, bhi = 0;
    for (double s : slopes) {
      double clo, chi;
      const double w = hull_detail::slab_for_slope(P, s, clo, chi);
      if (w < best_w) { best_w = w; bs = s; blo = clo; bhi = chi; }
    }

    // Store as float, then VERIFY+WIDEN so float rounding can never exclude a
    // stored point (which would corrupt correctness).
    bl.s = static_cast<float>(bs);
    bl.c_lo = static_cast<float>(std::floor(blo));
    bl.c_hi = static_cast<float>(std::ceil(bhi));
    bool ok = false;
    while (!ok) {
      ok = true;
      for (const auto& p : P) {
        const int64_t e = (int64_t)p.x;
        const int64_t i = (int64_t)(p.x + p.y);     // actual = e + d
        const int64_t lo = e + (int64_t)std::floor(bl.s * (double)e + bl.c_lo);
        const int64_t hi = e + (int64_t)std::ceil (bl.s * (double)e + bl.c_hi) + 1;
        if (i < lo) { bl.c_lo -= 1.0f; ok = false; }
        if (i >= hi) { bl.c_hi += 1.0f; ok = false; }
      }
    }
  }
  return lines;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make check TESTS=test/test 2>&1 | tail -20`
Expected: PASS — both `hull_lines_*` cases pass (every stored hash bounded; empties flagged).

- [ ] **Step 5: Commit**

```bash
git add include/hashset/hull_lines.h test/test_hull_lines.cpp Makefile.am
git commit -m "feat(hashset): add convex-hull min-width slab per-block bound lines (verify+widen)"
```

### Task 10: C2 block-linear (revived with true hull lines + branchless search)

**Files:**
- Create: `bench/candidates/c2_block_linear.h`
- Modify: `include/hashset/block_linear_ls.h` (replace `std::binary_search` with the branchless windowed search; use `BlockLine` bounds with floor/ceil + clamping; add batch override); `bench/candidates/registry.h`
- Test: covered by the oracle in the leaderboard run (Step 4) + the round-trip tests in Phase 5.

**Interfaces:**
- Consumes: `BlockLine` (Task 9), `primary_key`/`fast_hash_cmp`/`HASHER_PREFETCH` (`hash_compare.h`), `expected_index`.
- Produces: `BlockLinearLookupStrategy<L,8>` rebuilt to take `std::array<BlockLine,256>` and expose `contains` + `contains_batch` with the same branchless/pipelined machinery as `BlockLookupStrategy`; `C2BlockLinear<L>` candidate.

- [ ] **Step 1: Rewrite `block_linear_ls.h` to match the shipping search machinery**

Replace the file with a strategy that (a) takes `std::array<BlockLine, (1<<BlockBits)>`, (b) computes the window via floor/ceil + clamp, (c) reuses the exact branchless `search_window` and staged `contains_batch` from `BlockLookupStrategy` (factor the shared window-search into a small base or copy verbatim). Concretely, mirror `block_ls.h` but swap only the `window()` body:

```cpp
// include/hashset/block_linear_ls.h  (full replacement)
#pragma once

#include "hashset/basic_ls.h"
#include "hashset/hash_compare.h"
#include "hashset/hull_lines.h"     // BlockLine
#include "hashset/probe.h"
#include "hashset/util.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

template <size_t HashLength, size_t BlockBits>
class BlockLinearLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  BlockLinearLookupStrategy(const void* beg, const void* end,
                            std::array<BlockLine, (1u << BlockBits)> blocks)
    : BasicLookupStrategy<HashLength>(beg, end), Blocks(blocks) {}
  virtual ~BlockLinearLookupStrategy() {}

  bool contains(const uint8_t* hash) const override {
    size_t lo, hi; window(hash, lo, hi); return search_window(hash, lo, hi);
  }
  void contains_batch(const uint8_t* hashes, size_t n, size_t stride, bool* results) const override {
    staged_batch(hashes, n, stride, results);
  }

protected:
  const uint8_t* base() const { return reinterpret_cast<const uint8_t*>(this->HashesBeg.get()); }
  size_t count() const { return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get()); }

  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const size_t exp = expected_index(hash, static_cast<uint32_t>(n));
    const size_t bi = hash[0] >> (8 - BlockBits);
    const BlockLine& bl = Blocks[bi];
    if (bl.empty) { lo = hi = 0; return; }
    int64_t l = (int64_t)exp + (int64_t)std::floor(bl.s * (double)exp + bl.c_lo);
    int64_t r = (int64_t)exp + (int64_t)std::ceil (bl.s * (double)exp + bl.c_hi) + 1;
    if (l < 0) l = 0;
    if (r > (int64_t)n) r = (int64_t)n;
    lo = (size_t)l;
    hi = (size_t)(r > l ? r : l);
  }

  // Identical to BlockLookupStrategy::search_window (branchless lower_bound on
  // the primary key + full-hash confirm). Copied verbatim so the query surface
  // is the same code that ships.
  inline bool search_window(const uint8_t* hash, size_t lo, size_t hi) const {
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);
    size_t pos = lo, len = hi - lo;
    while (len > 0) {
      const size_t half = len >> 1, probe = pos + half;
      HASHER_PROBE_TOUCH(b + probe * HashLength); HASHER_PROBE_CMP();
      const uint64_t pk = primary_key<HashLength>(b + probe * HashLength);
      const bool lt = pk < hk;
      pos = lt ? probe + 1 : pos; len = lt ? len - half - 1 : half;
    }
    if constexpr (HashLength <= 8) {
      return pos < hi && primary_key<HashLength>(b + pos * HashLength) == hk;
    } else {
      for (size_t j = pos; j < hi; ++j) {
        const uint8_t* cand = b + j * HashLength;
        if (primary_key<HashLength>(cand) != hk) break;
        if (std::memcmp(cand + 8, hash + 8, HashLength - 8) == 0) return true;
      }
      return false;
    }
  }

  // Identical staged pipeline to BlockLookupStrategy::staged_batch, but calling
  // this class's window(). (Copy the D=32 lane loop verbatim from block_ls.h,
  // replacing only the window() call — it is already a member here.)
  void staged_batch(const uint8_t* hashes, size_t n, size_t stride, bool* results) const {
    /* VERBATIM copy of BlockLookupStrategy::staged_batch body from
       include/hashset/block_ls.h lines 121-201, unchanged: it already calls
       window()/base()/count()/fast_hash_cmp/HASHER_PREFETCH, all members here. */
  }

  std::array<BlockLine, (1u << BlockBits)> Blocks;
};
```

Fill the `staged_batch` body by copying `BlockLookupStrategy::staged_batch` (block_ls.h:121–201) verbatim — it references only `window`, `base`, `count`, `fast_hash_cmp`, `HASHER_PREFETCH`, all valid here. Add the two `HASHER_PROBE_*` hook lines before its `fast_hash_cmp` call (as in Task 1).

- [ ] **Step 2: Write `c2_block_linear.h`**

```cpp
// bench/candidates/c2_block_linear.h
#pragma once
#include "eval/candidate.h"
#include "hashset/block_linear_ls.h"
#include "hashset/hull_lines.h"
#include <chrono>
#include <memory>

template <size_t L>
struct C2BlockLinear : eval::Candidate {
  std::unique_ptr<BlockLinearLookupStrategy<L,8>> ls;
  std::array<BlockLine,256> lines;
  double build_ns = 0;
  std::string name() const override { return "c2-block-linear"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    lines = make_block_hull_lines(hs);
    ls = std::make_unique<BlockLinearLookupStrategy<L,8>>(hs.beg(), hs.end(), lines);
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return { build_ns, 256.0*16.0/hs_count(), true }; }
private:
  // aux bytes = 256 blocks * 16 B (4 floats) spread over the set.
  double hs_count() const { return ls ? (double)(/*count*/1) : 1.0; }
};
```

Fix the `aux_bytes_per_hash`: capture `count` at build time (`size_t nhash;`) and return `256.0*16.0/nhash`. (256×16 B = 4 KB of block lines, amortized per hash — negligible, but reported honestly.)

- [ ] **Step 3: Register C2**

Add `#include "candidates/c2_block_linear.h"` and `v.push_back(std::make_unique<C2BlockLinear<L>>());` to `registry.h`.

- [ ] **Step 4: Build + run; C2 must validate and be timed**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | grep -E "c2-block-linear|DISQUALIFIED"`
Expected: `c2-block-linear` appears with ns numbers and is **not** DISQUALIFIED on any dataset (synthetic, adversarial, NSRL). Its window should be tighter than `c1-block256` (fewer probe touches/lookup in the budget line).

- [ ] **Step 5: Commit**

```bash
git add include/hashset/block_linear_ls.h bench/candidates/c2_block_linear.h bench/candidates/registry.h
git commit -m "feat: revive block-linear strategy with true convex-hull lines + branchless/pipelined search"
```

### Task 11: C3 global-hull

**Files:**
- Create: `include/hashset/global_hull_ls.h`, `bench/candidates/c3_global_hull.h`
- Modify: `bench/candidates/registry.h`

**Interfaces:**
- Consumes: `upper_ch`/`lower_ch`, `expected_index`, the branchless `search_window` pattern.
- Produces: `GlobalHullLookupStrategy<L>` — builds ONE upper and ONE lower hull over all `(expected_index, actual_index)` points; at query time binary-searches the hull vertices for the segment bracketing the query's `exp` and evaluates the two supporting lines to get `[lo, hi]`, then runs the branchless window search. `C3GlobalHull<L>` candidate.
- **Correctness:** the global upper hull lies on/above every point and the lower hull on/below, so `lo <= actual < hi` for every stored hash ⇒ exact lookups on any distribution (uniformity only affects tightness).

- [ ] **Step 1: Write `global_hull_ls.h`**

```cpp
// include/hashset/global_hull_ls.h
#pragma once
#include "hashset/basic_ls.h"
#include "hashset/convex_hull.h"
#include "hashset/hash_compare.h"
#include "hashset/probe.h"
#include "hashset/util.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

template <size_t HashLength>
class GlobalHullLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  GlobalHullLookupStrategy(const void* beg, const void* end)
    : BasicLookupStrategy<HashLength>(beg, end) { build_hulls(); }

  bool contains(const uint8_t* hash) const override {
    size_t lo, hi; window(hash, lo, hi); return search_window(hash, lo, hi);
  }

protected:
  const uint8_t* base() const { return reinterpret_cast<const uint8_t*>(this->HashesBeg.get()); }
  size_t count() const { return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get()); }

  void build_hulls() {
    const size_t n = count();
    std::vector<Point<double>> pts; pts.reserve(n);
    const uint8_t* b = base();
    for (size_t i = 0; i < n; ++i) {
      const size_t e = expected_index(b + i * HashLength, static_cast<uint32_t>(n));
      pts.emplace_back((double)e, (double)i);
    }
    std::sort(pts.begin(), pts.end(), [](const Point<double>&a,const Point<double>&b){
      return a.x < b.x || (a.x==b.x && a.y<b.y); });
    Upper = upper_ch(pts);    // above all points  -> hi bound
    Lower = lower_ch(pts);    // below all points  -> lo bound
    std::sort(Upper.begin(), Upper.end(), [](auto&a,auto&b){return a.x<b.x;});
    std::sort(Lower.begin(), Lower.end(), [](auto&a,auto&b){return a.x<b.x;});
  }

  // Evaluate a hull (as a piecewise-linear function) at x by locating the
  // bracketing segment with a binary search over vertices.
  static double eval_hull(const std::vector<Point<double>>& h, double x) {
    if (x <= h.front().x) return h.front().y;
    if (x >= h.back().x)  return h.back().y;
    size_t lo = 0, hi = h.size() - 1;
    while (hi - lo > 1) { size_t m = (lo+hi)/2; if (h[m].x <= x) lo = m; else hi = m; }
    const double t = (x - h[lo].x) / (h[hi].x - h[lo].x);
    return h[lo].y + t * (h[hi].y - h[lo].y);
  }

  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const double e = (double)expected_index(hash, static_cast<uint32_t>(n));
    int64_t l = (int64_t)std::floor(eval_hull(Lower, e));
    int64_t r = (int64_t)std::ceil (eval_hull(Upper, e)) + 1;
    if (l < 0) l = 0; if (r > (int64_t)n) r = (int64_t)n;
    lo = (size_t)l; hi = (size_t)(r > l ? r : l);
  }

  inline bool search_window(const uint8_t* hash, size_t lo, size_t hi) const {
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);
    size_t pos = lo, len = hi - lo;
    while (len > 0) {
      const size_t half = len >> 1, probe = pos + half;
      HASHER_PROBE_TOUCH(b + probe*HashLength); HASHER_PROBE_CMP();
      const uint64_t pk = primary_key<HashLength>(b + probe*HashLength);
      const bool lt = pk < hk; pos = lt ? probe+1 : pos; len = lt ? len-half-1 : half;
    }
    if constexpr (HashLength <= 8) return pos < hi && primary_key<HashLength>(b + pos*HashLength) == hk;
    else { for (size_t j=pos;j<hi;++j){ const uint8_t* c=b+j*HashLength; if(primary_key<HashLength>(c)!=hk)break; if(std::memcmp(c+8,hash+8,HashLength-8)==0)return true;} return false; }
  }

  std::vector<Point<double>> Upper, Lower;
};
```

Note: `eval_hull` piecewise-linear interpolation stays on/above (Upper) and on/below (Lower) all points because the hull is convex and we interpolate *between adjacent hull vertices* — chords of the upper hull lie on/above interior points, chords of the lower hull on/below. Add a build-time `assert`-style verify+widen (same loop as Task 9) to guard float rounding: after building, for each stored point check `lo<=i<hi`, and if not, nudge the nearer hull vertex outward by 1. Include this loop.

- [ ] **Step 2: Write `c3_global_hull.h` (mirror C2's wrapper), register in `registry.h`.**

```cpp
// bench/candidates/c3_global_hull.h
#pragma once
#include "eval/candidate.h"
#include "hashset/global_hull_ls.h"
#include <chrono>
#include <memory>
template <size_t L>
struct C3GlobalHull : eval::Candidate {
  std::unique_ptr<GlobalHullLookupStrategy<L>> ls; double build_ns=0; size_t nhash=0;
  std::string name() const override { return "c3-global-hull"; }
  void build(const eval::SetRef& hs) override {
    auto t0=std::chrono::steady_clock::now(); nhash=hs.count;
    ls=std::make_unique<GlobalHullLookupStrategy<L>>(hs.beg(), hs.end());
    build_ns=std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q,size_t n,size_t s,bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return { build_ns, 0.0, true }; }  // hull vertices are O(hull) << set
};
```

`GlobalHullLookupStrategy` inherits the default `contains_batch` (loops `contains`); that is acceptable for C3 (its point is the tight *global* bound, batched pipelining is C6's job). Note this in RESULTS.md.

- [ ] **Step 3: Build + run; verify C3 validates on all datasets incl. adversarial.**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | grep -E "c3-global-hull|DISQUALIFIED"`
Expected: `c3-global-hull` timed, never DISQUALIFIED.

- [ ] **Step 4: Commit**

```bash
git add include/hashset/global_hull_ls.h bench/candidates/c3_global_hull.h bench/candidates/registry.h
git commit -m "feat: add C3 global-hull lookup strategy + candidate"
```

### Task 12: C4 fine-block (12–16 leading bits)

**Files:**
- Create: `include/hashset/fine_block_ls.h`, `bench/candidates/c4_fine_block.h`
- Modify: `bench/candidates/registry.h`

**Interfaces:**
- Produces: `FineBlockLookupStrategy<L, BlockBits>` — flat min/max delta bounds keyed on the leading `BlockBits` bits (12–16), where `bi = (leading 16 bits of hash) >> (16 - BlockBits)`. Stores `std::vector<std::pair<int32_t,int32_t>>` of size `1<<BlockBits`. `C4FineBlock<L>` uses `BlockBits = 14`. Branchless windowed search + staged batch (same machinery).
- **Rationale/trade-off:** more blocks ⇒ tighter flat bounds, but the block table grows (`2^14 * 8 B = 128 KB`, reported as aux bytes). This is the "no query-time hull search" point on the curve.

- [ ] **Step 1: Write `fine_block_ls.h`** — copy `block_ls.h` and change only: (a) the block index uses two leading bytes: `const size_t bi = ((hash[0] << 8) | hash[1]) >> (16 - BlockBits);` (valid for `BlockBits <= 16`; require `HashLength >= 2`); (b) `Blocks` is a `std::vector<std::pair<int64_t,int64_t>>` sized `1u<<BlockBits`, taken by the constructor. Keep `search_window`/`staged_batch` verbatim (with probe hooks).

- [ ] **Step 2: Write `c4_fine_block.h`** — mirror C1's wrapper, computing bounds with the 14-bit index; `aux_bytes_per_hash = (double)((size_t)1<<14) * 16.0 / nhash;` `name()` = `"c4-fine-block"`. Register in `registry.h`.

```cpp
// build() bounds computation (14-bit blocks):
    constexpr size_t BB = 14;
    b.assign((size_t)1<<BB, {INT64_MAX, INT64_MIN});
    for (size_t i=0;i<hs.count;++i){ const uint8_t* h=hs.at(i);
      const size_t e=expected_index(h,(uint32_t)hs.count); const int64_t d=(int64_t)i-(int64_t)e;
      const size_t bi=((h[0]<<8)|h[1])>>(16-BB);
      b[bi].first=std::min(b[bi].first,d); b[bi].second=std::max(b[bi].second,d); }
    ls=std::make_unique<FineBlockLookupStrategy<L,BB>>(hs.beg(),hs.end(),b);
```

- [ ] **Step 3: Build + run; verify C4 validates (esp. small sets: empty fine blocks use the sentinel path).**

Run: `g++ ... bench/eval.cpp ... -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | grep -E "c4-fine-block|DISQUALIFIED"`
Expected: timed, never DISQUALIFIED.

- [ ] **Step 4: Commit**

```bash
git add include/hashset/fine_block_ls.h bench/candidates/c4_fine_block.h bench/candidates/registry.h
git commit -m "feat: add C4 fine-block (14-bit) lookup strategy + candidate"
```

### Task 13: C5 interpolation ("dictionary") search within hull bounds

**Files:**
- Create: `include/hashset/interp_ls.h` (defines `InterpLookupStrategy<L>`), `bench/candidates/c5_interp.h`
- Modify: `bench/candidates/registry.h`

**Interfaces:**
- Consumes: the per-block hull lines (`make_block_hull_lines`, reused) OR the global hull — C5 uses **per-block hull lines** to establish `[lo,hi]` once (recursive hulls are too much overhead, per the spec), then interpolation search inside.
- Produces: `InterpLookupStrategy<L>` — window via `BlockLine`, then a bounded interpolation search on the leading-8-byte primary key: at each step estimate `probe = lo + (hk - key[lo]) / (key[hi-1] - key[lo]) * (hi-1-lo)`, clamp into `[lo,hi)`, compare, shrink `[lo,hi)`; fall back to one branchless step if the estimate fails to shrink (guarantees termination and O(log) worst case). `C5Interp<L>` candidate.
- **Correctness:** the loop maintains the invariant that `hk`, if present, lies in `[lo,hi)`; it only chooses *where* to probe. Interpolation's pathological case only costs *time*, never correctness — and cannot even arise on uniform crypto hashes. Confirm full hash on match (tail compare for `L>8`).

- [ ] **Step 1: Write `interp_ls.h`**

```cpp
// include/hashset/interp_ls.h
#pragma once
#include "hashset/basic_ls.h"
#include "hashset/hash_compare.h"
#include "hashset/hull_lines.h"
#include "hashset/probe.h"
#include "hashset/util.h"
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

template <size_t HashLength>
class InterpLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  InterpLookupStrategy(const void* beg, const void* end, std::array<BlockLine,256> blocks)
    : BasicLookupStrategy<HashLength>(beg, end), Blocks(blocks) {}
  bool contains(const uint8_t* hash) const override {
    size_t lo, hi; window(hash, lo, hi); return interp_search(hash, lo, hi);
  }
protected:
  const uint8_t* base() const { return reinterpret_cast<const uint8_t*>(this->HashesBeg.get()); }
  size_t count() const { return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get()); }

  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const size_t exp = expected_index(hash, static_cast<uint32_t>(n));
    const BlockLine& bl = Blocks[hash[0]];
    if (bl.empty) { lo = hi = 0; return; }
    int64_t l=(int64_t)exp+(int64_t)std::floor(bl.s*(double)exp+bl.c_lo);
    int64_t r=(int64_t)exp+(int64_t)std::ceil (bl.s*(double)exp+bl.c_hi)+1;
    if(l<0)l=0; if(r>(int64_t)n)r=(int64_t)n; lo=(size_t)l; hi=(size_t)(r>l?r:l);
  }

  inline bool interp_search(const uint8_t* hash, size_t lo, size_t hi) const {
    if (lo >= hi) return false;
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);
    size_t l = lo, r = hi;                       // [l, r)
    while (l < r) {
      const uint64_t kl = primary_key<HashLength>(b + l * HashLength);
      HASHER_PROBE_TOUCH(b + l * HashLength);
      if (hk < kl) return false;
      const uint64_t kr = primary_key<HashLength>(b + (r-1) * HashLength);
      HASHER_PROBE_TOUCH(b + (r-1) * HashLength);
      if (hk > kr) return false;
      size_t probe;
      if (kr == kl) { probe = l + ((r - l) >> 1); }
      else {
        // interpolate; long double avoids overflow for 64-bit key spans.
        long double frac = (long double)(hk - kl) / (long double)(kr - kl);
        probe = l + (size_t)(frac * (long double)(r - 1 - l));
        if (probe < l) probe = l; if (probe >= r) probe = r - 1;
      }
      HASHER_PROBE_TOUCH(b + probe * HashLength); HASHER_PROBE_CMP();
      const uint64_t kp = primary_key<HashLength>(b + probe * HashLength);
      if (kp < hk) l = probe + 1;
      else if (kp > hk) r = probe;
      else {
        if constexpr (HashLength <= 8) return true;
        else {                                   // confirm full hash on tie
          for (size_t j = probe; j < hi && primary_key<HashLength>(b+j*HashLength)==hk; ++j)
            if (std::memcmp(b+j*HashLength+8, hash+8, HashLength-8)==0) return true;
          for (size_t j = probe; j-- > lo && primary_key<HashLength>(b+j*HashLength)==hk; )
            if (std::memcmp(b+j*HashLength+8, hash+8, HashLength-8)==0) return true;
          return false;
        }
      }
    }
    return false;
  }
  std::array<BlockLine,256> Blocks;
};
```

- [ ] **Step 2: Write `c5_interp.h`** (mirror C2, but construct `InterpLookupStrategy<L>` with `make_block_hull_lines`), `name()` = `"c5-interp"`, register in `registry.h`.

- [ ] **Step 3: Build + run; C5 must validate on ALL datasets, especially adversarial/clustered (proves correctness doesn't depend on uniformity).**

Run: `g++ ... -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | grep -E "c5-interp|DISQUALIFIED"`
Expected: `c5-interp` timed, never DISQUALIFIED — including the adversarial dataset.

- [ ] **Step 4: Commit**

```bash
git add include/hashset/interp_ls.h bench/candidates/c5_interp.h bench/candidates/registry.h
git commit -m "feat: add C5 interpolation search within per-block hull bounds"
```

### Task 14: C6 hull + interpolation + branchless tail (batch-pipelined synthesis)

**Files:**
- Create: `bench/candidates/c6_hull_interp.h` (adds `HullInterpLookupStrategy<L>` to `include/hashset/interp_ls.h`)
- Modify: `include/hashset/interp_ls.h` (add the synthesis class), `bench/candidates/registry.h`

**Interfaces:**
- Produces: `HullInterpLookupStrategy<L>` — window via `BlockLine`; **one** interpolation probe to split the window; then the branchless windowed binary search on the (now short) tail; plus a `contains_batch` that pipelines D=32 lanes (window + one interp probe + prefetch, then branchless tail), mirroring `staged_batch`. `C6HullInterp<L>`.
- **Correctness:** identical invariant to C5 (interpolation only chooses a split point; the branchless tail is exact over the sub-window that must contain `hk` if present).

- [ ] **Step 1: Add `HullInterpLookupStrategy<L>` to `interp_ls.h`** — reuse `window()`; `contains()` does: compute `[lo,hi)`, one interpolation estimate `p` clamped into range, compare `key[p]` to `hk` to pick the sub-window `[lo,p)` or `[p+1,hi)` (or return true on equal + tail-confirm), then call the verbatim branchless `search_window` (copied from `block_ls.h`, with probe hooks) on that sub-window. Implement `contains_batch` as a staged D=32 pipeline: per lane, do window + one interp probe during dispatch (prefetch the interp probe address), then run the branchless binary on the tail across rounds (copy the lane structure from `staged_batch`, adding a one-shot interp step per lane before the binary loop).

- [ ] **Step 2: Write `c6_hull_interp.h`** (mirror C2's wrapper; `name()` = `"c6-hull-interp"`), register in `registry.h`.

- [ ] **Step 3: Build + run; C6 must validate everywhere and be the batch front-runner.**

Run: `g++ ... -o bench/eval && taskset -c 2 bench/eval 2000000 2>&1 | grep -E "c6-hull-interp|DISQUALIFIED"`
Expected: timed, never DISQUALIFIED; batch ns competitive with or beating `c1-block256` batch.

- [ ] **Step 4: Commit**

```bash
git add include/hashset/interp_ls.h bench/candidates/c6_hull_interp.h bench/candidates/registry.h
git commit -m "feat: add C6 hull+interpolation+branchless-tail synthesis (single + batch pipeline)"
```

### Task 15: Freeze the harness + record the leaderboard (the win-condition gate)

**Files:**
- Modify: `bench/RESULTS.md` (fill in the held-out leaderboard), `bench/README.md`
- No code change; this task runs the frozen harness and records evidence.

**Interfaces:**
- Consumes: the full registry (C0–C6, phmap, unordered).

- [ ] **Step 1: Run the full held-out matrix at scale, pinned.**

Run: `g++ -O3 -march=native -std=c++17 -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval && taskset -c 2 bench/eval 20000000 2>&1 | tee $HOME/build/eval-heldout.txt`
Expected: every candidate validates (no DISQUALIFIED) on synthetic held-out, adversarial, NSRL SHA-1, NSRL MD5; a full ns table for single + batch.

- [ ] **Step 2: Capture perf counters for the top 3 single and top 3 batch candidates.**

Run: `for c in c1-block256 c2-block-linear c6-hull-interp; do ./bench/run_perf.sh $c 20000000 2>&1 | tee -a $HOME/build/eval-perf.txt; done`
Expected: `cycles/instructions/IPC/L1/LLC/branch-miss` per candidate. Record whether ns ranking is *consistent with* LLC-miss ranking (the anti-cheat cross-check).

- [ ] **Step 3: Capture probe cross-check (instrumented build).**

Run: `g++ -O3 -march=native -std=c++17 -DHASHER_PROBE -Iinclude -Ibench -Ivendors/parallel-hashmap bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval_probe && taskset -c 2 bench/eval_probe 20000000 2>&1 | grep probe_touch`
Expected: touches/lookup per candidate; tighter-window candidates (C2/C6) show fewer touches than C1. Flag any candidate whose ns win contradicts its probe/LLC trend.

- [ ] **Step 4: Fill `bench/RESULTS.md`** — the held-out table (single + batch ns min/med/sd, preserves_sorted, aux B/hash, build ms, probe touches/lookup, perf LLC-miss/lookup), the phmap north-star column, and a one-line rationale per candidate (why it won/lost, what the profile showed). Declare the **current leaderboard winner** for single and for batch against the win condition (beat/ tie `block256` on both, no bad regression on any dataset/axis).

- [ ] **Step 5: Freeze marker.**

Add a "HARNESS FROZEN" note + date to `bench/RESULTS.md` and `bench/README.md`: the harness, datasets, seeds, and anti-cheat contract are now fixed; subagents may only *add* candidate files.

- [ ] **Step 6: Commit + tag.**

```bash
git add bench/RESULTS.md bench/README.md
git commit -m "chore(bench): freeze harness; record held-out leaderboard + perf/probe evidence"
git tag harness-frozen
```

---

## Phase 3 — Subagent challenge & code-review gate

This phase is a *process* run against the frozen harness, not new production code. Its deliverables are (a) a challenge packet and template so a subagent can add exactly one candidate file and nothing else, and (b) a written acceptance gate the reviewer applies. Each accepted candidate is a commit adding one `bench/candidates/*.h` + a `registry.h` line.

### Task 16: Challenge packet, candidate template, and acceptance gate

**Files:**
- Create: `bench/CHALLENGE.md`, `bench/candidates/TEMPLATE.h`
- Modify: `bench/candidates/registry.h` (documented registration point)

**Interfaces:**
- Consumes: the frozen harness (`eval::Candidate`, oracle, timing, datasets, `RESULTS.md` bar).
- Produces: a copy-me candidate stub and a reviewer checklist.

- [ ] **Step 1: Write `bench/candidates/TEMPLATE.h`** — a compiling `eval::Candidate` stub a subagent copies to `cN_<idea>.h`:

```cpp
// bench/candidates/TEMPLATE.h — copy to cN_<idea>.h, rename the struct, fill build/contains.
#pragma once
#include "eval/candidate.h"
#include <chrono>
template <size_t L>
struct CandidateTemplate : eval::Candidate {
  double build_ns = 0; size_t nhash = 0;
  std::string name() const override { return "cN-idea"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now(); nhash = hs.count;
    // ... build auxiliary structures over hs (sorted array at hs.beg()/hs.end()) ...
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { /* ... */ return false; }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);   // override for MLP
  }
  eval::Budget budget() const override { return { build_ns, /*aux B/hash*/0.0, /*preserves_sorted*/true }; }
};
```

- [ ] **Step 2: Write `bench/CHALLENGE.md`** — the packet given to each subagent, containing verbatim:
  - The challenge: "Add one `bench/candidates/cN_<idea>.h` that beats `c1-block256` and `c6-hull-interp` on the held-out matrix (single and batch), touching nothing else in the harness. Register it with one line in `registry.h`."
  - The frozen anti-cheat contract (copied from Global Constraints).
  - The current bar (paste the `RESULTS.md` headline numbers).
  - Reserved ideas to try: Eytzinger/BFS layout within the window (flag: does NOT preserve sorted → must report the auxiliary reordered copy in `aux_bytes_per_hash`), two-level RMI/learned index replacing the hull, SSE4.2 SIMD-batched comparison (no AVX2), prefetch-depth tuning for the batch pipeline.
  - The **acceptance gate (applied by the reviewer, in order):**
    1. **Correctness** — `eval::validate` exact match on every dataset incl. adversarial + held-out. One mismatch = rejected.
    2. **Anti-cheat code review** — no work hidden in captured per-query state; no per-query heap alloc; no benchmark-/seed-/dataset-specific constants; no tuning on the held-out set; `contains`/`contains_batch` is the same code that would ship.
    3. **Real win** — beats the bar on the held-out set on ns/lookup, *consistent with* perf counters and probe counts. A ns win contradicted by higher LLC misses or probe counts = rejected pending explanation.
    4. **Generality** — no bad regression on any dataset or on either single/batch axis. Data-reordering candidates are judged with the `preserves_sorted=false` + aux-bytes cost visible.
  - The definition of done for a subagent: a single commit adding one candidate file + one registry line, plus a short rationale paragraph appended to `RESULTS.md`.

- [ ] **Step 3: Commit the packet.**

```bash
git add bench/CHALLENGE.md bench/candidates/TEMPLATE.h bench/candidates/registry.h
git commit -m "docs(bench): add subagent challenge packet, candidate template, acceptance gate"
```

- [ ] **Step 4: Run the challenge (orchestration — performed by the executor, not a code edit).**

Dispatch subagents in parallel (independent files, no shared mutable state), each with `bench/CHALLENGE.md` + the frozen harness + `TEMPLATE.h`. Use superpowers:dispatching-parallel-agents. Each returns one candidate file. Review **sequentially** with the Step 2 gate; accept only passers. For each accepted candidate:

```bash
git add bench/candidates/cN_<idea>.h bench/candidates/registry.h bench/RESULTS.md
git commit -m "feat(bench): accept candidate cN-<idea> (beats bar on <axis>, <profile note>)"
```

Rejected candidates are recorded in `RESULTS.md` with the reason (correctness / anti-cheat / not-a-real-win / regression), then discarded. Re-run `bench/eval` after each acceptance so the leaderboard stays current.

---

## Phase 4 — Profiling loop

For the top candidates, gather counter deltas, hot instructions, call-graph time, and phase-attributed memory accesses; feed findings back as concrete targets for the next subagent round.

### Task 17: Profiling driver + findings log

**Files:**
- Create: `bench/profile.sh`, `bench/PROFILE.md`

**Interfaces:**
- Consumes: `bench/eval` (+ `-pg` and `-DHASHER_PROBE` builds), `bench/run_perf.sh`, `EVAL_ONLY`.

- [ ] **Step 1: Write `bench/profile.sh`** — for a given candidate name and `n`:

```sh
#!/bin/sh
# Usage: bench/profile.sh <candidate-name> [n]
set -e
CAND="$1"; N="${2:-20000000}"
INC="-Iinclude -Ibench -Ivendors/parallel-hashmap"
# 1) perf stat counter deltas
./bench/run_perf.sh "$CAND" "$N"
# 2) perf record/report — hot instructions in the timed region
g++ -O3 -march=native -std=c++17 $INC bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval
EVAL_ONLY="$CAND" taskset -c 2 perf record -o "$HOME/build/perf-$CAND.data" bench/eval "$N" || true
perf report -i "$HOME/build/perf-$CAND.data" --stdio 2>/dev/null | head -40 || true
# 3) gprof — call-graph time
g++ -O3 -march=native -std=c++17 -pg $INC bench/eval.cpp src/lib/hashset/util.cpp -o bench/eval_pg
EVAL_ONLY="$CAND" taskset -c 2 bench/eval_pg "$N"
gprof bench/eval_pg gmon.out | head -40
# 4) probe attribution — touches/comparisons per search phase
g++ -O3 -march=native -std=c++17 -DHASHER_PROBE $INC bench/eval.cpp src/lib/hashset/util.cpp -lrt -o bench/eval_probe
EVAL_ONLY="$CAND" taskset -c 2 bench/eval_probe "$N" | grep probe_touch
```

- [ ] **Step 2: Run for the top single + top batch candidates.**

Run: `chmod +x bench/profile.sh; for c in c2-block-linear c6-hull-interp; do ./bench/profile.sh $c 20000000 2>&1 | tee -a $HOME/build/profile-$c.txt; done`
Expected: per-candidate counters, top hot symbols, gprof call-graph, probe touches. (If `perf record` is denied pre-reboot, the script continues past it via `|| true`.)

- [ ] **Step 3: Write `bench/PROFILE.md`** — record, per profiled candidate: the counter deltas vs `block256`, the hottest instructions/functions, where memory accesses land (hull eval vs interpolation vs tail, from probe attribution), and 2–3 concrete next-round targets (e.g. "C6 tail dominated by branch-misses on windows > 8 → widen interp to two probes", "C2 window still 2× C6 on adversarial → per-block slab too loose under skew").

- [ ] **Step 4: Commit.**

```bash
git add bench/profile.sh bench/PROFILE.md
git commit -m "feat(bench): add profiling driver and findings log"
```

---

## Phase 5 — Production format wiring (the winner)

Wire the benchmark-proven winner into the `.hset` format as a new, additive hint type. **This plan wires the per-block convex-hull supporting-line strategy (hint `0x6209`), the representative winner** (see the winner-dependency note in File Structure). If Task 15 named a different winner, revise the hint payload (Task 18) and the decoded strategy (Task 20) to match before executing; the task shape is unchanged.

### Task 18: New hint type + format documentation

**Files:**
- Modify: `HASHSET_FORMAT`, `include/hashset/hset_structs.h`
- Test: `test/test_hull_lines.cpp` already covers the math; format constants are exercised by Task 21's round-trip test.

**Interfaces:**
- Produces: hint type constant `0x6209` = "block-linear-hull, 8-bit" (`bl8`). Payload layout (all little-endian except the 2-byte big-endian hint type, matching the existing `0x6208` convention): `uint16_t hint_type (BE) = 0x6209`, then `256 × { float32 s; float32 c_lo; float32 c_hi; uint32_t flags }` where `flags` bit 0 = `empty`. Total `2 + 256*16 = 4098` bytes — the same chunk length as `0x6208`, so `length_hint()` is unchanged.
- **Backward compatibility:** `0x6208` (flat block bounds) still decodes to `BlockLookupStrategy`; `0x6209` is new and additive.

- [ ] **Step 1: Document the new hint in `HASHSET_FORMAT`.** Append a "HINT chunk types" section describing both `0x6208` (256 × `{int64 min; int64 max}` LE) and the new `0x6209` (256 × `{float32 s; float32 c_lo; float32 c_hi; uint32 flags}` LE; `lo_index(e)=e+floor(s*e+c_lo)`, `hi_index(e)=e+ceil(s*e+c_hi)+1`, `flags&1`=empty block). State the correctness invariant and that both are 4098-byte chunks.

- [ ] **Step 2: Add the constant to `hset_structs.h`.** In the `HintType` enum add `BLOCK_LINEAR_HULL = 0x6209` (keep the existing `BLOCK_LINEAR = 4` for source compatibility; the on-disk 16-bit hint value is `0x6209`). Add a one-line comment mapping the enum to the on-disk value.

- [ ] **Step 3: Commit.**

```bash
git add HASHSET_FORMAT include/hashset/hset_structs.h
git commit -m "feat(format): define additive hint type 0x6209 (per-block hull lines)"
```

### Task 19: Encoder — compute hull lines at build time + write the new hint

**Files:**
- Modify: `src/lib/hashset/hset_encoder_chunks.cpp`, `src/lib/hashset/hset_encoder_chunks.h`, `src/lib/hashset/hset_encoder.cpp`
- Test: `test/test_hset_encoder.cpp` (extend), then Task 21 round-trip.

**Interfaces:**
- Consumes: `make_block_hull_lines` (Task 9) — but the encoder iterates `RecordIterator`, not a `SetT`; provide a `RecordIterator` overload `make_block_hull_lines_ri(RecordIterator beg, RecordIterator end, size_t hlen)` in `hull_lines.h` (or adapt the existing `make_block_bounds` loop shape). It computes `BlockLine[256]` from `(expected_index, deviation)` points using the same min-width-slab + verify-and-widen as Task 9.
- Produces: `size_t write_hint_linear(const std::array<BlockLine,256>& lines, char* out);` writing `0x6209` + 256 × `{s,c_lo,c_hi,flags}` (LE floats/uint32). `length_hint()` stays 4098 (assert both variants equal). Encoder selects hint type via a build flag / default; **default to `0x6209`** so new sets ship the winner, but keep `0x6208` reachable for A/B.

- [ ] **Step 1: Add a failing encoder test.** In `test/test_hset_encoder.cpp`, add a `TEST_CASE` that builds a small set, encodes it, and asserts the HINT chunk's leading 2 bytes are `0x62 0x09` (big-endian `0x6209`) when the linear encoder is selected.

- [ ] **Step 2: Run it to verify it fails.** Run: `make check TESTS=test/test 2>&1 | tail -20` → FAIL (`write_hint_linear` undefined / hint still `0x6208`).

- [ ] **Step 3: Implement `make_block_hull_lines_ri`, `write_hint_linear`, `length_hint_data` parity, and route `write_chunks`' `HINT` case to the linear writer.** In `hset_encoder_chunks.cpp`:

```cpp
size_t write_hint_linear(const std::array<BlockLine,256>& lines, char* out) {
  const char* beg = out;
  out += write_be<uint16_t>(0x6209, out);
  for (const auto& bl : lines) {
    out += write_le<float>(bl.s, out);
    out += write_le<float>(bl.c_lo, out);
    out += write_le<float>(bl.c_hi, out);
    out += write_le<uint32_t>(bl.empty ? 1u : 0u, out);
  }
  return out - beg;   // 2 + 256*16 = 4098, == length_hint_data()
}
```

Add `static_assert`/runtime check that `length_hint_data()` (currently `2 + 256*8*2 = 4098`) equals `2 + 256*16`. In `hset_encoder.cpp`'s `write_chunks` `HINT` case, replace `write_hint(make_block_bounds<8>(...), out)` with the linear path:

```cpp
    case Chunk::Type::HINT:
      { const size_t i = off2hbidx.at(choff);
        auto lines = make_block_hull_lines_ri(std::get<1>(hb[i]), std::get<2>(hb[i]),
                                              rhdr.fields[i].length);
        write_hint_linear(lines, out); }
      break;
```

- [ ] **Step 4: Run it to verify it passes.** Run: `make check TESTS=test/test 2>&1 | tail -20` → PASS (hint leads with `0x6209`).

- [ ] **Step 5: Commit.**

```bash
git add src/lib/hashset/hset_encoder_chunks.cpp src/lib/hashset/hset_encoder_chunks.h src/lib/hashset/hset_encoder.cpp include/hashset/hull_lines.h test/test_hset_encoder.cpp
git commit -m "feat(encoder): compute per-block hull lines and write hint 0x6209"
```

### Task 20: Decoder — dispatch the new hint to the revived strategy

**Files:**
- Modify: `src/lib/hashset/hset_decoder.cpp`

**Interfaces:**
- Consumes: `HashsetHint` (`hint_type`, `beg`, `end`), `BlockLinearLookupStrategy<L,8>` (Task 10), `BlockLine`.
- Produces: `make_lookup_strategy` handles `0x6209` → `BlockLinearLookupStrategy`; keeps `0x6208` → `BlockLookupStrategy`; `handle_hint` accepts both hint types (currently it `THROW`s on anything but `0x6208`).

- [ ] **Step 1: Add a `make_lines(const HashsetHint&)` helper** that reads 256 × `{float s; float c_lo; float c_hi; uint32 flags}` from `hnt.beg` (skipping the 2-byte hint type is already handled by the chunk parser placing `beg` at the payload — verify against `parse_hint`; if `beg` points at the hint type, offset by 2) into `std::array<BlockLine,256>`.

```cpp
std::array<BlockLine,256> make_lines(const HashsetHint& hnt) {
  std::array<BlockLine,256> lines;
  const uint8_t* p = static_cast<const uint8_t*>(hnt.beg);
  for (int i = 0; i < 256; ++i) {
    float s, clo, chi; uint32_t flags;
    std::memcpy(&s,   p +  0, 4); std::memcpy(&clo, p + 4, 4);
    std::memcpy(&chi, p +  8, 4); std::memcpy(&flags, p + 12, 4);
    lines[i] = { s, clo, chi, (flags & 1u) != 0 };
    p += 16;
  }
  return lines;
}
```

(Confirm `parse_hint` sets `hnt.beg` to the start of the per-block data, not the 2-byte type; the existing `make_blocks<8>` reads pairs directly from `hnt.beg`, so `beg` already points past the type — mirror that.)

- [ ] **Step 2: Extend the dispatch.** In `make_lookup_strategy`, before the `0x6208` branch:

```cpp
  if (hnt.hint_type == 0x6209) {
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeBlockLinearHullStrategy8>(
        hsh.hash_length, hsd.beg, hsd.end, make_lines(hnt)));
  }
```

Add the `MakeBlockLinearHullStrategy8` maker (mirroring `MakeBlockLookupStrategy8`): a `template <size_t HashLength> struct MakeBlockLinearHullStrategy8 { LookupStrategy* operator()(const void* b, const void* e, std::array<BlockLine,256> lines) { return new BlockLinearLookupStrategy<HashLength,8>(b, e, lines); } };`. Add `#include "hashset/block_linear_ls.h"` at the top.

- [ ] **Step 3: Relax `handle_hint`.** Change the `THROW_IF(hnt.hint_type != 0x6208, ...)` to accept both `0x6208` and `0x6209` (throw only on unknown types).

- [ ] **Step 4: Build the library.** Run: `make 2>&1 | tail -20` → clean build.

- [ ] **Step 5: Commit.**

```bash
git add src/lib/hashset/hset_decoder.cpp
git commit -m "feat(decoder): dispatch hint 0x6209 to block-linear hull strategy; keep 0x6208"
```

### Task 21: Round-trip tests + real NSRL end-to-end

**Files:**
- Modify: `test/test_hset_round_trip.cpp` (extend), `Makefile.am` if a new test file is added.

**Interfaces:**
- Consumes: encoder (`0x6209`), decoder dispatch, the `contains`/`contains_batch` surface.

- [ ] **Step 1: Write a failing round-trip test.** In `test/test_hset_round_trip.cpp`, add `TEST_CASE("round_trip_hull_hint_agreement")`: build an in-memory set of ~200k random L=20 hashes, encode to a temp `.hset` under `$HOME/build`, decode it, and assert the decoded strategy's `contains()` **and** `contains_batch()` agree with a `std::binary_search` oracle over a hard query stream (reuse the `truth_contains<L>`/near-miss/boundary pattern from `test_hset_batch.cpp`). Assert the decoded hint type is `0x6209`.

- [ ] **Step 2: Run it to verify it fails** (if the encoder default or decoder wiring is incomplete). Run: `make check TESTS=test/test 2>&1 | tail -20`.

- [ ] **Step 3: Make it pass** — fix any offset/parse mismatch surfaced (the most likely bug is the `hnt.beg` offset in `make_lines` vs `parse_hint`). Run: `make check TESTS=test/test 2>&1 | tail -20` → PASS.

- [ ] **Step 4: Confirm existing agreement + old-format tests still pass.** Run: `make check 2>&1 | tail -30`
Expected: `test_hset_batch`, `test_convex_hull`, `test_hull_lines`, `test_hset_encoder`, `test_probe`, and all pre-existing tests pass (backward compatibility: any checked-in `0x6208` fixtures still decode).

- [ ] **Step 5: Build a real NSRL-derived `.hset` and check it end-to-end.** Using `src/mkhashset` (or the encoder API), build a `.hset` from a slice of NSRL SHA-1 into `$HOME/build/nsrl-sha1.hset`, decode it, and spot-check `contains()` on known-present digests (row 1 of `NSRLFile.txt`) and known-absent random digests against the oracle. Document the command + result in `bench/RESULTS.md` (the end-to-end proof).

- [ ] **Step 6: Commit.**

```bash
git add test/test_hset_round_trip.cpp bench/RESULTS.md Makefile.am
git commit -m "test(format): round-trip agreement for hint 0x6209 + real NSRL end-to-end"
```

---

## Self-Review

**1. Spec coverage** (each spec section → task):
- Phase 1 harness (datasets, anti-cheat contract, four metrics, baseline columns, reproducibility) → Tasks 1 (probe metric), 3 (oracle/correctness contract), 4 (timing contract), 5 (dataset matrix + tuning/held-out split), 6 (suite + baseline columns + reproducibility seeds), 7 (perf + gprof). ✓
- Phase 2 candidate interface + C0–C6 + phmap/unordered → Tasks 2 (interface), 8 (C0/C1/phmap/unordered bar), 9 (hull-line math), 10 (C2), 11 (C3), 12 (C4), 13 (C5), 14 (C6), 15 (freeze + leaderboard). ✓
- Phase 3 subagent challenge + review gate → Task 16 (packet, template, gate, orchestration). ✓
- Phase 4 profiling loop → Task 17. ✓
- Phase 5 production wiring (new hint, encoder, decoder, round-trip, backward-compat) → Tasks 18–21. ✓
- Cross-cutting "preserve sorted layout" → `Budget.preserves_sorted` + `aux_bytes_per_hash` (Task 2), enforced/reported in every candidate and the leaderboard (Tasks 8–15), and called out in the challenge gate (Task 16). ✓
- Out-of-scope items (set-ops, new hash lengths, AVX2, multithread) are respected: no task adds them; SSE4.2-only is a Global Constraint. ✓

**2. Placeholder scan:** The driver seeds `0xTUNE1/0xHELD1/0xADVE` are explicitly flagged for replacement with concrete literals in Task 6 Step 2 (values given). The C2 wrapper's `aux_bytes_per_hash` self-correction is called out in Task 10 Step 2. The `staged_batch`/`search_window` "copy verbatim from block_ls.h lines X–Y" instructions reference exact, existing line ranges rather than leaving code unwritten. No `TBD`/`handle edge cases`/`add validation` placeholders remain.

**3. Type consistency:** `eval::Candidate` (name/build/contains/contains_batch/budget) is used identically across Tasks 2, 8, 10–16. `build` takes `const eval::SetRef&` consistently (Task 8 Step 1 changes the signature and updates all prior tests/candidates). `BlockLine {s, c_lo, c_hi, empty}` is defined once (Task 9) and consumed unchanged by Tasks 10, 13, 14, 19, 20. Hint value `0x6209` is consistent across Tasks 18–21. `make_block_hull_lines` (SetT) and `make_block_hull_lines_ri` (RecordIterator) are named distinctly to reflect their different inputs.

**Known execution-order dependency:** `bench/eval.cpp` (Task 6) will not link until the bar candidates exist (Task 8); Task 6 Step 3 notes this and registers C0/C1 stubs so the driver compiles as soon as Task 8 lands. Execute Task 8 immediately after Task 6, or fold Task 6's driver-build verification into Task 8 Step 4 (where it is already repeated).

