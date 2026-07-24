// Standalone lookup benchmark harness for libhasher.
//
// Builds a synthetic sorted hash set (uniform-random cryptographic hashes are
// a faithful model of NSRL/VirusShare since the predictor assumes uniformity),
// constructs the various lookup strategies, and measures ns/lookup across a
// range of batch sizes and hit ratios. Also validates every strategy against a
// ground-truth std::binary_search.
//
// Compile standalone (no autotools), from the repository root:
//   g++ -O3 -march=native -std=c++17 -Iinclude -Ibench \
//       bench/bench_lookup.cpp src/lib/hashset/util.cpp -o bench/bench_lookup
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "hashset/util.h" // expected_index

// ---------------------------------------------------------------------------
// Data generation
// ---------------------------------------------------------------------------

// A synthetic sorted hash set: `count` hashes of `hlen` bytes, contiguous.
struct HashSet {
  size_t hlen;
  size_t count;
  std::vector<uint8_t> data; // count*hlen bytes, sorted lexicographically

  const uint8_t* beg() const { return data.data(); }
  const uint8_t* end() const { return data.data() + data.size(); }
  const uint8_t* at(size_t i) const { return data.data() + i * hlen; }
};

inline HashSet make_sorted_set(size_t count, size_t hlen, uint64_t seed) {
  HashSet hs;
  hs.hlen = hlen;
  hs.count = count;
  hs.data.resize(count * hlen);

  // Fill with random bytes. splitmix64 -> fast, deterministic.
  uint64_t x = seed ? seed : 0x9E3779B97F4A7C15ull;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };

  uint8_t* p = hs.data.data();
  size_t total = count * hlen;
  size_t i = 0;
  for (; i + 8 <= total; i += 8) {
    uint64_t v = next();
    std::memcpy(p + i, &v, 8);
  }
  for (; i < total; ++i) {
    p[i] = static_cast<uint8_t>(next());
  }

  // Sort the hashes lexicographically (as bytes / big-endian order).
  std::vector<size_t> idx(count);
  // Sort in place using an index-free approach: sort an array of pointers,
  // then materialize. For simplicity & correctness, sort via a temp of rows.
  struct Row { const uint8_t* p; };
  std::vector<const uint8_t*> rows(count);
  for (size_t k = 0; k < count; ++k) rows[k] = hs.at(k);
  std::sort(rows.begin(), rows.end(), [hlen](const uint8_t* a, const uint8_t* b) {
    return std::memcmp(a, b, hlen) < 0;
  });
  std::vector<uint8_t> sorted(count * hlen);
  for (size_t k = 0; k < count; ++k) {
    std::memcpy(sorted.data() + k * hlen, rows[k], hlen);
  }
  hs.data.swap(sorted);
  (void)idx;
  return hs;
}

// ---------------------------------------------------------------------------
// Query generation
// ---------------------------------------------------------------------------

struct Queries {
  size_t hlen;
  size_t count;
  std::vector<uint8_t> data;
  const uint8_t* at(size_t i) const { return data.data() + i * hlen; }
};

inline Queries make_random_queries(size_t m, size_t hlen, uint64_t seed) {
  Queries q;
  q.hlen = hlen;
  q.count = m;
  q.data.resize(m * hlen);
  uint64_t x = seed;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  size_t total = m * hlen, i = 0;
  uint8_t* p = q.data.data();
  for (; i + 8 <= total; i += 8) { uint64_t v = next(); std::memcpy(p + i, &v, 8); }
  for (; i < total; ++i) p[i] = static_cast<uint8_t>(next());
  return q;
}

// Queries sampled from the set (guaranteed hits), plus optional fraction of
// random misses.
inline Queries make_mixed_queries(const HashSet& hs, size_t m, double hit_frac,
                                  uint64_t seed) {
  Queries q;
  q.hlen = hs.hlen;
  q.count = m;
  q.data.resize(m * hs.hlen);
  std::mt19937_64 re(seed);
  std::uniform_int_distribution<size_t> pick(0, hs.count - 1);
  std::uniform_real_distribution<double> coin(0.0, 1.0);
  uint64_t x = seed ^ 0xD1B54A32D192ED03ull;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  for (size_t k = 0; k < m; ++k) {
    uint8_t* dst = q.data.data() + k * hs.hlen;
    if (coin(re) < hit_frac) {
      std::memcpy(dst, hs.at(pick(re)), hs.hlen);
    } else {
      for (size_t j = 0; j + 8 <= hs.hlen; j += 8) { uint64_t v = next(); std::memcpy(dst + j, &v, 8); }
      for (size_t j = (hs.hlen / 8) * 8; j < hs.hlen; ++j) dst[j] = static_cast<uint8_t>(next());
    }
  }
  return q;
}

// ---------------------------------------------------------------------------
// Ground truth
// ---------------------------------------------------------------------------

inline bool ground_truth_contains(const HashSet& hs, const uint8_t* h) {
  size_t lo = 0, hi = hs.count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = std::memcmp(hs.at(mid), h, hs.hlen);
    if (c < 0) lo = mid + 1;
    else if (c > 0) hi = mid;
    else return true;
  }
  return false;
}

// Template overload: works with any type that has hlen/count/at() (e.g. HashSetView).
template <class SetT>
inline bool ground_truth_contains_v(const SetT& hs, const uint8_t* h) {
  size_t lo = 0, hi = hs.count;
  while (lo < hi) { size_t mid = lo + (hi - lo) / 2;
    int c = std::memcmp(hs.at(mid), h, hs.hlen);
    if (c < 0) lo = mid + 1; else if (c > 0) hi = mid; else return true; }
  return false;
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

struct BenchResult {
  double ns_per_lookup;
  uint64_t checksum;
};

// Run `fn` over the queries, repeating until at least min_ns elapsed, return
// best (lowest) ns/lookup across repetitions.
template <class Fn>
BenchResult time_lookups(size_t nqueries, Fn&& fn, int reps = 5) {
  using clk = std::chrono::steady_clock;
  double best = std::numeric_limits<double>::max();
  uint64_t checksum = 0;
  for (int r = 0; r < reps; ++r) {
    auto t0 = clk::now();
    uint64_t cs = fn();
    auto t1 = clk::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    best = std::min(best, ns / static_cast<double>(nqueries));
    checksum ^= cs;
  }
  return {best, checksum};
}

// ---------------------------------------------------------------------------
// Generic candidate suite
// ---------------------------------------------------------------------------
//
// A "Runner" fills out[i] with 0/1 for whether query i is present, and returns
// a checksum. Signature: uint64_t(const Queries& q, uint8_t* out).
//
// This lets single-lookup and batch-lookup candidates be measured and
// validated through one identical code path, so numbers are comparable.

using Runner = std::function<uint64_t(const Queries&, uint8_t*)>;

struct Candidate {
  std::string name;
  Runner run;
};

// Validate a runner against ground truth on a mixed workload.
inline bool validate_runner(const HashSet& hs, const Runner& run) {
  Queries q = make_mixed_queries(hs, 50000, 0.5, 777);
  std::vector<uint8_t> out(q.count, 0xFF);
  run(q, out.data());
  size_t mism = 0;
  for (size_t i = 0; i < q.count; ++i) {
    bool truth = ground_truth_contains(hs, q.at(i));
    if ((out[i] != 0) != truth) mism++;
  }
  if (mism) std::printf("  [VALIDATION FAIL] %zu / %zu mismatches\n", mism, q.count);
  return mism == 0;
}

struct Workload {
  size_t m;
  double hit;     // fraction of queries that are guaranteed present
  const char* tag;
};

inline std::vector<Workload> default_workloads() {
  return {
      {4096, 0.0, "4K miss"},
      {4096, 1.0, "4K hit"},
      {1000000, 0.0, "1M miss"},
      {1000000, 0.5, "1M mix"},
      {1000000, 1.0, "1M hit"},
  };
}

// Run a set of candidates across the workloads; print a comparison table
// (rows=workloads, cols=candidates), ns/lookup. Validates each candidate first.
inline void run_suite(const char* title, const HashSet& hs,
                      const std::vector<Candidate>& cands,
                      const std::vector<Workload>& wls = default_workloads(),
                      int reps = 4) {
  std::printf("=== %s (hlen=%zu, count=%zu) ===\n", title, hs.hlen, hs.count);
  for (auto& c : cands) validate_runner(hs, c.run);

  std::printf("  %-10s", "workload");
  for (auto& c : cands) std::printf("%14s", c.name.c_str());
  std::printf("   (ns/lookup)\n");

  std::vector<uint8_t> out;
  for (auto& wl : wls) {
    Queries q = (wl.hit == 0.0)
                    ? make_random_queries(wl.m, hs.hlen, 999 + wl.m)
                    : make_mixed_queries(hs, wl.m, wl.hit, 999 + wl.m);
    out.assign(q.count, 0);
    std::printf("  %-10s", wl.tag);
    for (auto& c : cands) {
      const Runner& run = c.run;
      auto r = time_lookups(q.count,
                            [&]() { return run(q, out.data()); }, reps);
      std::printf("%14.1f", r.ns_per_lookup);
    }
    std::printf("\n");
  }
  std::printf("\n");
}

