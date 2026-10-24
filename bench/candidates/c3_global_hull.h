// bench/candidates/c3_global_hull.h
#pragma once
#include "eval/candidate.h"
#include "hashset/global_hull_ls.h"
#include <chrono>
#include <memory>

// C3GlobalHull: global-hull-bounded lookup candidate.
//
// Builds ONE upper and ONE lower convex hull over all (expected_index,
// actual_index) points in the set, then evaluates both hulls at query time to
// derive a tight [lo, hi) window before running a branchless binary search.
//
// contains_batch delegates to the inherited default (loops contains).
// Batched pipelining is C6's job; C3's distinguishing contribution is the
// tight GLOBAL bound — a single pair of hulls over the whole set.

template <size_t L>
struct C3GlobalHull : eval::Candidate {
  std::unique_ptr<GlobalHullLookupStrategy<L>> ls;
  double build_ns = 0;
  size_t nhash = 0;

  std::string name() const override { return "c3-global-hull"; }

  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    nhash = hs.count;
    ls = std::make_unique<GlobalHullLookupStrategy<L>>(hs.beg(), hs.end());
    build_ns = std::chrono::duration<double, std::nano>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
  }

  bool contains(const uint8_t* h) const override { return ls->contains(h); }

  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    ls->contains_batch(q, n, s, o);
  }

  eval::Budget budget() const override {
    // Hull vertices are O(hull_size) << set size; aux bytes are negligible.
    return { build_ns, 0.0, true };
  }
};
