// include/hashset/global_hull_ls.h
#pragma once
#include "hashset/basic_ls.h"
#include "hashset/convex_hull.h"
#include "hashset/hash_compare.h"
#include "hashset/probe.h"
#include "hashset/util.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

// GlobalHullLookupStrategy: builds ONE upper and ONE lower convex hull over
// ALL stored (expected_index, actual_index) points, then at query time
// evaluates both hulls as piecewise-linear functions to derive a tight
// [lo, hi) window before running the branchless binary search.
//
// Correctness invariant: the global upper hull lies on/above every stored
// point and the lower hull on/below, so lo <= actual_index < hi for every
// stored hash — exact lookups on ANY distribution (uniformity only affects
// window tightness).
//
// A build-time VERIFY+WIDEN guard additionally guards against float-rounding
// artefacts: after hull construction we re-evaluate every stored point and
// nudge hull vertices outward (by 1) until every point is strictly inside its
// predicted window. The guard terminates because each nudge widens the window
// by at least 1 — a strictly improving direction.

template <size_t HashLength>
class GlobalHullLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  GlobalHullLookupStrategy(const void* beg, const void* end)
    : BasicLookupStrategy<HashLength>(beg, end) { build_hulls(); }

  virtual ~GlobalHullLookupStrategy() {}

  bool contains(const uint8_t* hash) const override {
    size_t lo, hi;
    window(hash, lo, hi);
    return search_window(hash, lo, hi);
  }

  // C3 inherits the default contains_batch (loops contains).
  // Batched pipelining is C6's job; C3's purpose is the tight GLOBAL bound.

protected:
  const uint8_t* base() const {
    return reinterpret_cast<const uint8_t*>(this->HashesBeg.get());
  }

  size_t count() const {
    return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get());
  }

  void build_hulls() {
    const size_t n = count();
    if (n == 0) return;

    // Gather (expected_index, actual_index) points for all stored hashes.
    std::vector<Point<double>> pts;
    pts.reserve(n);
    const uint8_t* b = base();
    for (size_t i = 0; i < n; ++i) {
      const size_t e = expected_index(b + i * HashLength, static_cast<uint32_t>(n));
      pts.emplace_back(static_cast<double>(e), static_cast<double>(i));
    }

    // Sort by x (required precondition for upper_ch / lower_ch).
    std::sort(pts.begin(), pts.end(), [](const Point<double>& a, const Point<double>& bpt) {
      return a.x < bpt.x || (a.x == bpt.x && a.y < bpt.y);
    });

    // Build the two half-hulls.
    // upper_ch: on/above all points  → supplies hi bound
    // lower_ch: on/below all points  → supplies lo bound
    // Both require >= 2 points; guard for degenerate sets.
    if (pts.size() >= 2) {
      Upper = upper_ch(pts);
      Lower = lower_ch(pts);
    } else {
      // Single-point degenerate: hull is just the point itself.
      Upper = pts;
      Lower = pts;
    }

    // Ensure hull vertices are sorted by x for binary search in eval_hull.
    std::sort(Upper.begin(), Upper.end(), [](const Point<double>& a, const Point<double>& bpt){ return a.x < bpt.x; });
    std::sort(Lower.begin(), Lower.end(), [](const Point<double>& a, const Point<double>& bpt){ return a.x < bpt.x; });

    // VERIFY+WIDEN guard: float interpolation can place a stored point just
    // outside [lo, hi).  Re-check every stored point using the same eval_hull
    // logic that window() uses; if any point is out-of-bounds, nudge the
    // nearer hull vertex outward by 1 and repeat.  This is the same correctness
    // principle as Task 9's hull_lines verify+widen.
    //
    // To nudge: find the hull vertex whose x is closest to the point's expected
    // index, then shift its y by ±1 in the appropriate direction.
    bool ok = false;
    while (!ok) {
      ok = true;
      for (size_t i = 0; i < n; ++i) {
        const double e = static_cast<double>(
            expected_index(b + i * HashLength, static_cast<uint32_t>(n)));
        const double actual = static_cast<double>(i);

        const double lo_val = eval_hull(Lower, e);
        const double hi_val = eval_hull(Upper, e);

        const int64_t lo = static_cast<int64_t>(std::floor(lo_val));
        const int64_t hi = static_cast<int64_t>(std::ceil(hi_val)) + 1;

        if (static_cast<int64_t>(actual) < lo) {
          // actual is below the lower hull — nudge the nearest lower hull vertex down
          nudge_nearest(Lower, e, -1.0);
          ok = false;
        }
        if (static_cast<int64_t>(actual) >= hi) {
          // actual is at or above the upper hull — nudge the nearest upper hull vertex up
          nudge_nearest(Upper, e, +1.0);
          ok = false;
        }
      }
    }
  }

  // Nudge the hull vertex whose x-coordinate is closest to query_x by delta.
  static void nudge_nearest(std::vector<Point<double>>& h, double query_x, double delta) {
    size_t best = 0;
    double best_dist = std::fabs(h[0].x - query_x);
    for (size_t i = 1; i < h.size(); ++i) {
      const double d = std::fabs(h[i].x - query_x);
      if (d < best_dist) { best_dist = d; best = i; }
    }
    h[best].y += delta;
  }

  // Evaluate a hull (as a piecewise-linear function) at x by locating the
  // bracketing segment with a binary search over hull vertices.
  // Upper hull chords lie on/above interior points; Lower hull chords on/below.
  static double eval_hull(const std::vector<Point<double>>& h, double x) {
    if (h.empty()) return 0.0;
    if (x <= h.front().x) return h.front().y;
    if (x >= h.back().x)  return h.back().y;
    size_t lo = 0, hi = h.size() - 1;
    while (hi - lo > 1) {
      size_t m = (lo + hi) / 2;
      if (h[m].x <= x) lo = m; else hi = m;
    }
    const double t = (x - h[lo].x) / (h[hi].x - h[lo].x);
    return h[lo].y + t * (h[hi].y - h[lo].y);
  }

  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const double e = static_cast<double>(expected_index(hash, static_cast<uint32_t>(n)));
    int64_t l = static_cast<int64_t>(std::floor(eval_hull(Lower, e)));
    int64_t r = static_cast<int64_t>(std::ceil(eval_hull(Upper, e))) + 1;
    if (l < 0) l = 0;
    if (r > static_cast<int64_t>(n)) r = static_cast<int64_t>(n);
    lo = static_cast<size_t>(l);
    hi = static_cast<size_t>(r > l ? r : l);
  }

  // Branchless lower_bound on the leading-8-byte primary key over [lo, hi),
  // then confirm the full hash. Copied VERBATIM from include/hashset/block_ls.h
  // per the human-approved plan mandate (no refactor into shared base).
  inline bool search_window(const uint8_t* hash, size_t lo, size_t hi) const {
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);

    size_t pos = lo;
    size_t len = hi - lo;
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

    if constexpr (HashLength <= 8) {
      return pos < hi && primary_key<HashLength>(b + pos * HashLength) == hk;
    }
    else {
      // Primary keys can collide; scan the (near-always length-1) run of equal
      // primary keys, confirming the full hash.
      for (size_t j = pos; j < hi; ++j) {
        const uint8_t* cand = b + j * HashLength;
        if (primary_key<HashLength>(cand) != hk) {
          break;
        }
        if (std::memcmp(cand + 8, hash + 8, HashLength - 8) == 0) {
          return true;
        }
      }
      return false;
    }
  }

  std::vector<Point<double>> Upper, Lower;
};
