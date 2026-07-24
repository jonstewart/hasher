#pragma once

#include "hashset/convex_hull.h"
#include "hashset/util.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>

// Per-block linear bound lines derived from the convex hull of (expected_index,
// deviation) points.
//
// For block b, a stored hash at actual index i with expected index e satisfies:
//   lo_index(e) = e + floor(s*e + c_lo)  <= i  <  hi_index(e) = e + ceil(s*e + c_hi) + 1
//
// Correctness invariant: every stored hash in the block lies inside its window,
// so lookups stay exact on ANY distribution — uniformity only affects window
// tightness.  A query equal to a stored hash shares its e and block, so its
// window contains it.  Misses need no window guarantee (absent => false
// regardless).
//
// The VERIFY+WIDEN loop (below) enforces this invariant despite float rounding:
// after choosing float s from the min-width-slab optimisation, we set
// c_lo = floor(blo), c_hi = ceil(bhi) and then re-check every point with the
// stored floats, widening c_lo -= 1 / c_hi += 1 until no point violates the
// bounds.  The loop terminates because each iteration widens the slab by at
// least 1 (a strictly improving direction).
struct BlockLine {
  float s    = 0.0f;
  float c_lo = 0.0f;
  float c_hi = 0.0f;
  bool  empty = true;
};

namespace hull_detail {

// For a fixed slope s, find the tightest slab of that slope enclosing all
// points: c_lo = min(d - s*e), c_hi = max(d - s*e).  Returns width.
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

// Collect edge slopes from a convex-hull polygon (upper or lower).
inline void collect_slopes(const std::vector<Point<double>>& hull,
                           std::vector<double>& out) {
  for (size_t i = 1; i < hull.size(); ++i) {
    const double dx = hull[i].x - hull[i - 1].x;
    if (std::fabs(dx) > 1e-9)
      out.push_back((hull[i].y - hull[i - 1].y) / dx);
  }
}

} // namespace hull_detail

// Compute per-block supporting-line slab parameters for every leading-byte
// block.  For each block with at least one stored hash, gathers points
// (e_i, d_i) where e_i = expected_index and d_i = i - e_i, builds convex
// hulls to enumerate candidate slopes, picks the min-width slab, stores it as
// float, then verifies and widens until every stored hash is bounded.
template <class SetT>
std::array<BlockLine, 256> make_block_hull_lines(const SetT& hs) {
  std::array<BlockLine, 256> lines;
  std::array<std::vector<Point<double>>, 256> pts;

  // Gather (expected_index, deviation) points for each block.
  for (size_t i = 0; i < hs.count; ++i) {
    const uint8_t* h = hs.at(i);
    const size_t   e = expected_index(h, static_cast<uint32_t>(hs.count));
    const double   d = static_cast<double>((int64_t)i - (int64_t)e);
    pts[h[0]].emplace_back(static_cast<double>(e), d);
  }

  for (int b = 0; b < 256; ++b) {
    auto&     P  = pts[b];
    BlockLine& bl = lines[b];

    if (P.empty()) {
      bl.empty = true;
      continue;
    }
    bl.empty = false;

    // Sort by x (expected index) — required precondition for upper_ch/lower_ch.
    std::sort(P.begin(), P.end(), [](const Point<double>& a,
                                     const Point<double>& c) {
      return a.x < c.x || (a.x == c.x && a.y < c.y);
    });

    // Candidate slopes: edge slopes of upper and lower convex hulls, plus 0
    // (flat baseline — safe fallback for single-point or two-point blocks).
    // Guard behind P.size() >= 3 because half_hull unconditionally pops two
    // points and is UB with fewer inputs.
    std::vector<double> slopes{0.0};
    if (P.size() >= 3) {
      hull_detail::collect_slopes(upper_ch(P), slopes);
      hull_detail::collect_slopes(lower_ch(P), slopes);
    }

    // Find the slope that minimises slab width.
    double best_w = std::numeric_limits<double>::max();
    double bs = 0.0, blo = 0.0, bhi = 0.0;
    for (double s : slopes) {
      double clo, chi;
      const double w = hull_detail::slab_for_slope(P, s, clo, chi);
      if (w < best_w) {
        best_w = w;
        bs  = s;
        blo = clo;
        bhi = chi;
      }
    }

    // Store as float, floor/ceil to integer boundaries.
    bl.s    = static_cast<float>(bs);
    bl.c_lo = static_cast<float>(std::floor(blo));
    bl.c_hi = static_cast<float>(std::ceil(bhi));

    // VERIFY+WIDEN: re-evaluate with stored floats against every point in the
    // block.  Float rounding can push a boundary inward; widening by 1 restores
    // it.  The loop terminates because each iteration increases the slab by >=1.
    bool ok = false;
    while (!ok) {
      ok = true;
      for (const auto& p : P) {
        const int64_t e  = static_cast<int64_t>(p.x);
        const int64_t i  = static_cast<int64_t>(p.x + p.y); // actual = e + d
        const int64_t lo = e + static_cast<int64_t>(std::floor(
                               static_cast<double>(bl.s) * static_cast<double>(e) +
                               static_cast<double>(bl.c_lo)));
        const int64_t hi = e + static_cast<int64_t>(std::ceil(
                               static_cast<double>(bl.s) * static_cast<double>(e) +
                               static_cast<double>(bl.c_hi))) + 1;
        if (i < lo) { bl.c_lo -= 1.0f; ok = false; }
        if (i >= hi) { bl.c_hi += 1.0f; ok = false; }
      }
    }
  }
  return lines;
}
