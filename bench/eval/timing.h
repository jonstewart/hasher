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
