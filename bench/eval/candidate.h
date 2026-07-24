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
