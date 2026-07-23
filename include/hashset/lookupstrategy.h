#pragma once

#include <cstddef>
#include <cstdint>

struct SFHASH_Hashset;

class LookupStrategy {
public:
  virtual ~LookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const = 0;

  // Look up a batch of `n` hashes, each `stride` bytes apart, writing the
  // results to `results[0..n)`. The default loops over contains(); strategies
  // that can hide memory latency across independent lookups (see
  // BlockLookupStrategy) override this. Answers are identical to calling
  // contains() on each hash.
  virtual void contains_batch(
    const uint8_t* hashes,
    size_t n,
    size_t stride,
    bool* results
  ) const {
    for (size_t i = 0; i < n; ++i) {
      results[i] = contains(hashes + i * stride);
    }
  }
};
