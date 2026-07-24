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
