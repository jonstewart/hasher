#include "hashset/tlsh_header_order.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace {

struct QPairs {
  // (k1, k2) with k in 0..8, sorted by tlsh_q_cost(k1) + tlsh_q_cost(k2)
  std::vector<std::pair<uint8_t, uint8_t>> pairs;

  QPairs() {
    for (uint8_t k1 = 0; k1 <= 8; ++k1) {
      for (uint8_t k2 = 0; k2 <= 8; ++k2) {
        pairs.emplace_back(k1, k2);
      }
    }
    std::stable_sort(pairs.begin(), pairs.end(), [](const auto& a, const auto& b) {
      return tlsh_q_cost(a.first) + tlsh_q_cost(a.second) <
             tlsh_q_cost(b.first) + tlsh_q_cost(b.second);
    });
  }
};

const QPairs QPAIRS;

} // namespace

TlshHeaderOrder::TlshHeaderOrder(const TlshDigest& query, bool include_length) {
  if (include_length) {
    size_t n = 0;
    l[n] = query.L;
    l_cost[n++] = 0;
    for (uint32_t k = 1; k <= 128; ++k) {
      const uint32_t c = tlsh_l_cost(k);
      l[n] = static_cast<uint8_t>(query.L + k);
      l_cost[n++] = c;
      if (k != 128) {
        l[n] = static_cast<uint8_t>(query.L - k);
        l_cost[n++] = c;
      }
    }
  }
  else {
    for (uint32_t v = 0; v < 256; ++v) {
      l[v] = static_cast<uint8_t>(v);
      l_cost[v] = 0;
    }
  }

  size_t n = 0;
  const uint8_t q1 = query.q1(), q2 = query.q2();
  for (const auto& [k1, k2]: QPAIRS.pairs) {
    const uint32_t c = tlsh_q_cost(k1) + tlsh_q_cost(k2);
    const uint8_t a1 = (q1 + k1) & 0x0F, b1 = (q1 - k1) & 0x0F;
    const uint8_t a2 = (q2 + k2) & 0x0F, b2 = (q2 - k2) & 0x0F;
    q[n] = static_cast<uint8_t>((a1 << 4) | a2);
    q_cost[n++] = c;
    if (b2 != a2) {
      q[n] = static_cast<uint8_t>((a1 << 4) | b2);
      q_cost[n++] = c;
    }
    if (b1 != a1) {
      q[n] = static_cast<uint8_t>((b1 << 4) | a2);
      q_cost[n++] = c;
      if (b2 != a2) {
        q[n] = static_cast<uint8_t>((b1 << 4) | b2);
        q_cost[n++] = c;
      }
    }
  }
}
