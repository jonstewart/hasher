#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "tlsh_digest.h"

/*
 * Enumeration of header cells in nondecreasing header-cost order for a query.
 *
 * TLSH header costs depend only on the circular differences k of L (mod 256)
 * and Q1, Q2 (mod 16) from the query, so the visiting order is the same for
 * every query up to a translation: L values are visited as q.L, q.L +- 1,
 * q.L +- 2, ...; Q bytes follow a static table of (k1, k2) pairs sorted by
 * tlsh_q_cost(k1) + tlsh_q_cost(k2), each expanded to the (up to four) Q
 * bytes at those circular offsets.
 */
struct TlshHeaderOrder {
  // L values and their costs, nondecreasing cost; cost is 0 when the length
  // is excluded (then every L has cost 0 and the order is just 0..255)
  std::array<uint8_t, 256> l;
  std::array<uint32_t, 256> l_cost;
  // Q bytes ((Q1 << 4) | Q2) and their costs, nondecreasing cost
  std::array<uint8_t, 256> q;
  std::array<uint32_t, 256> q_cost;

  TlshHeaderOrder(const TlshDigest& query, bool include_length);
};
