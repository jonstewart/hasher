#include "hashset/tlsh_cell_search.h"

#include <algorithm>
#include <array>
#include <numeric>
#include <queue>

#include "hashset/tlsh_cells.h"

namespace {

struct Hit {
  uint32_t distance;
  uint64_t index;
  bool operator<(const Hit& o) const {
    return distance != o.distance ? distance < o.distance : index < o.index;
  }
};

// values 0..255 ordered by ascending cost
std::array<uint8_t, 256> order_by_cost(const std::array<uint32_t, 256>& cost) {
  std::array<uint8_t, 256> order;
  std::iota(order.begin(), order.end(), 0);
  std::stable_sort(order.begin(), order.end(), [&](uint8_t a, uint8_t b) {
    return cost[a] < cost[b];
  });
  return order;
}

} // namespace

std::vector<SFHASH_TlshMatch> tlsh_knn_cells(
  const TlshDigest* rows,
  const uint64_t* cells,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length)
{
  std::vector<SFHASH_TlshMatch> out;
  if (k == 0 || !rows || !cells || q.is_null()) {
    return out;
  }

  // header cost tables for this query
  std::array<uint32_t, 256> l_cost, q_cost;
  for (uint32_t v = 0; v < 256; ++v) {
    l_cost[v] = include_length ? tlsh_l_cost(tlsh_mod_diff(v, q.L, 256)) : 0;
    q_cost[v] = tlsh_q_cost(tlsh_mod_diff(v >> 4, q.q1(), 16)) +
                tlsh_q_cost(tlsh_mod_diff(v & 0x0F, q.q2(), 16));
  }
  const auto l_order = order_by_cost(l_cost);
  const auto q_order = order_by_cost(q_cost);

  std::priority_queue<Hit> best;
  uint32_t tau = max_distance; // inclusive bound on useful distances

  for (const uint8_t L: l_order) {
    const uint32_t cl = l_cost[L];
    if (cl > tau) {
      break;
    }
    for (const uint8_t Q: q_order) {
      const uint32_t ch = cl + q_cost[Q];
      if (ch > tau) {
        break;
      }
      const uint32_t c = (static_cast<uint32_t>(L) << 8) | Q;
      const uint64_t lb = cells[c], le = cells[c + 1];
      for (uint64_t i = lb; i < le; ++i) {
        const TlshDigest& r = rows[i];
        const uint32_t hd = ch + (r.checksum != q.checksum);
        if (hd > tau) {
          continue;
        }
        const uint32_t d = hd + tlsh_body_diff(q, r);
        if (d > tau) {
          continue;
        }
        const Hit h{ d, i };
        if (best.size() < k) {
          best.push(h);
        }
        else if (h < best.top()) {
          best.pop();
          best.push(h);
        }
        else {
          continue;
        }
        if (best.size() == k) {
          tau = best.top().distance;
        }
      }
    }
  }

  out.resize(best.size());
  for (size_t i = out.size(); i-- > 0;) {
    out[i] = { best.top().index, best.top().distance };
    best.pop();
  }
  return out;
}
