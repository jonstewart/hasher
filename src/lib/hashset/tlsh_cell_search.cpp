#include "hashset/tlsh_cell_search.h"

#include <algorithm>
#include <queue>

#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_header_order.h"

namespace {

struct Hit {
  uint32_t distance;
  uint64_t index;
  bool operator<(const Hit& o) const {
    return distance != o.distance ? distance < o.distance : index < o.index;
  }
};

} // namespace

std::vector<SFHASH_TlshMatch> tlsh_knn_cells(
  const TlshDigest* rows,
  const uint64_t* cells,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  TlshKnnStats* stats)
{
  std::vector<SFHASH_TlshMatch> out;
  if (k == 0 || !rows || !cells || q.is_null()) {
    return out;
  }

  const TlshHeaderOrder order(q, include_length);

  std::priority_queue<Hit> best;
  uint32_t tau = max_distance; // inclusive bound on useful distances

  for (size_t li = 0; li < 256; ++li) {
    const uint32_t cl = order.l_cost[li];
    if (cl > tau) {
      break;
    }
    for (size_t qi = 0; qi < 256; ++qi) {
      const uint32_t ch = cl + order.q_cost[qi];
      if (ch > tau) {
        break;
      }
      const uint32_t c = (static_cast<uint32_t>(order.l[li]) << 8) | order.q[qi];
      const uint64_t lb = cells[c], le = cells[c + 1];
      if (lb == le) {
        continue;
      }
      if (stats) {
        ++stats->cells;
        stats->rows += le - lb;
      }
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
