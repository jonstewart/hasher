#include "hashset/tlsh_search.h"

#include <algorithm>
#include <cstring>
#include <tuple>

#include "hashset/hset.h"

namespace {

bool nearer(const SFHASH_TlshMatch& a, const SFHASH_TlshMatch& b) {
  return std::tie(a.distance, a.index) < std::tie(b.distance, b.index);
}

} // namespace

std::vector<SFHASH_TlshMatch> tlsh_knn_brute(
  const TlshDigest* beg,
  const TlshDigest* end,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length)
{
  std::vector<SFHASH_TlshMatch> heap;

  if (k == 0 || beg == end || q.is_null()) {
    return heap;
  }

  heap.reserve(std::min<size_t>(k, end - beg) + 1);

  // max-heap on (distance, index), so the worst retained match is on top;
  // once full, the top's distance bounds what is worth keeping
  const auto worse = [](const SFHASH_TlshMatch& a, const SFHASH_TlshMatch& b) {
    return nearer(a, b);
  };

  uint32_t bound = max_distance;

  for (const TlshDigest* d = beg; d != end; ++d) {
    const uint32_t hdist = tlsh_header_diff(q, *d, include_length);
    if (hdist > bound) {
      continue;
    }

    const uint32_t dist = hdist + tlsh_body_diff(q, *d);
    if (dist > bound) {
      continue;
    }

    const SFHASH_TlshMatch m{ static_cast<uint64_t>(d - beg), dist };

    if (heap.size() < k) {
      heap.push_back(m);
      std::push_heap(heap.begin(), heap.end(), worse);
    }
    else if (nearer(m, heap.front())) {
      // scanning in index order, so equal distance never displaces the top
      std::pop_heap(heap.begin(), heap.end(), worse);
      heap.back() = m;
      std::push_heap(heap.begin(), heap.end(), worse);
    }
    else {
      continue;
    }

    if (heap.size() == k) {
      bound = std::min(bound, heap.front().distance);
    }
  }

  std::sort_heap(heap.begin(), heap.end(), worse);
  return heap;
}

//
// C API
//

const void* sfhash_hashset_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t idx)
{
  const auto& hs = hset->holder.hsets[tidx];
  const auto& hhdr = std::get<HashsetHeader>(hs);
  const auto& hdat = std::get<ConstHashsetData>(hs);
  return static_cast<const uint8_t*>(hdat.beg) + idx * hhdr.hash_length;
}

size_t sfhash_hashset_tlsh_knn(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* digest,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  SFHASH_TlshMatch* out)
{
  if (!digest || tidx >= hset->holder.hsets.size()) {
    return 0;
  }

  const auto& hs = hset->holder.hsets[tidx];
  const auto& hhdr = std::get<HashsetHeader>(hs);
  if (hhdr.hash_type != SFHASH_TLSH || hhdr.hash_length != sizeof(TlshDigest)) {
    return 0;
  }

  const auto& hdat = std::get<ConstHashsetData>(hs);

  const auto matches = tlsh_knn_brute(
    static_cast<const TlshDigest*>(hdat.beg),
    static_cast<const TlshDigest*>(hdat.end),
    *static_cast<const TlshDigest*>(digest),
    k,
    max_distance,
    include_length
  );

  std::copy(matches.begin(), matches.end(), out);
  return matches.size();
}
