#include "hashset/tlsh_search.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <tuple>
#include <vector>

#include "hashset/hset.h"
#include "hashset/tlsh_ivf.h"

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

  // per-query header cost tables and body planes
  uint32_t l_cost[256], q_cost[256];
  for (uint32_t v = 0; v < 256; ++v) {
    l_cost[v] = include_length ? tlsh_l_cost(tlsh_mod_diff(v, q.L, 256)) : 0;
    q_cost[v] = tlsh_q_cost(tlsh_mod_diff(v >> 4, q.q1(), 16)) +
                tlsh_q_cost(tlsh_mod_diff(v & 0x0F, q.q2(), 16));
  }
  const TlshBodyQuery qb(q);

  for (const TlshDigest* d = beg; d != end; ++d) {
    const uint32_t hdist = l_cost[d->L] + q_cost[d->Q] + (d->checksum != q.checksum);
    if (hdist > bound) {
      continue;
    }

    const uint32_t dist = hdist + qb.body(*d);
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

namespace {

using HashsetTuple = decltype(Holder::hsets)::value_type;

// the hashset tuple at tidx if it is a TLSH hashset, else null
const HashsetTuple* tlsh_hashset(const SFHASH_Hashset* hset, size_t tidx) {
  if (tidx >= hset->holder.hsets.size()) {
    return nullptr;
  }
  const auto& hs = hset->holder.hsets[tidx];
  const auto& hhdr = std::get<HashsetHeader>(hs);
  if (hhdr.hash_type != SFHASH_TLSH || hhdr.hash_length != sizeof(TlshDigest)) {
    return nullptr;
  }
  return &hs;
}

uint32_t knn_strategies(const HashsetTuple& hs) {
  uint32_t s = SFHASH_TLSH_KNN_BRUTE;
  if (!std::get<TlshIvfView>(hs).empty()) {
    s |= SFHASH_TLSH_KNN_INDEX;
  }
  return s;
}

} // namespace

const float* sfhash_hashset_tlsh_vectors(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t* dims)
{
  const HashsetTuple* hs = tlsh_hashset(hset, tidx);
  const ConstTlshVectors* tv = hs ? &std::get<ConstTlshVectors>(*hs) : nullptr;
  if (dims) {
    *dims = tv && tv->data ? tv->dims : 0;
  }
  return tv ? tv->data : nullptr;
}

uint32_t sfhash_hashset_tlsh_knn_strategies(
  const SFHASH_Hashset* hset,
  size_t tidx)
{
  const HashsetTuple* hs = tlsh_hashset(hset, tidx);
  return hs ? knn_strategies(*hs) : 0;
}

size_t sfhash_hashset_tlsh_knn_with(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* digest,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  uint32_t strategy,
  SFHASH_TlshMatch* out)
{
  const HashsetTuple* hs = digest ? tlsh_hashset(hset, tidx) : nullptr;
  if (!hs) {
    return 0;
  }

  // exactly one supported strategy
  if (std::popcount(strategy) != 1 || !(strategy & knn_strategies(*hs))) {
    return 0;
  }

  const auto& hdat = std::get<ConstHashsetData>(*hs);
  const TlshDigest* rows = static_cast<const TlshDigest*>(hdat.beg);
  const TlshDigest& q = *static_cast<const TlshDigest*>(digest);

  std::vector<SFHASH_TlshMatch> matches;
  switch (strategy) {
  case SFHASH_TLSH_KNN_BRUTE:
    matches = tlsh_knn_brute(
      rows,
      static_cast<const TlshDigest*>(hdat.end),
      q,
      k,
      max_distance,
      include_length
    );
    break;

  case SFHASH_TLSH_KNN_INDEX:
    matches = tlsh_knn_ivf(
      std::get<TlshIvfView>(*hs),
      rows,
      q,
      k,
      max_distance,
      include_length
    );
    break;

  default:
    return 0;
  }

  std::copy(matches.begin(), matches.end(), out);
  return matches.size();
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
  const HashsetTuple* hs = tlsh_hashset(hset, tidx);
  if (!hs) {
    return 0;
  }

  // prefer the index when the file has one
  const uint32_t strategy = (knn_strategies(*hs) & SFHASH_TLSH_KNN_INDEX) ?
    SFHASH_TLSH_KNN_INDEX : SFHASH_TLSH_KNN_BRUTE;

  return sfhash_hashset_tlsh_knn_with(
    hset, tidx, digest, k, max_distance, include_length, strategy, out
  );
}
