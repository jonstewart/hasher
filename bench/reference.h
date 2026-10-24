// Reference strategy runners + bounds helpers shared by all experiments.
#pragma once
#include "harness.h"

#include "hashset/basic_ls.h"
#include "hashset/block_ls.h"
#include "hashset/radius_ls.h"
#include "hashset/range_ls.h"

#include <memory>

// ---- bounds computation (mirrors test/bench_hashset.cpp) ------------------

template <size_t L>
std::pair<int64_t, int64_t> compute_left_right(const HashSet& hs) {
  int64_t left = std::numeric_limits<int64_t>::max();
  int64_t right = std::numeric_limits<int64_t>::min();
  for (size_t i = 0; i < hs.count; ++i) {
    const size_t e = expected_index(hs.at(i), hs.count);
    const int64_t d = static_cast<int64_t>(i) - static_cast<int64_t>(e);
    left = std::min(left, d);
    right = std::max(right, d);
  }
  return {left, right};
}

template <size_t L, size_t BucketBits>
std::array<std::pair<int64_t, int64_t>, (1 << BucketBits)>
compute_block_bounds(const HashSet& hs) {
  std::array<std::pair<int64_t, int64_t>, (1 << BucketBits)> b;
  std::fill(b.begin(), b.end(),
            std::make_pair(std::numeric_limits<int64_t>::max(),
                           std::numeric_limits<int64_t>::min()));
  for (size_t i = 0; i < hs.count; ++i) {
    const size_t e = expected_index(hs.at(i), hs.count);
    const int64_t d = static_cast<int64_t>(i) - static_cast<int64_t>(e);
    const size_t bi = hs.at(i)[0] >> (8 - BucketBits);
    b[bi].first = std::min(b[bi].first, d);
    b[bi].second = std::max(b[bi].second, d);
  }
  return b;
}

// ---- reference runners -----------------------------------------------------

// Wrap a LookupStrategy (owned) into a Runner. The unique_ptr is captured by
// shared_ptr so the std::function is copyable.
template <size_t L>
Runner make_ls_runner(std::shared_ptr<LookupStrategy> ls) {
  return [ls](const Queries& q, uint8_t* out) -> uint64_t {
    uint64_t cs = 0;
    for (size_t i = 0; i < q.count; ++i) {
      bool r = ls->contains(q.at(i));
      out[i] = r ? 1 : 0;
      cs += r;
    }
    return cs;
  };
}

// The real, currently-shipping strategy: BlockLookupStrategy<L,8> ("block256").
template <size_t L>
Candidate make_block256_reference(const HashSet& hs) {
  auto b8 = compute_block_bounds<L, 8>(hs);
  std::shared_ptr<LookupStrategy> ls =
      std::make_shared<BlockLookupStrategy<L, 8>>(hs.beg(), hs.end(), b8);
  return {"block256(ref)", make_ls_runner<L>(ls)};
}

template <size_t L>
Candidate make_basic_reference(const HashSet& hs) {
  std::shared_ptr<LookupStrategy> ls =
      std::make_shared<BasicLookupStrategy<L>>(hs.beg(), hs.end());
  return {"basic", make_ls_runner<L>(ls)};
}
