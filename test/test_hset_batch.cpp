#include <catch2/catch_test_macros.hpp>

#include "hashset/block_ls.h"
#include "hashset/util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

// Correctness tests for the block lookup strategy's fast contains() and the
// staged, prefetched contains_batch(). Both must agree with a plain
// std::binary_search ground truth for every input, including small sets whose
// first-byte blocks are mostly empty (the sentinel-bounds path).

namespace {

// Build a sorted set of `count` random L-byte hashes.
template <size_t L>
std::vector<uint8_t> make_sorted_set(size_t count, uint64_t seed) {
  std::mt19937_64 re(seed);
  std::vector<std::array<uint8_t, L>> rows(count);
  for (auto& r : rows) {
    for (size_t i = 0; i < L; ++i) {
      r[i] = static_cast<uint8_t>(re());
    }
  }
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
    return std::memcmp(a.data(), b.data(), L) < 0;
  });
  std::vector<uint8_t> data(count * L);
  for (size_t k = 0; k < count; ++k) {
    std::memcpy(data.data() + k * L, rows[k].data(), L);
  }
  return data;
}

template <size_t L>
std::array<std::pair<int64_t, int64_t>, 256> make_bounds(const uint8_t* base,
                                                         size_t count) {
  std::array<std::pair<int64_t, int64_t>, 256> b;
  b.fill({std::numeric_limits<int64_t>::max(),
          std::numeric_limits<int64_t>::min()});
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* h = base + i * L;
    const size_t e = expected_index(h, static_cast<uint32_t>(count));
    const int64_t d = static_cast<int64_t>(i) - static_cast<int64_t>(e);
    const size_t bi = h[0];
    b[bi].first = std::min(b[bi].first, d);
    b[bi].second = std::max(b[bi].second, d);
  }
  return b;
}

template <size_t L>
bool truth_contains(const uint8_t* base, size_t count, const uint8_t* h) {
  size_t lo = 0, hi = count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = std::memcmp(base + mid * L, h, L);
    if (c < 0) lo = mid + 1;
    else if (c > 0) hi = mid;
    else return true;
  }
  return false;
}

template <size_t L>
void check_agreement(size_t count, uint64_t seed) {
  auto data = make_sorted_set<L>(count, seed);
  const uint8_t* base = data.data();
  auto bounds = make_bounds<L>(base, count);

  BlockLookupStrategy<L, 8> ls(base, base + count * L, bounds);

  // Query set: half sampled from the set (hits), half random (mostly misses).
  std::mt19937_64 re(seed ^ 0x5151);
  const size_t m = 4096;
  std::vector<uint8_t> queries(m * L);
  for (size_t k = 0; k < m; ++k) {
    uint8_t* q = queries.data() + k * L;
    if (count > 0 && (k & 1)) {
      std::uniform_int_distribution<size_t> pick(0, count - 1);
      std::memcpy(q, base + pick(re) * L, L);
    } else {
      for (size_t i = 0; i < L; ++i) q[i] = static_cast<uint8_t>(re());
    }
  }

  // Ground truth.
  std::vector<bool> truth(m);
  for (size_t k = 0; k < m; ++k) {
    truth[k] = truth_contains<L>(base, count, queries.data() + k * L);
  }

  // contains() must match ground truth.
  for (size_t k = 0; k < m; ++k) {
    REQUIRE(ls.contains(queries.data() + k * L) == truth[k]);
  }

  // contains_batch() must match ground truth (and thus contains()).
  std::vector<uint8_t> batch(m, 0xFF);
  ls.contains_batch(queries.data(), m, L,
                    reinterpret_cast<bool*>(batch.data()));
  for (size_t k = 0; k < m; ++k) {
    REQUIRE((batch[k] != 0) == truth[k]);
  }
}

} // namespace

TEST_CASE("hashset_batch_agreement_large") {
  // Large enough to populate all 256 first-byte blocks.
  check_agreement<4>(200000, 1);
  check_agreement<8>(200000, 2);
  check_agreement<16>(200000, 3);
  check_agreement<20>(200000, 4);
  check_agreement<32>(200000, 5);
}

TEST_CASE("hashset_batch_agreement_small_empty_blocks") {
  // Tiny sets leave most first-byte blocks empty (sentinel bounds path).
  for (size_t n : {size_t(0), size_t(1), size_t(2), size_t(7), size_t(31),
                   size_t(100), size_t(1000)}) {
    check_agreement<16>(n, 100 + n);
    check_agreement<20>(n, 200 + n);
  }
}

TEST_CASE("hashset_batch_tail_collisions") {
  // Stress hashes that share a leading 8-byte primary key but differ in the
  // tail, so the primary-key fast path must fall through to the tail compare.
  constexpr size_t L = 20;
  const size_t count = 4000;
  std::mt19937_64 re(9001);
  std::vector<std::array<uint8_t, L>> rows(count);
  std::array<uint8_t, 8> shared;
  for (auto& b : shared) b = static_cast<uint8_t>(re());
  for (auto& r : rows) {
    // 3/4 of rows share the same first 8 bytes to force tail comparisons.
    if (re() & 3) {
      std::memcpy(r.data(), shared.data(), 8);
    } else {
      for (size_t i = 0; i < 8; ++i) r[i] = static_cast<uint8_t>(re());
    }
    for (size_t i = 8; i < L; ++i) r[i] = static_cast<uint8_t>(re());
  }
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
    return std::memcmp(a.data(), b.data(), L) < 0;
  });
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());

  std::vector<uint8_t> data(rows.size() * L);
  for (size_t k = 0; k < rows.size(); ++k) {
    std::memcpy(data.data() + k * L, rows[k].data(), L);
  }
  const uint8_t* base = data.data();
  const size_t n = rows.size();
  auto bounds = make_bounds<L>(base, n);
  BlockLookupStrategy<L, 8> ls(base, base + n * L, bounds);

  // Every stored hash must be found; near-misses (tail flipped) must not.
  std::vector<uint8_t> qs;
  for (size_t k = 0; k < n; ++k) {
    qs.insert(qs.end(), base + k * L, base + (k + 1) * L);
    std::array<uint8_t, L> miss;
    std::memcpy(miss.data(), base + k * L, L);
    miss[L - 1] ^= 0xFF;
    qs.insert(qs.end(), miss.begin(), miss.end());
  }
  const size_t m = qs.size() / L;
  std::vector<uint8_t> batch(m, 0xFF);
  ls.contains_batch(qs.data(), m, L, reinterpret_cast<bool*>(batch.data()));
  for (size_t k = 0; k < m; ++k) {
    const uint8_t* h = qs.data() + k * L;
    REQUIRE(ls.contains(h) == truth_contains<L>(base, n, h));
    REQUIRE((batch[k] != 0) == truth_contains<L>(base, n, h));
  }
}
