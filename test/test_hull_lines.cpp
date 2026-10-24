// test/test_hull_lines.cpp
#include <catch2/catch_test_macros.hpp>
#include "hashset/block_linear_ls.h"
#include "hashset/hull_lines.h"
#include "hashset/util.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <random>
#include <vector>

namespace {
template <size_t L>
struct Set {
  size_t hlen = L, count;
  std::vector<uint8_t> d;
  const uint8_t* at(size_t i) const { return d.data() + i * L; }
  const uint8_t* beg() const { return d.data(); }
  const uint8_t* end() const { return d.data() + count * L; }
};
template <size_t L>
Set<L> make(size_t n, uint64_t seed) {
  std::mt19937_64 re(seed);
  std::vector<std::array<uint8_t,L>> rows(n);
  for (auto& r : rows) for (auto& x : r) x = (uint8_t)re();
  std::sort(rows.begin(), rows.end(), [](auto&a,auto&b){return std::memcmp(a.data(),b.data(),L)<0;});
  Set<L> s; s.count = n; s.d.resize(n*L);
  for (size_t k=0;k<n;++k) std::memcpy(s.d.data()+k*L, rows[k].data(), L);
  return s;
}
} // namespace

TEST_CASE("hull_lines_bound_every_stored_hash") {
  auto s = make<20>(200000, 1);
  auto lines = make_block_hull_lines(s);
  for (size_t i = 0; i < s.count; ++i) {
    const uint8_t* h = s.at(i);
    const size_t e = expected_index(h, (uint32_t)s.count);
    const BlockLine& bl = lines[h[0]];
    REQUIRE(!bl.empty);
    const int64_t lo = (int64_t)e + (int64_t)std::floor(bl.s * (double)e + bl.c_lo);
    const int64_t hi = (int64_t)e + (int64_t)std::ceil (bl.s * (double)e + bl.c_hi) + 1;
    REQUIRE(lo <= (int64_t)i);
    REQUIRE((int64_t)i < hi);
  }
}

TEST_CASE("hull_lines_empty_block_flagged") {
  auto s = make<20>(50, 2);              // tiny: most first-byte blocks empty
  auto lines = make_block_hull_lines(s);
  size_t empties = 0;
  for (auto& bl : lines) if (bl.empty) ++empties;
  REQUIRE(empties > 200);                // vast majority of 256 blocks empty
}

TEST_CASE("hull_lines_coarser_blocks_bound_every_stored_hash") {
  // with BlockBits < 8 a block is the hashes sharing the leading byte's top
  // BlockBits bits, the block BlockLinearLookupStrategy<L, BlockBits> reads
  auto s = make<20>(200000, 3);
  auto lines = make_block_hull_lines<3>(s);
  STATIC_REQUIRE(lines.size() == 8);
  for (size_t i = 0; i < s.count; ++i) {
    const uint8_t* h = s.at(i);
    const size_t e = expected_index(h, (uint32_t)s.count);
    const BlockLine& bl = lines[h[0] >> 5];
    REQUIRE(!bl.empty);
    const int64_t lo = (int64_t)e + (int64_t)std::floor(bl.s * (double)e + bl.c_lo);
    const int64_t hi = (int64_t)e + (int64_t)std::ceil (bl.s * (double)e + bl.c_hi) + 1;
    REQUIRE(lo <= (int64_t)i);
    REQUIRE((int64_t)i < hi);
  }

  // one block holds the whole set
  const auto one = make_block_hull_lines<0>(s);
  STATIC_REQUIRE(one.size() == 1);
  REQUIRE(!one[0].empty);

  BlockLinearLookupStrategy<20, 3> ls(s.beg(), s.end(), lines);
  for (size_t i = 0; i < s.count; ++i) {
    REQUIRE(ls.contains(s.at(i)));
  }
}
