#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <random>
#include <set>
#include <vector>

#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_search.h"

namespace {

std::vector<TlshDigest> sorted_corpus(uint64_t seed, size_t n) {
  auto c = make_tlsh_corpus(seed, n);
  std::sort(c.begin(), c.end());
  return c;
}

bool same_matches(const std::vector<SFHASH_TlshMatch>& a, const std::vector<SFHASH_TlshMatch>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i].index != b[i].index || a[i].distance != b[i].distance) {
      return false;
    }
  }
  return true;
}

} // namespace

TEST_CASE("tlsh_ivf_build_invariants") {
  const auto rows = sorted_corpus(1, 5000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64);

  REQUIRE(ivf.n == rows.size());
  REQUIRE(ivf.lists() > 1);
  REQUIRE(ivf.list_start.size() == ivf.lists() + 1);
  REQUIRE(ivf.medoids.size() == ivf.lists());
  REQUIRE(ivf.radius2.size() == ivf.lists());
  REQUIRE(ivf.cell_lists.size() == TLSH_CELL_COUNT + 1);
  CHECK(ivf.list_start.front() == 0);
  CHECK(ivf.list_start.back() == rows.size());
  CHECK(ivf.ids.size() == rows.size());
  CHECK(ivf.cell_lists.front() == 0);
  CHECK(ivf.cell_lists.back() == ivf.lists());

  // the lists of a cell hold exactly that cell's rows
  const auto cells = make_tlsh_cell_index(rows.data(), rows.data() + rows.size());
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    CHECK(ivf.cell_lists[c] <= ivf.cell_lists[c + 1]);
    const uint64_t rows_in_cell = cells[c + 1] - cells[c];
    uint64_t rows_in_lists = 0;
    for (uint32_t l = ivf.cell_lists[c]; l < ivf.cell_lists[c + 1]; ++l) {
      rows_in_lists += ivf.list_start[l + 1] - ivf.list_start[l];
      for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
        CHECK(tlsh_cell_id(rows[ivf.ids[i]]) == c);
      }
    }
    CHECK(rows_in_lists == rows_in_cell);
  }

  // every row appears exactly once
  std::vector<uint32_t> sorted_ids(ivf.ids);
  std::sort(sorted_ids.begin(), sorted_ids.end());
  for (size_t i = 0; i < sorted_ids.size(); ++i) {
    REQUIRE(sorted_ids[i] == i);
  }

  for (size_t c = 0; c < ivf.lists(); ++c) {
    const auto lb = ivf.list_start[c], le = ivf.list_start[c + 1];
    REQUIRE(lb < le); // no empty lists
    const TlshDigest& med = ivf.medoids[c];
    bool medoid_is_member = false;
    for (auto i = lb; i < le; ++i) {
      if (i > lb) {
        CHECK(ivf.ids[i - 1] < ivf.ids[i]); // ascending within a list
      }
      CHECK(tlsh_embed_body_dist2(med, rows[ivf.ids[i]]) <= ivf.radius2[c]);
      medoid_is_member |= rows[ivf.ids[i]] == med;
    }
    // build_tlsh_ivf picks a member as the medoid; the format does not
    // require it (an index carried through merge_tlsh_ivf may have dropped
    // its medoid row), so this holds for fresh indexes only
    CHECK(medoid_is_member);
  }
}

TEST_CASE("tlsh_ivf_build_is_deterministic_across_threads") {
  const auto rows = sorted_corpus(9, 6000);
  const auto a = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 1);
  const auto b = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 4);
  const auto c = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 0);
  CHECK(a.cell_lists == b.cell_lists);
  CHECK(a.medoids == b.medoids);
  CHECK(a.radius2 == b.radius2);
  CHECK(a.list_start == b.list_start);
  CHECK(a.ids == b.ids);
  CHECK(a.ids == c.ids);
  CHECK(a.medoids == c.medoids);
}

TEST_CASE("tlsh_ivf_serialization_round_trip") {
  const auto rows = sorted_corpus(2, 2000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32);

  std::vector<char> buf(length_tivf_data(ivf.lists(), ivf.n));
  REQUIRE(write_tivf_data(ivf, buf.data()) == buf.size());

  const auto v = parse_tivf_data(
    reinterpret_cast<const uint8_t*>(buf.data()),
    reinterpret_cast<const uint8_t*>(buf.data() + buf.size())
  );
  CHECK(v.lists == ivf.lists());
  CHECK(v.n == ivf.n);
  CHECK(std::equal(ivf.cell_lists.begin(), ivf.cell_lists.end(), v.cell_lists));
  CHECK(std::equal(ivf.medoids.begin(), ivf.medoids.end(), v.medoids));
  CHECK(std::equal(ivf.radius2.begin(), ivf.radius2.end(), v.radius2));
  CHECK(std::equal(ivf.list_start.begin(), ivf.list_start.end(), v.list_start));
  CHECK(std::equal(ivf.ids.begin(), ivf.ids.end(), v.ids));

  // truncated payload is rejected
  CHECK_THROWS(parse_tivf_data(
    reinterpret_cast<const uint8_t*>(buf.data()),
    reinterpret_cast<const uint8_t*>(buf.data() + buf.size() - 1)
  ));
}

TEST_CASE("tlsh_ivf_knn_matches_brute_force") {
  const auto rows = sorted_corpus(3, 20000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 128);
  const auto view = make_tlsh_ivf_view(ivf);

  std::mt19937 rng(11);
  const auto queries = perturb_tlsh_corpus(5, rows, 60, 0.03);

  for (const auto& q: queries) {
    for (size_t k: {1, 5, 20}) {
      for (uint32_t T: {10u, 30u, 60u, 100u, 144u, 400u}) {
        for (bool incl: {true, false}) {
          const auto brute = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, k, T, incl);
          const auto fast = tlsh_knn_ivf(view, rows.data(), q, k, T, incl);
          CHECK(same_matches(brute, fast));
        }
      }
    }
  }
}

TEST_CASE("tlsh_ivf_knn_is_exact_beyond_144") {
  const auto rows = sorted_corpus(4, 3000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64);
  const auto view = make_tlsh_ivf_view(ivf);

  const auto q = perturb_tlsh_corpus(6, rows, 1, 0.2).front();
  const auto fast = tlsh_knn_ivf(view, rows.data(), q, 1000, 100000, true);
  const auto brute = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, 1000, 100000, true);
  CHECK(fast.size() == 1000);
  CHECK(same_matches(brute, fast));

  const auto fast_x = tlsh_knn_ivf(view, rows.data(), q, 1000, 100000, false);
  const auto brute_x = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, 1000, 100000, false);
  CHECK(same_matches(brute_x, fast_x));
}

TEST_CASE("tlsh_ivf_knn_edge_cases") {
  const auto rows = sorted_corpus(8, 500);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64);
  const auto view = make_tlsh_ivf_view(ivf);

  CHECK(tlsh_knn_ivf(view, rows.data(), rows[0], 0, 100, true).empty());
  CHECK(tlsh_knn_ivf(view, rows.data(), TlshDigest{}, 5, 100, true).empty());

  // exact member is found at distance 0
  const auto r = tlsh_knn_ivf(view, rows.data(), rows[123], 1, 0, true);
  REQUIRE(r.size() == 1);
  CHECK(r[0].distance == 0);
  CHECK(rows[r[0].index] == rows[123]);
}

namespace {

// n distinct rows of one header cell, sorted
std::vector<TlshDigest> one_cell_corpus(uint64_t seed, size_t n) {
  auto c = make_tlsh_corpus(seed, n);
  for (auto& d: c) {
    d.L = 0x40;
    d.Q = 0x21;
  }
  std::sort(c.begin(), c.end());
  c.erase(std::unique(c.begin(), c.end()), c.end());
  return c;
}

TlshIvf build_bisect(const std::vector<TlshDigest>& rows, size_t T, uint64_t seed = 7, unsigned threads = 0) {
  return build_tlsh_ivf(rows.data(), rows.data() + rows.size(), T, seed, threads, TlshIvfBuild::BISECT);
}

// max squared body distance from rows[c] over the members of list l
uint32_t max_dist2_about(const TlshIvf& ivf, const std::vector<TlshDigest>& rows, size_t l, const TlshDigest& c) {
  uint32_t r = 0;
  for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
    r = std::max(r, tlsh_embed_body_dist2(c, rows[ivf.ids[i]]));
  }
  return r;
}

// every list's medoid is a member, radius2 is the attained max distance
// from it, and no member has a smaller max distance (a 1-center)
void check_one_centers(const TlshIvf& ivf, const std::vector<TlshDigest>& rows) {
  for (size_t l = 0; l < ivf.lists(); ++l) {
    bool member = false;
    uint32_t best = UINT32_MAX;
    for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
      const TlshDigest& r = rows[ivf.ids[i]];
      member |= r == ivf.medoids[l];
      best = std::min(best, max_dist2_about(ivf, rows, l, r));
    }
    CHECK(member);
    CHECK(ivf.radius2[l] == max_dist2_about(ivf, rows, l, ivf.medoids[l]));
    CHECK(ivf.radius2[l] == best);
  }
}

} // namespace

TEST_CASE("tlsh_ivf_bisect_leaf_bound") {
  CHECK(tlsh_ivf_bisect_leaf_max(32) == 42);
  CHECK(tlsh_ivf_bisect_leaf_max(3) == 4);
  CHECK(tlsh_ivf_bisect_leaf_max(1) == 1);
}

TEST_CASE("tlsh_ivf_bisect_lists_are_bounded_one_centers") {
  const auto rows = one_cell_corpus(21, 2000);
  const auto ivf = build_bisect(rows, 32);
  REQUIRE(ivf.ids.size() == rows.size());
  for (size_t l = 0; l < ivf.lists(); ++l) {
    CHECK(ivf.list_start[l + 1] - ivf.list_start[l] <= 42);
  }
  check_one_centers(ivf, rows);
}
