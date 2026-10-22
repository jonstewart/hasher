#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <random>
#include <set>
#include <vector>

#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hashset/tlsh_ivf.h"
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
  REQUIRE(ivf.centroids.size() == ivf.lists() * TLSH_EMBED_DIMS);
  CHECK(ivf.list_start.front() == 0);
  CHECK(ivf.list_start.back() == rows.size());
  CHECK(ivf.ids.size() == rows.size());

  // every row appears exactly once
  std::vector<uint32_t> sorted_ids(ivf.ids);
  std::sort(sorted_ids.begin(), sorted_ids.end());
  for (size_t i = 0; i < sorted_ids.size(); ++i) {
    REQUIRE(sorted_ids[i] == i);
  }

  for (size_t c = 0; c < ivf.lists(); ++c) {
    const auto lb = ivf.list_start[c], le = ivf.list_start[c + 1];
    REQUIRE(lb < le); // no empty lists
    const float* cent = &ivf.centroids[c * TLSH_EMBED_DIMS];
    const float L = cent[TLSH_EMBED_L_DIM];
    for (auto i = lb; i < le; ++i) {
      if (i > lb) {
        CHECK(ivf.ids[i - 1] < ivf.ids[i]); // ascending within a list
      }
      const auto& d = rows[ivf.ids[i]];
      CHECK(static_cast<float>(d.L) == L); // lists never span L
      const float dist = std::sqrt(tlsh_embed_dist2_to_point(d, cent));
      CHECK(dist <= ivf.radius[c]);
    }
  }
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
  CHECK(v.dims == TLSH_EMBED_DIMS);
  CHECK(v.lists == ivf.lists());
  CHECK(v.n == ivf.n);
  CHECK(std::equal(ivf.centroids.begin(), ivf.centroids.end(), v.centroids));
  CHECK(std::equal(ivf.radius.begin(), ivf.radius.end(), v.radius));
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
      for (uint32_t T: {10u, 30u, 60u, 100u, 144u}) {
        for (bool incl: {true, false}) {
          const auto brute = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, k, T, incl);
          const auto fast = tlsh_knn_ivf(view, rows.data(), q, k, T, incl);
          CHECK(same_matches(brute, fast));
        }
      }
    }
  }
}

TEST_CASE("tlsh_ivf_knn_clamps_max_distance_with_length") {
  const auto rows = sorted_corpus(4, 3000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64);
  const auto view = make_tlsh_ivf_view(ivf);

  const auto q = perturb_tlsh_corpus(6, rows, 1, 0.2).front();
  const auto fast = tlsh_knn_ivf(view, rows.data(), q, 1000, 100000, true);
  for (const auto& m: fast) {
    CHECK(m.distance <= TLSH_EMBED_MAX_BOUNDED_DIFF);
  }
  const auto brute = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, 1000, TLSH_EMBED_MAX_BOUNDED_DIFF, true);
  CHECK(same_matches(brute, fast));

  // without the length there is no cap
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
