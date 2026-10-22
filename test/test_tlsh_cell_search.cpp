#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <vector>

#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_cell_search.h"
#include "hashset/tlsh_search.h"

namespace {

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

TEST_CASE("tlsh_cell_knn_matches_brute_force") {
  auto rows = make_tlsh_corpus(21, 20000);
  std::sort(rows.begin(), rows.end());
  const auto cells = make_tlsh_cell_index(rows.data(), rows.data() + rows.size());

  const auto queries = perturb_tlsh_corpus(22, rows, 60, 0.03);
  for (const auto& q: queries) {
    for (size_t k: {1, 5, 20}) {
      for (uint32_t T: {10u, 30u, 100u, 144u, 400u, 100000u}) {
        for (bool incl: {true, false}) {
          const auto brute = tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, k, T, incl);
          const auto fast = tlsh_knn_cells(rows.data(), cells.data(), q, k, T, incl);
          CHECK(same_matches(brute, fast));
        }
      }
    }
  }
}

TEST_CASE("tlsh_cell_knn_edge_cases") {
  auto rows = make_tlsh_corpus(23, 500);
  std::sort(rows.begin(), rows.end());
  const auto cells = make_tlsh_cell_index(rows.data(), rows.data() + rows.size());

  CHECK(tlsh_knn_cells(rows.data(), cells.data(), rows[0], 0, 100, true).empty());
  CHECK(tlsh_knn_cells(rows.data(), cells.data(), TlshDigest{}, 5, 100, true).empty());
  CHECK(tlsh_knn_cells(rows.data(), nullptr, rows[0], 5, 100, true).empty());

  const auto r = tlsh_knn_cells(rows.data(), cells.data(), rows[77], 1, 0, true);
  REQUIRE(r.size() == 1);
  CHECK(r[0].distance == 0);
  CHECK(rows[r[0].index] == rows[77]);

  // everything within a huge radius: all rows, in (distance, index) order
  const auto all = tlsh_knn_cells(rows.data(), cells.data(), rows[5], rows.size(), 1u << 30, true);
  CHECK(all.size() == rows.size());
  CHECK(same_matches(all, tlsh_knn_brute(rows.data(), rows.data() + rows.size(), rows[5], rows.size(), 1u << 30, true)));
}
