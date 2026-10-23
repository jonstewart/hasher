#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

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
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(1, 5000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64, 0x7175657279, 0, method);

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
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(9, 6000);
  const auto a = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 1, method);
  const auto b = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 4, method);
  const auto c = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 0, method);
  CHECK(a.cell_lists == b.cell_lists);
  CHECK(a.medoids == b.medoids);
  CHECK(a.radius2 == b.radius2);
  CHECK(a.list_start == b.list_start);
  CHECK(a.ids == b.ids);
  CHECK(a.ids == c.ids);
  CHECK(a.medoids == c.medoids);
  CHECK(a.radius2 == c.radius2);
  CHECK(a.list_start == c.list_start);

  // the same build again
  const auto d = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 1, 1, method);
  CHECK(a.medoids == d.medoids);
  CHECK(a.radius2 == d.radius2);
  CHECK(a.list_start == d.list_start);
  CHECK(a.ids == d.ids);
}

TEST_CASE("tlsh_ivf_serialization_round_trip") {
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(2, 2000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 32, 0x7175657279, 0, method);

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
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(3, 20000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 128, 0x7175657279, 0, method);
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
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(4, 3000);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64, 0x7175657279, 0, method);
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
  const auto method = GENERATE(TlshIvfBuild::KMEANS, TlshIvfBuild::BISECT);
  const auto rows = sorted_corpus(8, 500);
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 64, 0x7175657279, 0, method);
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

/*
 * List counts of a BISECT build with coalescing threshold T, F =
 * TLSH_IVF_BISECT_FLAT_MAX, per cell of m rows:
 *
 * - The cell is split into flat nodes of s_i <= F rows, each clustered into
 *   at most ceil(s_i / T) lists, and coalescing only removes lists, so a
 *   cell has at most sum_i ceil(s_i / T) lists. A cell of m <= F rows is one
 *   flat node: at most ceil(m / T) lists.
 * - A larger cell is split only while a node has more than F rows, and a
 *   split leaves at least 1/8 of the node on each side (else it is a median
 *   split, half on each side), so every flat node has more than F / 8 rows
 *   and there are fewer than 8m / F of them. Since ceil(s / T) <=
 *   (s + T - 1) / T, lists * T <= m + (8m / F) (T - 1).
 * - Coalescing leaves at most one list below T / 2, so (lists - 1) (T / 2)
 *   <= m: at most 2m / T + 1 lists.
 */
void check_bisect_shape(const TlshIvf& ivf, size_t T) {
  const uint64_t F = TLSH_IVF_BISECT_FLAT_MAX;
  const size_t half = T / 2;
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    const uint32_t fl = ivf.cell_lists[c], el = ivf.cell_lists[c + 1];
    if (fl == el) {
      continue;
    }
    const uint64_t m = ivf.list_start[el] - ivf.list_start[fl];
    const uint64_t lists = el - fl;
    if (m <= F) {
      CHECK(lists <= (m + T - 1) / T);
    }
    else {
      CHECK(lists * T * F <= m * F + 8 * m * (T - 1));
    }
    CHECK((lists - 1) * half <= m);
  }
}

} // namespace

TEST_CASE("tlsh_ivf_bisect_lists_are_one_centers") {
  const auto rows = one_cell_corpus(21, 2000);
  const auto ivf = build_bisect(rows, 32);
  REQUIRE(ivf.ids.size() == rows.size());
  check_bisect_shape(ivf, 32);
  check_one_centers(ivf, rows);
}

namespace {

/*
 * nf families of `per` rows in one cell: random leading 4 body bytes of
 * both planes (32 noise buckets), and three 4-byte blocks of the trailing
 * 12 bytes of which family f has block f all 1 (codes 3) and the others all
 * 0 (codes 0). Two families then differ in 2 x 32 buckets by codes 0 vs 3,
 * a squared distance of 2 x 32 x 5 = 320 on top of the noise, while two
 * members of one family differ in the 32 noise buckets only, at most
 * 32 x 5 = 160. Sorted order interleaves the families.
 */
std::vector<TlshDigest> family_cell_corpus(size_t nf, size_t per) {
  std::mt19937_64 rng(5);
  std::vector<TlshDigest> rows;
  for (size_t f = 0; f < nf; ++f) {
    for (size_t i = 0; i < per; ++i) {
      TlshDigest d{};
      d.L = 3;
      d.Q = 0x45;
      for (int b = 0; b < 4; ++b) {
        d.hi[b] = static_cast<uint8_t>(rng());
        d.lo[b] = static_cast<uint8_t>(rng());
      }
      for (int b = 4; b < 16; ++b) {
        d.hi[b] = d.lo[b] = (b - 4) / 4 == static_cast<int>(f) ? 0xFF : 0x00;
      }
      rows.push_back(d);
    }
  }
  std::sort(rows.begin(), rows.end());
  return rows;
}

// the family of a family_cell_corpus row
size_t family_of(const TlshDigest& d) {
  for (size_t f = 0; f < 3; ++f) {
    if (d.hi[4 + 4 * f]) {
      return f;
    }
  }
  return 0;
}

} // namespace

TEST_CASE("tlsh_ivf_bisect_separates_families") {
  // nf families of 30 rows in one flat node, T = 32: k = nf lists, and each
  // comes out as one pure list
  for (const size_t nf: { 2u, 3u }) {
    const auto rows = family_cell_corpus(nf, 30);
    const auto ivf = build_bisect(rows, 32);
    REQUIRE(ivf.lists() == nf);
    std::set<size_t> seen;
    for (size_t l = 0; l < nf; ++l) {
      CHECK(ivf.list_start[l + 1] - ivf.list_start[l] == 30);
      const size_t f = family_of(rows[ivf.ids[ivf.list_start[l]]]);
      seen.insert(f);
      for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
        CHECK(family_of(rows[ivf.ids[i]]) == f);
      }
    }
    CHECK(seen.size() == nf);
  }
}

namespace {

// n rows of one cell sharing one body, differing in the checksum only
std::vector<TlshDigest> same_body_corpus(size_t n) {
  TlshDigest d = one_cell_corpus(31, 1).front();
  std::vector<TlshDigest> rows;
  for (size_t i = 0; i < n; ++i) {
    d.checksum = static_cast<uint8_t>(i);
    rows.push_back(d);
  }
  std::sort(rows.begin(), rows.end());
  return rows;
}

} // namespace

TEST_CASE("tlsh_ivf_bisect_identical_bodies") {
  // one distinct body, k = ceil(200 / 32) = 7: seeding finds no second
  // medoid, so the node is one list of radius 0
  const auto rows = same_body_corpus(200);
  const auto ivf = build_bisect(rows, 32);
  REQUIRE(ivf.ids.size() == rows.size());
  REQUIRE(ivf.lists() == 1);
  CHECK(ivf.radius2[0] == 0);

  // a cell of one body larger than TLSH_IVF_BISECT_FLAT_MAX: the pivot
  // split puts every row on one side, so only the median fallback makes the
  // coarse split terminate; every list has radius 0
  const auto big = same_body_corpus(TLSH_IVF_BISECT_FLAT_MAX + 1000);
  const auto b = build_bisect(big, 32);
  REQUIRE(b.ids.size() == big.size());
  check_bisect_shape(b, 32);
  for (size_t l = 0; l < b.lists(); ++l) {
    CHECK(b.radius2[l] == 0);
  }
}

TEST_CASE("tlsh_ivf_bisect_fewer_bodies_than_lists") {
  // three distinct bodies, 70 rows each (differing in the checksum), in a
  // node with k = ceil(210 / 32) = 7: one list per body, each of radius 0
  std::vector<TlshDigest> rows;
  const auto bodies = one_cell_corpus(32, 3);
  REQUIRE(bodies.size() == 3);
  for (TlshDigest d: bodies) {
    for (size_t i = 0; i < 70; ++i) {
      d.checksum = static_cast<uint8_t>(i);
      rows.push_back(d);
    }
  }
  std::sort(rows.begin(), rows.end());

  const auto ivf = build_bisect(rows, 32);
  REQUIRE(ivf.ids.size() == rows.size());
  REQUIRE(ivf.lists() == 3);
  for (size_t l = 0; l < 3; ++l) {
    CHECK(ivf.list_start[l + 1] - ivf.list_start[l] == 70);
    CHECK(ivf.radius2[l] == 0);
  }
}

TEST_CASE("tlsh_ivf_bisect_coalesces_small_lists") {
  // lists below T / 2 are coalesced pairwise as merge_tlsh_ivf does, so the
  // coalescing invariant holds at threshold T
  for (const size_t T: { 16u, 32u }) {
    const auto one = one_cell_corpus(41, 3000);
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(build_bisect(one, T)), static_cast<uint32_t>(T)));
    const auto many = sorted_corpus(42, 20000);
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(build_bisect(many, T)), static_cast<uint32_t>(T)));
  }
}

TEST_CASE("tlsh_ivf_bisect_list_sizes_and_counts") {
  for (const size_t T: { 8u, 32u, 64u }) {
    const auto rows = sorted_corpus(51, 20000);
    const auto ivf = build_bisect(rows, T);
    check_bisect_shape(ivf, T);
    check_one_centers(ivf, rows);
  }
  check_bisect_shape(build_bisect(same_body_corpus(250), 32), 32);
}

TEST_CASE("tlsh_ivf_bisect_small_cells") {
  // one row: one list of it, radius 0
  const auto one = one_cell_corpus(61, 1);
  const auto a = build_bisect(one, 32);
  REQUIRE(a.lists() == 1);
  CHECK(a.medoids[0] == one[0]);
  CHECK(a.radius2[0] == 0);
  CHECK(a.ids == std::vector<uint32_t>{ 0 });

  // exactly T rows: a single leaf, its 1-center
  const auto t = one_cell_corpus(62, 40);
  REQUIRE(t.size() >= 32);
  const std::vector<TlshDigest> rows(t.begin(), t.begin() + 32);
  const auto b = build_bisect(rows, 32);
  REQUIRE(b.lists() == 1);
  check_one_centers(b, rows);
}

TEST_CASE("tlsh_ivf_bisect_one_large_cell") {
  // ~20k rows in one cell, several times TLSH_IVF_BISECT_FLAT_MAX: coarse
  // splits, then a flat clustering of each node
  const auto rows = one_cell_corpus(71, 20000);
  REQUIRE(rows.size() > 3 * TLSH_IVF_BISECT_FLAT_MAX);
  const auto ivf = build_bisect(rows, 32);
  REQUIRE(ivf.ids.size() == rows.size());
  check_bisect_shape(ivf, 32);
  CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(ivf), 32));
  for (size_t l = 0; l < ivf.lists(); ++l) {
    for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
      REQUIRE(tlsh_embed_body_dist2(ivf.medoids[l], rows[ivf.ids[i]]) <= ivf.radius2[l]);
    }
  }

  const auto view = make_tlsh_ivf_view(ivf);
  for (const auto& q: perturb_tlsh_corpus(72, rows, 10, 0.05)) {
    CHECK(same_matches(
      tlsh_knn_ivf(view, rows.data(), q, 10, 300, true),
      tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, 10, 300, true)
    ));
  }
}

TEST_CASE("tlsh_ivf_merge_of_bisect_builds_is_exact") {
  // two BISECT indexes over the even and odd rows of one sorted corpus,
  // merged into an index over all of it
  auto rows = sorted_corpus(81, 12000);
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  std::vector<TlshDigest> even, odd;
  std::vector<uint32_t> even_map, odd_map;
  for (size_t i = 0; i < rows.size(); ++i) {
    (i % 2 ? odd : even).push_back(rows[i]);
    (i % 2 ? odd_map : even_map).push_back(static_cast<uint32_t>(i));
  }
  const auto a = build_bisect(even, 32);
  const auto b = build_bisect(odd, 32);
  const auto m = merge_tlsh_ivf(
    make_tlsh_ivf_view(a), even_map.data(), make_tlsh_ivf_view(b), odd_map.data(),
    rows.data(), rows.size()
  );
  const auto view = make_tlsh_ivf_view(m);
  CHECK(tlsh_ivf_check_invariant(view, TLSH_IVF_DEFAULT_COALESCE));
  for (size_t l = 0; l < m.lists(); ++l) {
    for (uint64_t i = m.list_start[l]; i < m.list_start[l + 1]; ++i) {
      REQUIRE(tlsh_embed_body_dist2(m.medoids[l], rows[m.ids[i]]) <= m.radius2[l]);
    }
  }
  for (const auto& q: perturb_tlsh_corpus(82, rows, 40, 0.04)) {
    for (const uint32_t T: { 30u, 100u, 300u }) {
      CHECK(same_matches(
        tlsh_knn_ivf(view, rows.data(), q, 10, T, true),
        tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, 10, T, true)
      ));
    }
  }
}

TEST_CASE("tlsh_ivf_nearer") {
  // N_a / n_a^2 < N_b / n_b^2, exactly
  CHECK(tlsh_ivf_nearer(3, 2, 1, 1));     // 3/4 < 1
  CHECK_FALSE(tlsh_ivf_nearer(1, 1, 3, 2));
  CHECK(tlsh_ivf_nearer(0, 5, 1, 1));
  CHECK_FALSE(tlsh_ivf_nearer(0, 5, 0, 1)); // 0 == 0
  CHECK(tlsh_ivf_nearer(1, 4096, 1, 4095));
  CHECK_FALSE(tlsh_ivf_nearer(1, 4095, 1, 4096));
  CHECK_FALSE(tlsh_ivf_nearer(1, 4096, 0, 1));

  // equal distances with different denominators: 4 / 2^2 == 1 / 1^2, so
  // neither is nearer (the caller keeps the smaller index)
  CHECK_FALSE(tlsh_ivf_nearer(4, 2, 1, 1));
  CHECK_FALSE(tlsh_ivf_nearer(1, 1, 4, 2));
  CHECK_FALSE(tlsh_ivf_nearer(9 * 50, 3 * 10, 50, 10)); // 450 / 900 == 50 / 100

  // at the bound N = 2^34, n = 4096: 2^34 / 2^24 == 1024 / 1, and one unit
  // less in N is nearer, which a 32-bit or float product would not see
  const uint64_t N = uint64_t{1} << 34;
  CHECK_FALSE(tlsh_ivf_nearer(N, 4096, 1024, 1));
  CHECK_FALSE(tlsh_ivf_nearer(1024, 1, N, 4096));
  CHECK(tlsh_ivf_nearer(N - 1, 4096, 1024, 1));
  CHECK(tlsh_ivf_nearer(N - 1, 4096, N, 4096));
  CHECK_FALSE(tlsh_ivf_nearer(N, 4096, N - 1, 4096));
}
