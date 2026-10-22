#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <vector>

#include "helper.h"
#include "util.h"
#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_decoder.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_merge.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

/*
 * Incremental merges of the TLSH kNN index: the coalescing of small lists in
 * merge_tlsh_ivf on hand-built cells, and a simulation of a master set
 * absorbing many batches, checked after every step against the invariant,
 * the list and size bounds of docs/TLSH_EMBEDDING.md section 3 and exact
 * search.
 */

namespace {

//
// hand-built cells
//

constexpr uint8_t CELL_L = 100, CELL_Q1 = 5, CELL_Q2 = 7;
const uint32_t CELL = (static_cast<uint32_t>(CELL_L) << 8) | ((CELL_Q1 << 4) | CELL_Q2);

// a digest of the test cell whose buckets in `ones` have code 1 and in
// `twos` code 2, the rest 0
TlshDigest digest(const std::vector<size_t>& ones, const std::vector<size_t>& twos = {}, uint8_t checksum = 1) {
  uint8_t codes[128] = {};
  for (const size_t b: ones) {
    codes[b] = 1;
  }
  for (const size_t b: twos) {
    codes[b] = 2;
  }
  return make_tlsh_digest(CELL_L, CELL_Q1, CELL_Q2, checksum, codes);
}

struct ListSpec {
  TlshDigest medoid;
  uint32_t radius2;
  std::vector<TlshDigest> members;
};

// sorted rows of the lists, and an index with one cell holding the lists
// in the given order; ids ascending within a list
struct HandCell {
  std::vector<TlshDigest> rows;
  TlshIvf ivf;
  std::vector<std::vector<uint32_t>> ids; // per list

  HandCell(const std::vector<ListSpec>& lists) {
    for (const auto& l: lists) {
      rows.insert(rows.end(), l.members.begin(), l.members.end());
    }
    std::sort(rows.begin(), rows.end());
    REQUIRE(std::adjacent_find(rows.begin(), rows.end()) == rows.end());

    ivf.n = rows.size();
    ivf.cell_lists.assign(TLSH_CELL_COUNT + 1, 0);
    ivf.list_start.push_back(0);
    for (const auto& l: lists) {
      std::vector<uint32_t> li;
      for (const auto& m: l.members) {
        li.push_back(static_cast<uint32_t>(std::lower_bound(rows.begin(), rows.end(), m) - rows.begin()));
      }
      std::sort(li.begin(), li.end());
      ivf.medoids.push_back(l.medoid);
      ivf.radius2.push_back(l.radius2);
      ivf.ids.insert(ivf.ids.end(), li.begin(), li.end());
      ivf.list_start.push_back(ivf.ids.size());
      ids.push_back(std::move(li));
    }
    for (uint32_t c = CELL + 1; c <= TLSH_CELL_COUNT; ++c) {
      ivf.cell_lists[c] = static_cast<uint32_t>(lists.size());
    }
  }

  std::vector<uint32_t> identity() const {
    std::vector<uint32_t> m(rows.size());
    std::iota(m.begin(), m.end(), 0u);
    return m;
  }

  TlshIvf merged(uint32_t C, const std::vector<uint32_t>& map, size_t n_out) const {
    return merge_tlsh_ivf(make_tlsh_ivf_view(ivf), map.data(), TlshIvfView(), nullptr, rows.data(), n_out, C);
  }

  TlshIvf merged(uint32_t C) const {
    return merged(C, identity(), rows.size());
  }
};

uint32_t radius_about(const TlshDigest& m, const std::vector<uint32_t>& ids, const std::vector<TlshDigest>& rows) {
  uint32_t r = 0;
  for (const uint32_t id: ids) {
    r = std::max(r, tlsh_embed_body_dist2(m, rows[id]));
  }
  return r;
}

std::vector<uint32_t> list_ids(const TlshIvf& ivf, size_t l) {
  return { ivf.ids.begin() + ivf.list_start[l], ivf.ids.begin() + ivf.list_start[l + 1] };
}

std::vector<uint32_t> sorted_union(std::vector<uint32_t> a, const std::vector<uint32_t>& b) {
  a.insert(a.end(), b.begin(), b.end());
  std::sort(a.begin(), a.end());
  return a;
}

//
// files
//

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

struct Loaded {
  std::vector<char> buf;
  HsetPtr hset{ nullptr, sfhash_destroy_hashset };

  const SFHASH_Hashset* get() const { return hset.get(); }
  const TlshDigest* rows() const { return static_cast<const TlshDigest*>(std::get<ConstHashsetData>(hset->holder.hsets[0]).beg); }
  uint64_t n() const { return std::get<HashsetHeader>(hset->holder.hsets[0]).hash_count; }
  const TlshIvfView& ivf() const { return std::get<TlshIvfView>(hset->holder.hsets[0]); }
};

Loaded load_file(const std::string& path) {
  Loaded l;
  l.buf = read_file(path);
  SFHASH_Error* err = nullptr;
  l.hset.reset(sfhash_load_hashset(l.buf.data(), l.buf.data() + l.buf.size(), &err));
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(l.hset);
  REQUIRE(l.hset->holder.hsets.size() == 1);
  return l;
}

// a TLSH-only, hashsets-only file with the index and no vectors
Loaded build_file(const std::string& path, const std::vector<TlshDigest>& digests) {
  const SFHASH_HashAlgorithm htype = SFHASH_TLSH;
  SFHASH_Error* err = nullptr;
  auto bctx = make_unique_del(
    sfhash_hashset_builder_open("inc", "incremental merge test", &htype, 1, false, true, path.c_str(), "test", &err),
    sfhash_hashset_builder_destroy
  );
  REQUIRE(!err);
  sfhash_hashset_builder_set_tlsh_options(bctx.get(), SFHASH_HSET_TLSH_INDEX);
  for (const auto& d: digests) {
    sfhash_hashset_builder_add_hash(bctx.get(), &d, sizeof(d));
  }
  REQUIRE(sfhash_hashset_builder_write(bctx.get(), &err) > 0);
  REQUIRE(!err);
  return load_file(path);
}

Loaded merge_union(const Loaded& l, const Loaded& r, const std::string& path, uint32_t C) {
  SFHASH_Error* err = nullptr;
  const uint64_t size = sfhash_hashset_merge(
    l.get(), r.get(), SFHASH_HSET_OP_UNION, "inc", "incremental merge test", path.c_str(),
    SFHASH_HSET_TLSH_INDEX, C, &err
  );
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(size > 0);
  return load_file(path);
}

std::vector<TlshDigest> sorted_unique(std::vector<TlshDigest> v) {
  std::sort(v.begin(), v.end());
  v.erase(std::unique(v.begin(), v.end()), v.end());
  return v;
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

// what a brute-force search with smaller k / max_distance returns, derived
// from the k = 50, max_distance = 1000 result (a prefix in (distance, index)
// order, filtered)
std::vector<SFHASH_TlshMatch> restricted(const std::vector<SFHASH_TlshMatch>& full, size_t k, uint32_t maxd) {
  std::vector<SFHASH_TlshMatch> out;
  for (const auto& m: full) {
    if (m.distance <= maxd && out.size() < k) {
      out.push_back(m);
    }
  }
  return out;
}

// structural validity of a loaded index: every row in exactly one list,
// ids ascending and in their cell, radii exact
void check_index_valid(const Loaded& o) {
  const TlshIvfView& ivf = o.ivf();
  const TlshDigest* rows = o.rows();
  const uint64_t n = o.n();
  REQUIRE(!ivf.empty());
  REQUIRE(ivf.n == n);
  REQUIRE(ivf.cell_lists[0] == 0);
  REQUIRE(ivf.cell_lists[TLSH_CELL_COUNT] == ivf.lists);
  REQUIRE(ivf.list_start[0] == 0);
  REQUIRE(ivf.list_start[ivf.lists] == n);

  std::vector<uint32_t> seen(ivf.ids, ivf.ids + n);
  std::sort(seen.begin(), seen.end());
  for (size_t i = 0; i < seen.size(); ++i) {
    REQUIRE(seen[i] == i);
  }

  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    REQUIRE(ivf.cell_lists[c] <= ivf.cell_lists[c + 1]);
    for (uint32_t l = ivf.cell_lists[c]; l < ivf.cell_lists[c + 1]; ++l) {
      const uint64_t lb = ivf.list_start[l], le = ivf.list_start[l + 1];
      REQUIRE(lb < le);
      const TlshBodyQuery q(ivf.medoids[l]);
      uint32_t tight = 0;
      for (uint64_t i = lb; i < le; ++i) {
        if (i > lb) {
          REQUIRE(ivf.ids[i - 1] < ivf.ids[i]);
        }
        REQUIRE(tlsh_cell_id(rows[ivf.ids[i]]) == c);
        tight = std::max(tight, q.emb_body(rows[ivf.ids[i]]));
      }
      REQUIRE(tight <= ivf.radius2[l]);
      CHECK(tight == ivf.radius2[l]);
    }
  }
}

// indexed search == brute force for perturbed queries
void check_index_exact(const Loaded& o, uint64_t query_seed) {
  const TlshDigest* rows = o.rows();
  const uint64_t n = o.n();
  const std::vector<TlshDigest> seeds(rows, rows + n);
  const auto queries = perturb_tlsh_corpus(query_seed, seeds, 30, 0.03);
  std::vector<SFHASH_TlshMatch> out(51);
  for (const auto& q: queries) {
    for (const bool incl: { true, false }) {
      const auto full = tlsh_knn_brute(rows, rows + n, q, 50, 1000, incl);
      for (const size_t k: { 1u, 10u, 50u }) {
        for (const uint32_t maxd: { 30u, 144u, 1000u }) {
          const size_t got = sfhash_hashset_tlsh_knn_with(o.get(), 0, &q, k, maxd, incl, SFHASH_TLSH_KNN_INDEX, out.data());
          REQUIRE(got <= k);
          REQUIRE(same_matches(std::vector<SFHASH_TlshMatch>(out.begin(), out.begin() + got), restricted(full, k, maxd)));
        }
      }
    }
  }
}

struct CellStats {
  size_t nonempty = 0;
  size_t bound_lists = 0; // sum over cells of floor(m_c / half) + 1
};

CellStats cell_stats(const Loaded& o, uint32_t C) {
  CellStats s;
  const auto cells = make_tlsh_cell_index(o.rows(), o.rows() + o.n());
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    const uint64_t m = cells[c + 1] - cells[c];
    if (m) {
      ++s.nonempty;
      if (C) {
        s.bound_lists += m / (C / 2) + 1;
      }
    }
  }
  return s;
}

} // namespace

TEST_CASE("tlsh_ivf_coalesce_small_lists") {
  // A: medoid at the origin, two members a bucket away
  const TlshDigest mA = digest({});
  const TlshDigest a1 = digest({ 0 });
  const TlshDigest a2 = digest({ 1 });
  // B: medoid 10 buckets from mA, members 1 and 2 more buckets further
  const TlshDigest mB = digest({ 50, 51, 52, 53, 54, 55, 56, 57, 58, 59 });
  const TlshDigest b1 = digest({ 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60 });
  const TlshDigest b2 = digest({ 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61 });
  // D: 40 rows with the same body (distinct checksums), far from A and B
  std::vector<TlshDigest> d;
  for (uint8_t cs = 0; cs < 40; ++cs) {
    d.push_back(digest({}, { 100, 101, 102, 103, 104, 105, 106, 107, 108, 109 }, cs));
  }

  REQUIRE(tlsh_embed_body_dist2(mA, mB) == 10);
  REQUIRE(tlsh_embed_body_dist2(mA, b2) == 12);
  REQUIRE(tlsh_embed_body_dist2(mB, a1) == 11);

  const HandCell h({
    { mA, 1, { mA, a1, a2 } },
    { mB, 2, { mB, b1, b2 } },
    { d[0], 0, d }
  });
  const auto ab = sorted_union(h.ids[0], h.ids[1]);

  SECTION("default threshold: the two small lists coalesce, the large one stays") {
    const TlshIvf m = h.merged(TLSH_IVF_DEFAULT_COALESCE);
    REQUIRE(m.lists() == 2);
    CHECK(m.cell_lists[CELL] == 0);
    CHECK(m.cell_lists[CELL + 1] == 2);
    CHECK(list_ids(m, 0) == ab);
    // mB gives radius 11 (to a1, a2), mA would give 12 (to b2)
    CHECK(m.medoids[0] == mB);
    CHECK(m.radius2[0] == 11);
    CHECK(m.radius2[0] == std::min(radius_about(mA, ab, h.rows), radius_about(mB, ab, h.rows)));
    CHECK(list_ids(m, 1) == h.ids[2]);
    CHECK(m.medoids[1] == d[0]);
    CHECK(m.radius2[1] == 0);
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), TLSH_IVF_DEFAULT_COALESCE));
  }

  SECTION("C = 8: both lists of 3 are below 4, their union of 6 is not") {
    const TlshIvf m = h.merged(8);
    REQUIRE(m.lists() == 2);
    CHECK(list_ids(m, 0) == ab);
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), 8));
  }

  SECTION("C = 6: no list is below 3, nothing coalesces") {
    const TlshIvf m = h.merged(6);
    REQUIRE(m.lists() == 3);
    for (size_t l = 0; l < 3; ++l) {
      CHECK(list_ids(m, l) == h.ids[l]);
      CHECK(m.medoids[l] == h.ivf.medoids[l]);
      CHECK(m.radius2[l] == h.ivf.radius2[l]);
    }
  }

  SECTION("C = 0: coalescing disabled") {
    const TlshIvf m = h.merged(0);
    REQUIRE(m.lists() == 3);
    CHECK(!tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), TLSH_IVF_DEFAULT_COALESCE));
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), 0));
  }
}

TEST_CASE("tlsh_ivf_coalesce_greedy_order") {
  // P and Q are close, R is far from both; three lists of three
  const TlshDigest mP = digest({});
  const TlshDigest mQ = digest({ 0, 1 });
  const TlshDigest mR = digest({}, { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 });
  const HandCell h({
    { mP, 1, { mP, digest({ 2 }), digest({ 3 }) } },
    { mQ, 1, { mQ, digest({ 0, 1, 4 }), digest({ 0, 1, 5 }) } },
    { mR, 2, { mR, digest({ 30 }, { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 }), digest({ 30, 31 }, { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 }) } }
  });

  SECTION("C = 10: P and Q coalesce to 6 >= 5 and stop, R stays small alone") {
    const TlshIvf m = h.merged(10);
    REQUIRE(m.lists() == 2);
    CHECK(list_ids(m, 0) == sorted_union(h.ids[0], h.ids[1]));
    CHECK((m.medoids[0] == mP || m.medoids[0] == mQ));
    CHECK(m.radius2[0] == radius_about(m.medoids[0], list_ids(m, 0), h.rows));
    CHECK(m.radius2[0] == std::min(
      radius_about(mP, list_ids(m, 0), h.rows), radius_about(mQ, list_ids(m, 0), h.rows)
    ));
    CHECK(list_ids(m, 1) == h.ids[2]);
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), 10));
  }

  SECTION("C = 14: P and Q first (6 < 7), then R joins") {
    const TlshIvf m = h.merged(14);
    REQUIRE(m.lists() == 1);
    std::vector<uint32_t> all(h.rows.size());
    std::iota(all.begin(), all.end(), 0u);
    CHECK(list_ids(m, 0) == all);
    CHECK((m.medoids[0] == mP || m.medoids[0] == mQ || m.medoids[0] == mR));
    CHECK(m.radius2[0] == radius_about(m.medoids[0], all, h.rows));
    CHECK(tlsh_ivf_check_invariant(make_tlsh_ivf_view(m), 14));
  }
}

TEST_CASE("tlsh_ivf_merge_shrink_recomputes_radius") {
  // one list with members 1, 5 and 9 away from the medoid, stored radius 9;
  // another with a loose stored radius that loses nothing
  const TlshDigest m1 = digest({});
  const TlshDigest far = digest({ 0, 1, 2, 3, 4, 5, 6, 7, 8 });
  const TlshDigest mid = digest({ 0, 1, 2, 3, 4 });
  const TlshDigest near = digest({ 0 });
  const TlshDigest m2 = digest({}, { 100 });
  const TlshDigest m2a = digest({}, { 100, 101 });
  const HandCell h({
    { m1, 9, { m1, near, mid, far } },
    { m2, 100, { m2, m2a } }
  });
  REQUIRE(tlsh_embed_body_dist2(m1, far) == 9);
  REQUIRE(tlsh_embed_body_dist2(m1, mid) == 5);

  // drop `far`; the kept rows are renumbered densely
  std::vector<uint32_t> map(h.rows.size());
  const uint32_t far_id = static_cast<uint32_t>(std::lower_bound(h.rows.begin(), h.rows.end(), far) - h.rows.begin());
  uint32_t next = 0;
  for (size_t i = 0; i < map.size(); ++i) {
    map[i] = i == far_id ? TLSH_IVF_DROPPED : next++;
  }
  std::vector<TlshDigest> kept(h.rows);
  kept.erase(kept.begin() + far_id);

  const TlshIvf m = merge_tlsh_ivf(make_tlsh_ivf_view(h.ivf), map.data(), TlshIvfView(), nullptr, kept.data(), kept.size(), 0);
  REQUIRE(m.lists() == 2);
  CHECK(m.medoids[0] == m1);
  CHECK(m.radius2[0] == 5);
  CHECK(list_ids(m, 0).size() == 3);
  // untouched: medoid and radius verbatim, loose or not
  CHECK(m.medoids[1] == m2);
  CHECK(m.radius2[1] == 100);
  CHECK(list_ids(m, 1).size() == 2);
}

TEST_CASE("tlsh_ivf_check_invariant_hand_built") {
  const HandCell h({
    { digest({}), 1, { digest({}), digest({ 0 }), digest({ 1 }) } },
    { digest({ 50 }), 1, { digest({ 50 }), digest({ 50, 51 }), digest({ 50, 52 }) } }
  });
  const auto v = make_tlsh_ivf_view(h.ivf);
  CHECK(!tlsh_ivf_check_invariant(v, 8));  // two lists below 4
  CHECK(tlsh_ivf_check_invariant(v, 6));   // none below 3
  CHECK(tlsh_ivf_check_invariant(v, 7));   // 7 / 2 == 3
  CHECK(tlsh_ivf_check_invariant(v, 0));
  CHECK(tlsh_ivf_check_invariant(TlshIvfView(), 64));
}

TEST_CASE("hset_merge_incremental_unions") {
  // a 50k master absorbs 24 batches of ~2000 rows: half near-duplicates of
  // master rows, half new families
  constexpr size_t MASTER = 50000, STEPS = 24, HALF_BATCH = 1000;
  constexpr uint32_t T = TLSH_IVF_TARGET_LIST_SIZE;

  const std::vector<TlshDigest> master_corpus = make_tlsh_corpus(101, MASTER);
  std::vector<std::vector<TlshDigest>> batches;
  for (size_t i = 0; i < STEPS; ++i) {
    std::vector<TlshDigest> b = make_tlsh_corpus(1000 + i, HALF_BATCH);
    const auto near = perturb_tlsh_corpus(2000 + i, master_corpus, HALF_BATCH, 0.03);
    b.insert(b.end(), near.begin(), near.end());
    batches.push_back(std::move(b));
  }

  for (const uint32_t C: { 2 * T, T, 0u }) {
    DYNAMIC_SECTION("C = " << C) {
      std::vector<TlshDigest> expected = sorted_unique(master_corpus);
      Loaded master = build_file("test/inc_master.hset", master_corpus);
      REQUIRE(master.n() == expected.size());

      for (size_t step = 0; step < STEPS; ++step) {
        const Loaded batch = build_file("test/inc_batch.hset", batches[step]);
        const std::string out = step % 2 ? "test/inc_out_a.hset" : "test/inc_out_b.hset";
        Loaded merged = merge_union(master, batch, out, C);

        // rows: the union so far
        {
          const auto b = sorted_unique(batches[step]);
          std::vector<TlshDigest> u;
          std::set_union(expected.begin(), expected.end(), b.begin(), b.end(), std::back_inserter(u));
          expected = std::move(u);
          REQUIRE(merged.n() == expected.size());
          REQUIRE(std::memcmp(merged.rows(), expected.data(), expected.size() * sizeof(TlshDigest)) == 0);
        }

        check_index_valid(merged);
        REQUIRE(tlsh_ivf_check_invariant(merged.ivf(), C));

        const CellStats cs = cell_stats(merged, C);
        const TlshIvfView& ivf = merged.ivf();
        if (C) {
          // the proven bound: per cell floor(m / (C / 2)) + 1 lists
          REQUIRE(ivf.lists <= cs.bound_lists);
        }
        if (C == 2 * T) {
          // against a fresh build over the same rows: at most one list more
          // per nonempty cell, 48 bytes each in the TIVF
          const TlshIvf fresh = build_tlsh_ivf(merged.rows(), merged.rows() + merged.n(), T);
          REQUIRE(ivf.lists <= fresh.lists() + cs.nonempty);
          REQUIRE(
            length_tivf_data(ivf.lists, ivf.n) <=
            length_tivf_data(static_cast<uint32_t>(fresh.lists()), fresh.n) + 48 * cs.nonempty
          );
        }

        check_index_exact(merged, 77 + step);

        master = std::move(merged);
      }
    }
  }
}
