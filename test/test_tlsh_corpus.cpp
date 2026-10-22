#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "tlsh_corpus.h"
#include "tlsh_digest.h"

TEST_CASE("tlsh_corpus_family_deterministic") {
  const auto a = make_tlsh_family_corpus(7, 6, 4, 1024, 8192);
  const auto b = make_tlsh_family_corpus(7, 6, 4, 1024, 8192);
  REQUIRE(!a.empty());
  CHECK(a == b);

  const auto c = make_tlsh_family_corpus(8, 6, 4, 1024, 8192);
  CHECK(a != c);
}

TEST_CASE("tlsh_corpus_family_sizes_and_non_null") {
  const auto fams = make_tlsh_families(11, 12, 5, 1024, 8192);
  // a null base drops its family; this should be rare at these lengths
  REQUIRE(fams.size() >= 10);

  size_t total = 0;
  for (const auto& f: fams) {
    CHECK(!f.base.is_null());
    CHECK(f.variants.size() <= 5);
    CHECK(f.variants.size() >= 4);
    for (const auto& v: f.variants) {
      CHECK(!v.is_null());
      CHECK(v.reserved == 0);
    }
    total += 1 + f.variants.size();
  }

  // flattened form: base then variants, family by family
  const auto flat = make_tlsh_family_corpus(11, 12, 5, 1024, 8192);
  REQUIRE(flat.size() == total);
  CHECK(flat.size() <= 12 * 6);
  CHECK(flat[0] == fams[0].base);
  REQUIRE(!fams[0].variants.empty());
  CHECK(flat[1] == fams[0].variants[0]);
}

TEST_CASE("tlsh_corpus_variants_cluster_with_their_base") {
  const auto fams = make_tlsh_families(3, 20, 6, 2048, 16384);
  REQUIRE(fams.size() >= 15);

  size_t closer = 0;
  double own_total = 0.0, other_total = 0.0;

  for (size_t i = 0; i < fams.size(); ++i) {
    REQUIRE(!fams[i].variants.empty());

    double own = 0.0;
    for (const auto& v: fams[i].variants) {
      own += tlsh_diff(v, fams[i].base);
    }
    own /= fams[i].variants.size();

    double other = 0.0;
    size_t n = 0;
    for (size_t j = 0; j < fams.size(); ++j) {
      if (j == i) {
        continue;
      }
      for (const auto& v: fams[i].variants) {
        other += tlsh_diff(v, fams[j].base);
        ++n;
      }
    }
    other /= n;

    own_total += own;
    other_total += other;
    if (own < other) {
      ++closer;
    }
  }

  CHECK(own_total < other_total);
  // nearly every family should be tighter than the inter-family spread
  CHECK(closer * 10 >= fams.size() * 9);
}

TEST_CASE("tlsh_corpus_perturb") {
  const auto seeds = make_tlsh_family_corpus(5, 4, 3, 1024, 4096);
  REQUIRE(!seeds.empty());

  const auto p = perturb_tlsh_corpus(99, seeds, 1000, 0.05);
  REQUIRE(p.size() == 1000);
  CHECK(p == perturb_tlsh_corpus(99, seeds, 1000, 0.05));
  CHECK(p != perturb_tlsh_corpus(100, seeds, 1000, 0.05));

  double nearest_total = 0.0;
  for (const auto& d: p) {
    CHECK(!d.is_null());
    CHECK(d.reserved == 0);

    TlshDigest back;
    REQUIRE(tlsh_from_hex(tlsh_to_hex(d).c_str(), back));
    CHECK(back == d);

    uint32_t nearest = std::numeric_limits<uint32_t>::max();
    for (const auto& s: seeds) {
      nearest = std::min(nearest, tlsh_diff(d, s));
    }
    nearest_total += nearest;
  }

  // ~6 bucket moves, a checksum mismatch, and the occasional L/Q nudge
  CHECK(nearest_total / p.size() < 30.0);

  CHECK(perturb_tlsh_corpus(1, {}, 10).empty());
  CHECK(perturb_tlsh_corpus(1, seeds, 0).empty());
}

TEST_CASE("tlsh_corpus_convenience") {
  const auto a = make_tlsh_corpus(1, 2500);
  REQUIRE(a.size() == 2500);
  CHECK(a == make_tlsh_corpus(1, 2500));
  CHECK(a != make_tlsh_corpus(2, 2500));
  CHECK(std::none_of(a.begin(), a.end(), [](const TlshDigest& d) { return d.is_null(); }));

  // the hashed prefix is exactly the family corpus
  const auto fam = make_tlsh_corpus(1, 30);
  REQUIRE(fam.size() == 30);
  CHECK(std::equal(fam.begin(), fam.end(), a.begin()));

  CHECK(make_tlsh_corpus(1, 25).size() == 25);
  CHECK(make_tlsh_corpus(1, 0).empty());
}
