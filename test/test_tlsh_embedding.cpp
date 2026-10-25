#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include <algorithm>
#include <cmath>
#include <random>
#include <vector>

#include "hasher/tlsh.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "tlsh_corpus.h"

using Catch::Approx;

namespace {

std::vector<float> embed(const TlshDigest& d) {
  std::vector<float> v(TLSH_EMBED_DIMS);
  tlsh_embed(d, v.data());
  return v;
}

TlshDigest digest_with(uint8_t L, uint8_t q1, uint8_t q2, uint8_t cs, const std::vector<uint8_t>& codes) {
  REQUIRE(codes.size() == 128);
  return make_tlsh_digest(L, q1, q2, cs, codes.data());
}

const std::vector<uint8_t> ZERO_CODES(128, 0);

} // namespace

TEST_CASE("tlsh_embed_dims_and_layout") {
  CHECK(TLSH_EMBED_DIMS == 264);
  CHECK(SFHASH_TLSH_EMBEDDING_DIMS == 264);

  std::vector<uint8_t> codes(128);
  for (size_t i = 0; i < 128; ++i) {
    codes[i] = i % 4;
  }
  const auto d = digest_with(77, 3, 12, 0b101, codes);
  const auto v = embed(d);

  // body coordinates are in {-1, 0, 1} and follow the code table
  const float bx[4] = { 1, 0, 0, -1 }, by[4] = { 0, 0, 1, 1 };
  for (size_t i = 0; i < 128; ++i) {
    CHECK(v[2 * i] == bx[i % 4]);
    CHECK(v[2 * i + 1] == by[i % 4]);
  }
  CHECK(v[256] == 77.f);
  // Q points lie on the circle of radius 1 / (2 sin(pi/16))
  const double R = 1.0 / (2.0 * std::sin(std::acos(-1.0) / 16.0));
  CHECK(std::hypot(v[257], v[258]) == Approx(R).epsilon(1e-5));
  CHECK(std::hypot(v[259], v[260]) == Approx(R).epsilon(1e-5));
  // Q1 = 3 -> angle 3 * 2pi / 16
  CHECK(v[257] == Approx(R * std::cos(3 * 2 * std::acos(-1.0) / 16)).epsilon(1e-5));
  // checksum bits scaled by 1/sqrt(3)
  CHECK(v[261] == Approx(1 / std::sqrt(3.0)).epsilon(1e-6));
  CHECK(v[262] == 0.f);
  CHECK(v[263] == Approx(1 / std::sqrt(3.0)).epsilon(1e-6));

  // C API agrees
  std::vector<float> c(TLSH_EMBED_DIMS);
  sfhash_tlsh_embed(&d, c.data());
  CHECK(c == v);
}

TEST_CASE("tlsh_embed_n_embeds_each_contiguous_digest") {
  // row r of the batch is the single-digest embedding of digest r, for
  // digests laid out as hash set rows are, 36 bytes apart
  const auto digests = make_tlsh_corpus(3, 100);
  REQUIRE(sizeof(TlshDigest) == SFHASH_TLSH_DIGEST_LENGTH);
  const size_t n = digests.size();

  // a sentinel past the last row is left alone
  std::vector<float> out(n * SFHASH_TLSH_EMBEDDING_DIMS + 1, -7.f);
  sfhash_tlsh_embed_n(digests.data(), n, out.data());
  CHECK(out.back() == -7.f);

  std::vector<float> one(SFHASH_TLSH_EMBEDDING_DIMS);
  for (size_t r = 0; r < n; ++r) {
    sfhash_tlsh_embed(&digests[r], one.data());
    const std::vector<float> row(
      out.begin() + r * SFHASH_TLSH_EMBEDDING_DIMS,
      out.begin() + (r + 1) * SFHASH_TLSH_EMBEDDING_DIMS
    );
    INFO("row " << r);
    CHECK(row == one);
  }

  // no digests, nothing written
  float untouched = -7.f;
  sfhash_tlsh_embed_n(nullptr, 0, &untouched);
  CHECK(untouched == -7.f);
}

TEST_CASE("tlsh_embed_body_component_bounds") {
  // every pair of codes in a single bucket, all else equal
  const uint32_t cost[4] = { 0, 1, 2, 6 };
  const float expected_d2[4] = { 0, 1, 2, 5 };
  for (int bucket: {0, 1, 64, 127}) {
    for (uint8_t ca = 0; ca < 4; ++ca) {
      for (uint8_t cb = 0; cb < 4; ++cb) {
        auto codes_a = ZERO_CODES, codes_b = ZERO_CODES;
        codes_a[bucket] = ca;
        codes_b[bucket] = cb;
        const auto a = digest_with(50, 0, 0, 0, codes_a);
        const auto b = digest_with(50, 0, 0, 0, codes_b);
        const float d2 = tlsh_embed_dist2(embed(a).data(), embed(b).data());
        CHECK(d2 == expected_d2[std::abs(ca - cb)]);
        CHECK(d2 <= cost[std::abs(ca - cb)]);
        CHECK(tlsh_embed_dist2(a, b) == d2);
      }
    }
  }
}

TEST_CASE("tlsh_embed_L_component_bounds") {
  const auto a = digest_with(100, 0, 0, 0, ZERO_CODES);
  for (int k = 0; k <= 12; ++k) {
    const auto b = digest_with(100 + k, 0, 0, 0, ZERO_CODES);
    const float d2 = tlsh_embed_dist2(embed(a).data(), embed(b).data());
    CHECK(d2 == static_cast<float>(k * k));
    CHECK(d2 <= tlsh_diff(a, b, true));
    CHECK(tlsh_embed_dist2(embed(a).data(), embed(b).data(), false) == 0.f);
    CHECK(tlsh_embed_dist2(a, b, false) == 0.f);
  }
  // beyond k = 12 the TLSH distance exceeds 144 and the bound no longer holds
  const auto far = digest_with(113, 0, 0, 0, ZERO_CODES);
  CHECK(tlsh_diff(a, far) > TLSH_EMBED_MAX_BOUNDED_DIFF);
}

TEST_CASE("tlsh_embed_Q_component_bounds") {
  for (int which = 0; which < 2; ++which) {
    for (int qa = 0; qa < 16; ++qa) {
      for (int qb = 0; qb < 16; ++qb) {
        const auto a = digest_with(50, which ? 0 : qa, which ? qa : 0, 0, ZERO_CODES);
        const auto b = digest_with(50, which ? 0 : qb, which ? qb : 0, 0, ZERO_CODES);
        const float d2 = tlsh_embed_dist2(embed(a).data(), embed(b).data());
        const uint32_t cost = tlsh_diff(a, b);
        CHECK(d2 <= cost + 1e-4f);
        const int k = std::min(std::abs(qa - qb), 16 - std::abs(qa - qb));
        if (k == 1) {
          CHECK(d2 == Approx(1.0f).epsilon(1e-5));
        }
        CHECK(tlsh_embed_dist2(a, b) == Approx(d2).epsilon(1e-5));
      }
    }
  }
}

TEST_CASE("tlsh_embed_checksum_component_bounds") {
  for (int ca = 0; ca < 256; ca += 7) {
    for (int cb = 0; cb < 256; cb += 5) {
      const auto a = digest_with(50, 0, 0, ca, ZERO_CODES);
      const auto b = digest_with(50, 0, 0, cb, ZERO_CODES);
      const float d2 = tlsh_embed_dist2(embed(a).data(), embed(b).data());
      CHECK(d2 <= (ca != cb ? 1.f : 0.f) + 1e-6f);
      CHECK(tlsh_embed_dist2(a, b) == Approx(d2).margin(1e-5));
    }
  }
}

TEST_CASE("tlsh_embed_lower_bound_on_corpus_pairs") {
  // near pairs: corpus digests against perturbations of themselves, plus
  // random pairs; both distance variants
  const auto corpus = make_tlsh_corpus(4242, 3000);
  REQUIRE(corpus.size() > 1000);
  std::mt19937 rng(7);
  size_t bounded_pairs = 0;
  double tightness = 0;
  for (size_t i = 0; i < 6000; ++i) {
    const auto& a = corpus[rng() % corpus.size()];
    const auto b = i < 3000 ?
      perturb_tlsh_corpus(i, std::vector<TlshDigest>{a}, 1, 0.05).front() :
      corpus[rng() % corpus.size()];
    const auto va = embed(a), vb = embed(b);
    for (bool incl: {true, false}) {
      const uint32_t t = tlsh_diff(a, b, incl);
      const float e_vec = tlsh_embed_dist2(va.data(), vb.data(), incl);
      const float e_dig = tlsh_embed_dist2(a, b, incl);
      CHECK(e_vec == Approx(e_dig).epsilon(1e-4).margin(1e-3));
      if (!incl || t <= TLSH_EMBED_MAX_BOUNDED_DIFF) {
        CHECK(e_vec <= t + 1e-3f);
        if (incl && t > 0) {
          ++bounded_pairs;
          tightness += e_vec / t;
        }
      }
    }
  }
  REQUIRE(bounded_pairs > 100);
  // the bound should be reasonably tight on near pairs
  CHECK(tightness / bounded_pairs > 0.5);
}

TEST_CASE("tlsh_embed_body_dist2_matches_float") {
  const auto corpus = make_tlsh_corpus(5, 300);
  for (size_t i = 0; i + 1 < corpus.size(); ++i) {
    const auto& a = corpus[i];
    const auto& b = corpus[i + 1];
    std::vector<float> va(TLSH_EMBED_BODY_DIMS), vb(TLSH_EMBED_BODY_DIMS);
    tlsh_embed_body(a, va.data());
    tlsh_embed_body(b, vb.data());
    float s = 0;
    for (size_t j = 0; j < TLSH_EMBED_BODY_DIMS; ++j) {
      s += (va[j] - vb[j]) * (va[j] - vb[j]);
    }
    CHECK(static_cast<float>(tlsh_embed_body_dist2(a, b)) == s);
    CHECK(tlsh_embed_body_dist2(a, b) <= tlsh_body_diff(a, b));
    CHECK(tlsh_embed_body_dist2_to_point(a, vb.data()) == Approx(s).margin(1e-3));
  }
}

TEST_CASE("tlsh_embed_dist2_to_point") {
  const auto corpus = make_tlsh_corpus(99, 200);
  std::vector<float> centroid(TLSH_EMBED_DIMS, 0.f);
  for (const auto& d: corpus) {
    const auto v = embed(d);
    for (size_t i = 0; i < TLSH_EMBED_DIMS; ++i) {
      centroid[i] += v[i] / corpus.size();
    }
  }
  for (const auto& d: corpus) {
    const auto v = embed(d);
    for (bool incl: {true, false}) {
      CHECK(tlsh_embed_dist2_to_point(d, centroid.data(), incl) ==
            Approx(tlsh_embed_dist2(v.data(), centroid.data(), incl)).epsilon(1e-4).margin(1e-3));
    }
  }
}

TEST_CASE("tlsh_embed_body_i8") {
  // codes 0, 1, 2, 3 repeating: by the table (1, 0), (0, 0), (0, 1),
  // (-1, 1), squared norms 1 + 0 + 1 + 2 per four buckets, 32 x 4 = 128
  std::vector<uint8_t> codes(128);
  for (size_t i = 0; i < 128; ++i) {
    codes[i] = i % 4;
  }
  const int8_t bx[4] = { 1, 0, 0, -1 }, by[4] = { 0, 0, 1, 1 };
  int8_t v[TLSH_EMBED_BODY_DIMS];
  CHECK(tlsh_embed_body_i8(digest_with(77, 3, 12, 5, codes), v) == 128);
  for (size_t i = 0; i < 128; ++i) {
    CHECK(v[2 * i] == bx[i % 4]);
    CHECK(v[2 * i + 1] == by[i % 4]);
  }

  // all code 1: the zero vector
  CHECK(tlsh_embed_body_i8(digest_with(1, 2, 3, 4, std::vector<uint8_t>(128, 1)), v) == 0);
  CHECK(std::all_of(v, v + TLSH_EMBED_BODY_DIMS, [](int8_t x) { return x == 0; }));

  // random planes: equals the float embedding, and the returned norm is
  // the squared distance to the all-code-1 body (the zero vector)
  std::mt19937_64 rng(3);
  const auto origin = digest_with(1, 2, 3, 4, std::vector<uint8_t>(128, 1));
  for (int n = 0; n < 200; ++n) {
    TlshDigest d = origin;
    for (size_t b = 0; b < 16; ++b) {
      d.hi[b] = static_cast<uint8_t>(rng());
      d.lo[b] = static_cast<uint8_t>(rng());
    }
    float f[TLSH_EMBED_BODY_DIMS];
    tlsh_embed_body(d, f);
    const uint32_t norm2 = tlsh_embed_body_i8(d, v);
    for (size_t j = 0; j < TLSH_EMBED_BODY_DIMS; ++j) {
      REQUIRE(static_cast<float>(v[j]) == f[j]);
    }
    CHECK(norm2 == tlsh_embed_body_dist2(d, origin));
  }
}
