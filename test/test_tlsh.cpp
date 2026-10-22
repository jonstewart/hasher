#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <tlsh.h> // reference implementation, for conformance only

#include "helper.h"
#include "hasher/hasher.h"
#include "hasher/tlsh.h"
#include "tlsh_digest.h"
#include "tlsh_hasher.h"
#include "util.h"

namespace {

const std::string TLSH_TESTING = "vendors/tlsh/Testing/";

const char* const VEC_HEX = "T11FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";

// filename -> hex digest
std::map<std::string, std::string> read_expected_hashes() {
  std::map<std::string, std::string> m;
  std::ifstream in(TLSH_TESTING + "exp/example_data.128.1.len.out_EXP");
  REQUIRE(in);
  std::string hex, path;
  while (in >> hex >> path) {
    m[path] = hex;
  }
  REQUIRE(m.size() == 80);
  return m;
}

// (file a, file b) -> score
std::vector<std::tuple<std::string, std::string, int>> read_expected_scores(const std::string& name) {
  std::vector<std::tuple<std::string, std::string, int>> v;
  std::ifstream in(TLSH_TESTING + "exp/" + name);
  REQUIRE(in);
  std::string a, b;
  int score;
  while (in >> a >> b >> score) {
    v.emplace_back(a, b, score);
  }
  REQUIRE(v.size() == 80);
  return v;
}

TlshDigest hash_bytes(const std::vector<char>& buf) {
  TlshHasher h;
  h.update(reinterpret_cast<const uint8_t*>(buf.data()), reinterpret_cast<const uint8_t*>(buf.data() + buf.size()));
  return h.digest();
}

std::string ref_hash(const std::vector<char>& buf) {
  Tlsh t;
  t.update(reinterpret_cast<const unsigned char*>(buf.data()), buf.size());
  t.final();
  const char* h = t.getHash(1);
  return h && *h ? h : "TNULL";
}

std::vector<char> random_bytes(std::mt19937& rng, size_t n, unsigned alphabet) {
  std::vector<char> v(n);
  std::uniform_int_distribution<unsigned> d(0, alphabet - 1);
  for (auto& c: v) {
    c = static_cast<char>(d(rng));
  }
  return v;
}

} // namespace

TEST_CASE("tlsh_digest_layout") {
  CHECK(sizeof(TlshDigest) == 36);
  CHECK(offsetof(TlshDigest, L) == 0);
  CHECK(offsetof(TlshDigest, Q) == 1);
  CHECK(offsetof(TlshDigest, hi) == 2);
  CHECK(offsetof(TlshDigest, lo) == 18);
  CHECK(offsetof(TlshDigest, checksum) == 34);
  CHECK(offsetof(TlshDigest, reserved) == 35);
  CHECK(sfhash_hash_length(SFHASH_TLSH) == 36);
  CHECK(std::string("TLSH") == sfhash_hash_name(SFHASH_TLSH));
  CHECK(sfhash_hash_type("tlsh") == SFHASH_TLSH);
}

TEST_CASE("tlsh_hex_round_trip") {
  TlshDigest d;
  REQUIRE(tlsh_from_hex(VEC_HEX, d));
  CHECK(!d.is_null());
  CHECK(d.reserved == 0);
  CHECK(tlsh_to_hex(d) == VEC_HEX);

  // no prefix, lowercase
  std::string lower(VEC_HEX + 2);
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  TlshDigest d2;
  REQUIRE(tlsh_from_hex(lower.c_str(), d2));
  CHECK(d == d2);

  // C API
  uint8_t buf[SFHASH_TLSH_DIGEST_LENGTH];
  REQUIRE(sfhash_tlsh_from_hex(VEC_HEX, buf));
  CHECK(!std::memcmp(buf, &d, sizeof(d)));
  char hex[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(buf, hex);
  CHECK(std::string(hex) == VEC_HEX);
  CHECK(!sfhash_tlsh_is_null(buf));
}

TEST_CASE("tlsh_hex_null") {
  TlshDigest d;
  REQUIRE(tlsh_from_hex("TNULL", d));
  CHECK(d.is_null());
  CHECK(tlsh_to_hex(d) == "TNULL");

  uint8_t zero[SFHASH_TLSH_DIGEST_LENGTH] = {};
  CHECK(sfhash_tlsh_is_null(zero));
  char hex[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(zero, hex);
  CHECK(std::string(hex) == "TNULL");
}

TEST_CASE("tlsh_hex_rejects_garbage") {
  TlshDigest d;
  CHECK(!tlsh_from_hex("", d));
  CHECK(!tlsh_from_hex("T1", d));
  CHECK(!tlsh_from_hex(("T2" + std::string(VEC_HEX + 2)).c_str(), d));
  CHECK(!tlsh_from_hex(std::string(VEC_HEX).substr(0, 71).c_str(), d)); // too short
  CHECK(!tlsh_from_hex((std::string(VEC_HEX) + "A").c_str(), d));       // too long
  std::string bad(VEC_HEX);
  bad[10] = 'G';
  CHECK(!tlsh_from_hex(bad.c_str(), d));
  CHECK(!tlsh_from_hex("TNULLX", d));
  CHECK(!sfhash_tlsh_from_hex(bad.c_str(), &d));
}

TEST_CASE("tlsh_decode_matches_reference_fields") {
  const auto exp = read_expected_hashes();
  for (const auto& [path, hex]: exp) {
    TlshDigest d;
    REQUIRE(tlsh_from_hex(hex.c_str(), d));

    Tlsh ref;
    REQUIRE(ref.fromTlshStr(hex.c_str()) == 0);

    CHECK(d.L == ref.Lvalue());
    CHECK(d.q1() == ref.Q1ratio());
    CHECK(d.q2() == ref.Q2ratio());
    CHECK(d.checksum == ref.Checksum(0));
    for (int i = 0; i < 128; ++i) {
      // Tlsh::BucketValue numbers buckets in hex (byte-reversed) order;
      // we number them as the reference's internal a_bucket index does.
      const int hex_order = 4 * (31 - i / 4) + (3 - i % 4);
      CHECK(d.bucket(i) == ref.BucketValue(hex_order));
    }
  }
}

TEST_CASE("tlsh_diff_matches_reference_scores") {
  const auto exp = read_expected_hashes();

  for (const auto& [scores, include_length]: {
    std::pair{"example_data.128.1.len.scores_EXP", true},
    std::pair{"example_data.128.1.xlen.scores_EXP", false}
  }) {
    for (const auto& [a, b, score]: read_expected_scores(scores)) {
      TlshDigest da, db;
      REQUIRE(tlsh_from_hex(exp.at(a).c_str(), da));
      REQUIRE(tlsh_from_hex(exp.at(b).c_str(), db));
      CHECK(static_cast<int>(tlsh_diff(da, db, include_length)) == score);
      CHECK(sfhash_tlsh_diff(&da, &db, include_length) == score);
      // symmetric
      CHECK(static_cast<int>(tlsh_diff(db, da, include_length)) == score);
    }
  }
}

TEST_CASE("tlsh_diff_null") {
  TlshDigest d, z{};
  REQUIRE(tlsh_from_hex(VEC_HEX, d));
  CHECK(sfhash_tlsh_diff(&d, &z, true) == -1);
  CHECK(sfhash_tlsh_diff(&z, &d, true) == -1);
  CHECK(sfhash_tlsh_diff(&d, &d, true) == 0);
}

TEST_CASE("tlsh_diff_exhaustive_single_bucket_costs") {
  // every pair of codes in one bucket, all else equal
  uint8_t codes_a[128] = {}, codes_b[128] = {};
  for (int bucket: {0, 7, 8, 63, 64, 127}) {
    for (uint8_t ca = 0; ca < 4; ++ca) {
      for (uint8_t cb = 0; cb < 4; ++cb) {
        codes_a[bucket] = ca;
        codes_b[bucket] = cb;
        const auto a = make_tlsh_digest(50, 3, 4, 7, codes_a);
        const auto b = make_tlsh_digest(50, 3, 4, 7, codes_b);
        const int ad = std::abs(ca - cb);
        const uint32_t exp = ad == 3 ? 6 : ad;
        CHECK(tlsh_body_diff(a, b) == exp);
        CHECK(tlsh_diff(a, b) == exp);
      }
    }
    codes_a[bucket] = codes_b[bucket] = 0;
  }
}

TEST_CASE("tlsh_diff_header_costs") {
  uint8_t codes[128] = {};
  const auto base = make_tlsh_digest(100, 5, 9, 42, codes);

  for (int k = 0; k < 256; ++k) {
    const auto o = make_tlsh_digest((100 + k) % 256, 5, 9, 42, codes);
    const uint32_t md = std::min(k, 256 - k);
    CHECK(tlsh_diff(base, o, true) == tlsh_l_cost(md));
    CHECK(tlsh_diff(base, o, false) == 0);
  }

  for (int k = 0; k < 16; ++k) {
    const uint32_t md = std::min(k, 16 - k);
    CHECK(tlsh_diff(base, make_tlsh_digest(100, (5 + k) % 16, 9, 42, codes)) == tlsh_q_cost(md));
    CHECK(tlsh_diff(base, make_tlsh_digest(100, 5, (9 + k) % 16, 42, codes)) == tlsh_q_cost(md));
  }

  CHECK(tlsh_diff(base, make_tlsh_digest(100, 5, 9, 43, codes)) == 1);
}

TEST_CASE("tlsh_hash_matches_reference_vectors") {
  const auto exp = read_expected_hashes();
  for (const auto& [path, hex]: exp) {
    const auto buf = read_file(TLSH_TESTING + path);
    const auto d = hash_bytes(buf);
    CHECK(tlsh_to_hex(d) == hex);
  }
}

TEST_CASE("tlsh_hash_via_hasher_api") {
  const auto exp = read_expected_hashes();
  const auto path = exp.begin()->first;
  const auto buf = read_file(TLSH_TESTING + path);

  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_TLSH | SFHASH_MD5), sfhash_destroy_hasher
  );
  sfhash_update_hasher(hasher.get(), buf.data(), buf.data() + buf.size());

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  char hex[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(hashes.Tlsh, hex);
  CHECK(std::string(hex) == exp.begin()->second);
}

TEST_CASE("tlsh_hash_chunked_equals_whole") {
  std::mt19937 rng(12345);
  const auto buf = random_bytes(rng, 10000, 256);
  const auto whole = hash_bytes(buf);
  REQUIRE(!whole.is_null());

  for (size_t chunk: {1, 3, 4, 5, 6, 7, 64, 4096}) {
    TlshHasher h;
    for (size_t i = 0; i < buf.size(); i += chunk) {
      const size_t n = std::min(chunk, buf.size() - i);
      h.update(reinterpret_cast<const uint8_t*>(buf.data() + i), reinterpret_cast<const uint8_t*>(buf.data() + i + n));
    }
    CHECK(h.digest() == whole);
  }
}

TEST_CASE("tlsh_hash_short_input_is_null") {
  std::mt19937 rng(99);
  for (size_t n: {0, 1, 4, 5, 49}) {
    CHECK(hash_bytes(random_bytes(rng, n, 256)).is_null());
  }
  // 50 bytes of varied data suffices
  CHECK(!hash_bytes(random_bytes(rng, 50, 256)).is_null());
  // low variety: too few nonzero buckets
  CHECK(hash_bytes(std::vector<char>(1000, 'a')).is_null());
}

TEST_CASE("tlsh_hash_random_matches_reference") {
  std::mt19937 rng(777);
  for (int i = 0; i < 200; ++i) {
    const size_t n = 1 + rng() % 5000;
    const unsigned alphabet = 1 + rng() % 256;
    const auto buf = random_bytes(rng, n, alphabet);
    CHECK(tlsh_to_hex(hash_bytes(buf)) == ref_hash(buf));
  }
  for (size_t n: {40000, 100000, 1000000}) {
    const auto buf = random_bytes(rng, n, 256);
    CHECK(tlsh_to_hex(hash_bytes(buf)) == ref_hash(buf));
  }
}

TEST_CASE("tlsh_diff_random_matches_reference") {
  std::mt19937 rng(31337);
  // Tlsh's copy constructor is shallow, so keep them in place
  std::vector<std::pair<TlshDigest, std::unique_ptr<Tlsh>>> ds;
  for (int i = 0; i < 40; ++i) {
    const auto buf = random_bytes(rng, 60 + rng() % 3000, 2 + rng() % 255);
    auto ref = std::make_unique<Tlsh>();
    ref->update(reinterpret_cast<const unsigned char*>(buf.data()), buf.size());
    ref->final();
    if (!ref->isValid()) {
      continue;
    }
    TlshDigest d;
    REQUIRE(tlsh_from_hex(ref->getHash(1), d));
    ds.emplace_back(d, std::move(ref));
  }
  REQUIRE(ds.size() > 20);
  for (const auto& [da, ra]: ds) {
    for (const auto& [db, rb]: ds) {
      CHECK(static_cast<int>(tlsh_diff(da, db, true)) == ra->totalDiff(rb.get(), true));
      CHECK(static_cast<int>(tlsh_diff(da, db, false)) == ra->totalDiff(rb.get(), false));
    }
  }
}

TEST_CASE("tlsh_hasher_clone_and_reset") {
  std::mt19937 rng(5);
  const auto buf = random_bytes(rng, 3000, 256);
  const auto* p = reinterpret_cast<const uint8_t*>(buf.data());

  TlshHasher h;
  h.update(p, p + 1000);
  std::unique_ptr<TlshHasher> c(h.clone());
  h.update(p + 1000, p + 3000);
  c->update(p + 1000, p + 3000);
  CHECK(h.digest() == c->digest());
  CHECK(h.digest() == hash_bytes(buf));

  // get() is not destructive
  CHECK(h.digest() == c->digest());

  h.reset();
  CHECK(h.digest().is_null());
  h.update(p, p + 3000);
  CHECK(h.digest() == c->digest());
}

TEST_CASE("tlsh_canonical_order_is_bytewise") {
  // L, then Q1, then Q2 dominate the bytewise order
  uint8_t codes[128] = {};
  const auto a = make_tlsh_digest(10, 15, 15, 255, codes);
  const auto b = make_tlsh_digest(11, 0, 0, 0, codes);
  CHECK(a < b);
  const auto c = make_tlsh_digest(11, 1, 0, 0, codes);
  CHECK(b < c);
  const auto d = make_tlsh_digest(11, 1, 1, 0, codes);
  CHECK(c < d);
}
