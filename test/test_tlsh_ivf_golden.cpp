#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "hasher/common.h"
#include "hasher/hasher.h"
#include "tlsh_digest.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

/*
 * Golden test for the reproducibility of BISECT index bytes.
 *
 * BISECT uses integer arithmetic only and draws straight from
 * std::mt19937_64, so for the same rows and seed its serialized TIVF
 * payload must be identical on every platform, compiler and standard
 * library. The corpora below are generated the same way: integer-only
 * arithmetic on mt19937_64 output (whose sequence the standard fully
 * specifies), no std::*_distribution, no floating point, no std::shuffle.
 *
 * Each case checks the row count, the list count, ids.size() and the
 * SHA-256 (through the library's hasher) of the write_tivf_data bytes of
 * the default (BISECT) build with the default seed. The KMEANS index of
 * the same rows is checked for exactness only: its bytes depend on the
 * float arithmetic of the platform.
 *
 * The constants were recorded on arm64 (macOS, clang). They must be
 * identical on every platform; a difference is a reproducibility bug in
 * the BISECT path, not something to update blindly.
 */

namespace {

struct CellSpec {
  uint8_t L;
  size_t rows;
};

/*
 * Rows of the given header cells (L distinct per cell, Q drawn), each
 * cell's rows drawn in families of about family_size: a random base body
 * (hi, lo), then each member a copy with up to 7 random body bits flipped
 * and a random checksum. Sorted and deduplicated (the canonical bytewise
 * order of an HDAT).
 */
std::vector<TlshDigest> golden_corpus(uint64_t seed, const std::vector<CellSpec>& cells, size_t family_size) {
  std::mt19937_64 g(seed);
  std::vector<TlshDigest> rows;
  for (const auto& c: cells) {
    const uint8_t Q = static_cast<uint8_t>(g() & 0xFF);
    TlshDigest base{};
    for (size_t i = 0; i < c.rows; ++i) {
      if (i % family_size == 0) {
        for (size_t b = 0; b < 16; ++b) {
          base.hi[b] = static_cast<uint8_t>(g() & 0xFF);
          base.lo[b] = static_cast<uint8_t>(g() & 0xFF);
        }
      }
      TlshDigest d = base;
      d.L = c.L;
      d.Q = Q;
      d.checksum = static_cast<uint8_t>(g() & 0xFF);
      d.reserved = 0;
      const uint64_t flips = g() % 8;
      for (uint64_t f = 0; f < flips; ++f) {
        const uint64_t bit = g() % 256;
        uint8_t* plane = bit < 128 ? d.hi : d.lo;
        plane[(bit % 128) >> 3] ^= static_cast<uint8_t>(1u << (bit & 7));
      }
      rows.push_back(d);
    }
  }
  std::sort(rows.begin(), rows.end());
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  return rows;
}

// one cell above TLSH_IVF_BISECT_FLAT_MAX (coarse split), 39 smaller cells
// of 20-219 rows (flat k-means, several above T = 32)
std::vector<CellSpec> large_cells() {
  std::mt19937_64 g(0x676f6c64656e);
  std::vector<CellSpec> cells{ { 0, 5000 } };
  for (uint8_t c = 1; c < 40; ++c) {
    cells.push_back({ static_cast<uint8_t>(5 * c), 20 + static_cast<size_t>(g() % 200) });
  }
  return cells;
}

// 12 cells of 150-399 rows: flat only
std::vector<CellSpec> small_cells() {
  std::mt19937_64 g(0x736d616c6c);
  std::vector<CellSpec> cells;
  for (uint8_t c = 0; c < 12; ++c) {
    cells.push_back({ static_cast<uint8_t>(7 + 11 * c), 150 + static_cast<size_t>(g() % 250) });
  }
  return cells;
}

std::string sha256_hex(const std::vector<char>& buf) {
  SFHASH_Hasher* h = sfhash_create_hasher(SFHASH_SHA_2_256);
  sfhash_update_hasher(h, buf.data(), buf.data() + buf.size());
  SFHASH_HashValues v;
  sfhash_get_hashes(h, &v);
  sfhash_destroy_hasher(h);
  static const char digits[] = "0123456789abcdef";
  std::string hex;
  for (const uint8_t b: v.Sha2_256) {
    hex += digits[b >> 4];
    hex += digits[b & 0x0F];
  }
  return hex;
}

std::vector<char> tivf_bytes(const TlshIvf& ivf) {
  std::vector<char> buf(length_tivf_data(ivf.lists(), ivf.n));
  REQUIRE(write_tivf_data(ivf, buf.data()) == buf.size());
  return buf;
}

size_t max_cell_rows(const TlshIvf& ivf) {
  size_t m = 0;
  for (size_t c = 0; c + 1 < ivf.cell_lists.size(); ++c) {
    m = std::max<size_t>(m, ivf.list_start[ivf.cell_lists[c + 1]] - ivf.list_start[ivf.cell_lists[c]]);
  }
  return m;
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

// kNN by the KMEANS index over the same rows equals brute force; queries
// are rows with a few bits of their body flipped
void check_kmeans_exact(const std::vector<TlshDigest>& rows) {
  const TlshIvf ivf = build_tlsh_ivf(
    rows.data(), rows.data() + rows.size(), TLSH_IVF_TARGET_LIST_SIZE, TLSH_IVF_DEFAULT_SEED, 0, TlshIvfBuild::KMEANS
  );
  const TlshIvfView v = make_tlsh_ivf_view(ivf);
  std::mt19937_64 g(99);
  for (size_t i = 0; i < 20; ++i) {
    TlshDigest q = rows[g() % rows.size()];
    for (size_t f = 0; f < 6; ++f) {
      q.hi[g() % 16] ^= static_cast<uint8_t>(1u << (g() % 8));
    }
    for (const size_t k: { 1u, 10u }) {
      for (const bool incl: { true, false }) {
        CHECK(same_matches(
          tlsh_knn_ivf(v, rows.data(), q, k, 300, incl),
          tlsh_knn_brute(rows.data(), rows.data() + rows.size(), q, k, 300, incl)
        ));
      }
    }
  }
}

struct Golden {
  size_t rows;
  size_t lists;
  std::string sha256;
};

void check_golden(const std::vector<TlshDigest>& rows, const Golden& want) {
  const TlshIvf ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size());
  const std::string got = sha256_hex(tivf_bytes(ivf));
  INFO("rows " << rows.size() << ", lists " << ivf.lists() << ", ids " << ivf.ids.size() << ", sha256 " << got);
  CHECK(rows.size() == want.rows);
  CHECK(ivf.ids.size() == want.rows);
  CHECK(ivf.lists() == want.lists);
  CHECK(got == want.sha256);
}

} // namespace

TEST_CASE("tlsh_ivf_golden_sha256_helper") {
  // FIPS 180-2 test vector, so a golden mismatch is not the helper's
  const std::vector<char> abc{ 'a', 'b', 'c' };
  CHECK(sha256_hex(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("tlsh_ivf_golden_bisect_small") {
  const auto rows = golden_corpus(0x5eed01, small_cells(), 20);
  {
    const TlshIvf ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size());
    REQUIRE(max_cell_rows(ivf) > TLSH_IVF_TARGET_LIST_SIZE);
    REQUIRE(max_cell_rows(ivf) <= TLSH_IVF_BISECT_FLAT_MAX);
  }
  check_golden(rows, { 2844, 94, "bdc17ba69181cce3886aba9a75cfabf6eccdf442e5b58c29b36f1379218598be" });
  check_kmeans_exact(rows);
}

TEST_CASE("tlsh_ivf_golden_bisect_large") {
  const auto rows = golden_corpus(0x5eed02, large_cells(), 20);
  {
    // the coarse split is exercised
    const TlshIvf ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size());
    REQUIRE(max_cell_rows(ivf) > TLSH_IVF_BISECT_FLAT_MAX);
  }
  check_golden(rows, { 10400, 343, "b1bb7a6d494bef04007ac04832f89aa00552c11f2d1eb01d6c085d5f0bfe55bb" });
  check_kmeans_exact(rows);
}
