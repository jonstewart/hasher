#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "helper.h"
#include "rwutil.h"
#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_decoder.h"
#include "hashset/hset_decoder_chunks.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_encoder_chunks.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

namespace {

constexpr uint32_t BOTH = SFHASH_HSET_TLSH_VECTORS | SFHASH_HSET_TLSH_INDEX;

const std::vector<TlshDigest>& corpus() {
  static const std::vector<TlshDigest> c = make_tlsh_corpus(21, 5000);
  return c;
}

// a distinct, deterministic 32-char hex "md5" per index
std::string fake_md5(size_t i) {
  std::ostringstream ss;
  ss << std::hex << std::setw(32) << std::setfill('0') << (i * 2654435761ULL + 0x9E3779B9ULL);
  return ss.str();
}

// one line per digest: "<md5> <tlsh>" or just "<tlsh>"
std::string corpus_text(bool with_md5) {
  std::ostringstream out;
  const auto& c = corpus();
  for (size_t i = 0; i < c.size(); ++i) {
    if (with_md5) {
      out << fake_md5(i) << ' ';
    }
    out << tlsh_to_hex(c[i]) << '\n';
  }
  return out.str();
}

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

struct Built {
  std::vector<char> buf;
  HsetPtr hset;
  TableOfContents toc;
  int tidx;
};

TableOfContents ftoc_of(const std::vector<char>& buf) {
  const uint8_t* beg = reinterpret_cast<const uint8_t*>(buf.data());
  const uint8_t* end = beg + buf.size();
  const uint8_t* cur = beg + 8 + 32; // magic, hset hash
  const Chunk ch = decode_chunk(beg, cur, end);
  REQUIRE(ch.type == Chunk::FTOC);
  return parse_ftoc(ch);
}

HsetPtr load(const std::vector<char>& buf) {
  SFHASH_Error* err = nullptr;
  HsetPtr hset(
    sfhash_load_hashset(buf.data(), buf.data() + buf.size(), &err),
    sfhash_destroy_hashset
  );
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(hset);
  return hset;
}

Built build(
  bool with_md5,
  const std::string& outpath,
  bool with_records,
  bool with_hashsets,
  uint32_t tlsh_options)
{
  const std::vector<SFHASH_HashAlgorithm> htypes = with_md5 ?
    std::vector<SFHASH_HashAlgorithm>{ SFHASH_MD5, SFHASH_TLSH } :
    std::vector<SFHASH_HashAlgorithm>{ SFHASH_TLSH };

  std::istringstream in(corpus_text(with_md5));

  write_hset(
    in,
    htypes,
    make_text_converters(htypes),
    "TLSH vectors test",
    "synthetic TLSH corpus",
    outpath,
    "test",
    with_records,
    with_hashsets,
    tlsh_options
  );

  Built b{ read_file(outpath), HsetPtr(nullptr, sfhash_destroy_hashset), {}, -1 };
  b.hset = load(b.buf);
  b.toc = ftoc_of(b.buf);
  b.tidx = sfhash_hashset_index_for_type(b.hset.get(), SFHASH_TLSH);
  REQUIRE(b.tidx >= 0);
  return b;
}

size_t count_type(const TableOfContents& toc, uint32_t type) {
  return std::count_if(
    toc.entries.begin(), toc.entries.end(),
    [type](const auto& e) { return e.second == type; }
  );
}

// the FTOC index of the first entry of the given type
size_t find_type(const TableOfContents& toc, uint32_t type) {
  const auto i = std::find_if(
    toc.entries.begin(), toc.entries.end(),
    [type](const auto& e) { return e.second == type; }
  );
  REQUIRE(i != toc.entries.end());
  return i - toc.entries.begin();
}

const TlshDigest* rows_of(const SFHASH_Hashset* hset, size_t tidx) {
  return static_cast<const TlshDigest*>(
    std::get<ConstHashsetData>(hset->holder.hsets[tidx]).beg
  );
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

std::vector<SFHASH_TlshMatch> knn(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const TlshDigest& q,
  size_t k,
  uint32_t maxd,
  bool incl)
{
  std::vector<SFHASH_TlshMatch> out(k + 1);
  const size_t n = sfhash_hashset_tlsh_knn(hset, tidx, &q, k, maxd, incl, out.data());
  REQUIRE(n <= k);
  out.resize(n);
  return out;
}

std::vector<SFHASH_TlshMatch> knn_with(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const TlshDigest& q,
  size_t k,
  uint32_t maxd,
  bool incl,
  uint32_t strategy)
{
  std::vector<SFHASH_TlshMatch> out(k + 1);
  const size_t n = sfhash_hashset_tlsh_knn_with(hset, tidx, &q, k, maxd, incl, strategy, out.data());
  REQUIRE(n <= k);
  out.resize(n);
  return out;
}

// the chunk at FTOC index i of buf
Chunk chunk_at(const std::vector<char>& buf, const TableOfContents& toc, size_t i) {
  const uint8_t* beg = reinterpret_cast<const uint8_t*>(buf.data());
  const uint8_t* cur = beg + toc.entries[i].first;
  return decode_chunk(beg, cur, beg + buf.size());
}

void check_vectors_and_index(const Built& b, uint32_t tlsh_options) {
  const SFHASH_Hashset* hset = b.hset.get();
  const size_t tidx = b.tidx;
  const auto& hs = hset->holder.hsets[tidx];
  const auto& hhdr = std::get<HashsetHeader>(hs);
  const uint64_t n = hhdr.hash_count;
  REQUIRE(n > 0);
  const TlshDigest* rows = rows_of(hset, tidx);

  const bool want_vec = tlsh_options & SFHASH_HSET_TLSH_VECTORS;
  const bool want_idx = tlsh_options & SFHASH_HSET_TLSH_INDEX;

  // chunk presence
  CHECK(count_type(b.toc, Chunk::TVEC) == (want_vec ? 1u : 0u));
  CHECK(count_type(b.toc, Chunk::TIVF) == (want_idx ? 1u : 0u));

  // chunk order: HDAT [RIDX] [TVEC] [TIVF] then HHnn or FEND
  {
    // the HDAT of the TLSH set is the last HDAT, as TLSH is the last field
    size_t i = find_type(b.toc, Chunk::HDAT);
    for (size_t j = i + 1; j < b.toc.entries.size(); ++j) {
      if (b.toc.entries[j].second == Chunk::HDAT) {
        i = j;
      }
    }
    ++i;
    if (i < b.toc.entries.size() && b.toc.entries[i].second == Chunk::RIDX) {
      ++i;
    }
    if (want_vec) {
      REQUIRE(i < b.toc.entries.size());
      CHECK(b.toc.entries[i].second == Chunk::TVEC);
      ++i;
    }
    if (want_idx) {
      REQUIRE(i < b.toc.entries.size());
      CHECK(b.toc.entries[i].second == Chunk::TIVF);
      ++i;
    }
    REQUIRE(i < b.toc.entries.size());
    const uint32_t next = b.toc.entries[i].second;
    CHECK((next == Chunk::FEND || (next & 0xFFFF0000) == Chunk::HHDR));

    // offsets ascend
    for (size_t j = 1; j < b.toc.entries.size(); ++j) {
      CHECK(b.toc.entries[j - 1].first < b.toc.entries[j].first);
    }
  }

  // vectors
  const auto& tv = std::get<ConstTlshVectors>(hs);
  size_t dims = 999;
  const float* vec = sfhash_hashset_tlsh_vectors(hset, tidx, &dims);
  if (want_vec) {
    REQUIRE(tv.data);
    CHECK(tv.dims == TLSH_EMBED_DIMS);
    CHECK(tv.n == n);
    CHECK(vec == tv.data);
    CHECK(dims == SFHASH_TLSH_EMBEDDING_DIMS);

    // float data is page aligned relative to the file start
    const ptrdiff_t off = reinterpret_cast<const char*>(tv.data) - b.buf.data();
    CHECK(off > 0);
    CHECK(off % 4096 == 0);

    // the chunk layout matches the doc: data at chunk offset + 12 + 32
    const size_t ci = find_type(b.toc, Chunk::TVEC);
    CHECK(static_cast<uint64_t>(off) == b.toc.entries[ci].first + 12 + 32);
    const Chunk ch = chunk_at(b.buf, b.toc, ci);
    CHECK(static_cast<uint64_t>(ch.dend - ch.dbeg) == length_tvec_data(n));

    // every row is the embedding of the HDAT row
    float exp[TLSH_EMBED_DIMS];
    for (uint64_t r = 0; r < n; ++r) {
      tlsh_embed(rows[r], exp);
      REQUIRE(std::memcmp(exp, tv.data + r * TLSH_EMBED_DIMS, sizeof(exp)) == 0);
    }
  }
  else {
    CHECK(!tv.data);
    CHECK(tv.n == 0);
    CHECK(vec == nullptr);
    CHECK(dims == 0);
  }

  // index
  const auto& ivf = std::get<TlshIvfView>(hs);
  const uint32_t strategies = sfhash_hashset_tlsh_knn_strategies(hset, tidx);
  if (want_idx) {
    REQUIRE(!ivf.empty());
    CHECK(ivf.n == n);
    CHECK(ivf.dims == TLSH_EMBED_DIMS);
    CHECK(ivf.lists > 1);
    CHECK(ivf.list_start[0] == 0);
    CHECK(ivf.list_start[ivf.lists] == n);
    std::vector<uint32_t> ids(ivf.ids, ivf.ids + n);
    std::sort(ids.begin(), ids.end());
    for (size_t i = 0; i < ids.size(); ++i) {
      REQUIRE(ids[i] == i);
    }
    CHECK(strategies == (SFHASH_TLSH_KNN_BRUTE | SFHASH_TLSH_KNN_INDEX));
    const size_t ci = find_type(b.toc, Chunk::TIVF);
    const Chunk ch = chunk_at(b.buf, b.toc, ci);
    CHECK(static_cast<uint64_t>(ch.dend - ch.dbeg) == length_tivf_data(ivf.lists, n));
  }
  else {
    CHECK(ivf.empty());
    CHECK(strategies == SFHASH_TLSH_KNN_BRUTE);
  }

  // a non-TLSH hashset has neither
  const int midx = sfhash_hashset_index_for_type(hset, SFHASH_MD5);
  if (midx >= 0) {
    const auto& ms = hset->holder.hsets[midx];
    CHECK(!std::get<ConstTlshVectors>(ms).data);
    CHECK(std::get<TlshIvfView>(ms).empty());
    size_t mdims = 999;
    CHECK(sfhash_hashset_tlsh_vectors(hset, midx, &mdims) == nullptr);
    CHECK(mdims == 0);
    CHECK(sfhash_hashset_tlsh_knn_strategies(hset, midx) == 0);
  }
}

} // namespace

TEST_CASE("tvec_lengths_and_alignment") {
  CHECK(length_tvec_data(0) == 32);
  CHECK(length_tvec_data(1) == 32 + 264 * 4);
  CHECK(length_tvec_data(5000) == 32 + 5000 * 264 * 4);
  CHECK(length_tvec(7) == 12 + 32 + 7 * 264 * 4);

  for (const uint64_t pos: { 0u, 1u, 43u, 44u, 45u, 4051u, 4052u, 4053u, 8191u, 8192u, 123457u }) {
    const size_t pad = length_tvec_alignment_padding(pos);
    CHECK(pad < 4096);
    CHECK((pos + pad + 12 + 32) % 4096 == 0);
  }

  CHECK(length_tivf(3, 100) == 12 + length_tivf_data(3, 100));
}

TEST_CASE("tvec_write_parse_round_trip") {
  const auto& c = corpus();
  const TlshDigest* beg = c.data();
  const TlshDigest* end = beg + 17;

  std::vector<char> buf(length_tvec(17) + 3, 0x7F);
  // write at an odd offset so nothing relies on buffer alignment
  REQUIRE(write_tvec(beg, end, buf.data() + 3) == length_tvec(17));

  const uint8_t* cbeg = reinterpret_cast<const uint8_t*>(buf.data() + 3);
  const uint8_t* cur = cbeg;
  const Chunk ch = decode_chunk(cbeg, cur, cbeg + length_tvec(17));
  CHECK(ch.type == Chunk::TVEC);
  CHECK(static_cast<size_t>(ch.dend - ch.dbeg) == length_tvec_data(17));

  // header fields
  const uint8_t* h = ch.dbeg;
  uint16_t version;
  std::memcpy(&version, h, 2);
  CHECK(version == 1);
  CHECK(h[2] == 0); // variant
  CHECK(h[3] == 0); // flags
  uint32_t dims;
  std::memcpy(&dims, h + 4, 4);
  CHECK(dims == 264);
  uint64_t n;
  std::memcpy(&n, h + 8, 8);
  CHECK(n == 17);
  uint32_t dtype;
  std::memcpy(&dtype, h + 16, 4);
  CHECK(dtype == 1);

  const ConstTlshVectors tv = parse_tvec(ch);
  CHECK(tv.dims == 264);
  CHECK(tv.n == 17);
  REQUIRE(tv.data == reinterpret_cast<const float*>(ch.dbeg + 32));
  for (size_t r = 0; r < 17; ++r) {
    float exp[TLSH_EMBED_DIMS];
    tlsh_embed(beg[r], exp);
    CHECK(std::memcmp(exp, ch.dbeg + 32 + r * TLSH_EMBED_DIMS * 4, sizeof(exp)) == 0);
  }

  // corruptions are rejected
  std::vector<uint8_t> data(ch.dbeg, ch.dend);
  const auto chunk_of = [&data]() {
    return Chunk{ Chunk::TVEC, data.data(), data.data() + data.size() };
  };
  CHECK_NOTHROW(parse_tvec(chunk_of()));

  data[0] = 2; // version
  CHECK_THROWS(parse_tvec(chunk_of()));
  data[0] = 1;

  data[2] = 1; // variant
  CHECK_THROWS(parse_tvec(chunk_of()));
  data[2] = 0;

  data[4] = 0x07; // dims = 263
  CHECK_THROWS(parse_tvec(chunk_of()));
  data[4] = 0x08;

  data[16] = 2; // dtype
  CHECK_THROWS(parse_tvec(chunk_of()));
  data[16] = 1;

  data[8] = 16; // n disagrees with the length
  CHECK_THROWS(parse_tvec(chunk_of()));
  data[8] = 17;

  CHECK_NOTHROW(parse_tvec(chunk_of()));
  CHECK_THROWS(parse_tvec(Chunk{ Chunk::TVEC, data.data(), data.data() + data.size() - 1 }));
  CHECK_THROWS(parse_tvec(Chunk{ Chunk::TVEC, data.data(), data.data() + 31 }));
}

TEST_CASE("hset_tlsh_vectors_options") {
  const struct { bool md5; bool records; const char* path; } modes[] = {
    { true,  true,  "test/tlsh_vec_rh.hset" },
    { true,  false, "test/tlsh_vec_ho.hset" },
    { false, true,  "test/tlsh_vec_rh1.hset" },
    { false, false, "test/tlsh_vec_ho1.hset" }
  };

  for (const auto& m: modes) {
    for (const uint32_t opts: { BOTH, uint32_t(SFHASH_HSET_TLSH_VECTORS), uint32_t(SFHASH_HSET_TLSH_INDEX), 0u }) {
      const Built b = build(m.md5, m.path, m.records, true, opts);
      const uint64_t n = sfhash_hashset_count(b.hset.get(), b.tidx);
      if (m.records && m.md5) {
        // every line is a distinct record, duplicates are duplicate rows
        CHECK(n == corpus().size());
      }
      else {
        CHECK(n <= corpus().size());
        CHECK(n > corpus().size() / 2);
      }
      check_vectors_and_index(b, opts);
    }
  }
}

TEST_CASE("hset_tlsh_vectors_non_tlsh_only") {
  // a file without a TLSH field never has TVEC/TIVF, whatever the options
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5 };
  std::ostringstream text;
  for (size_t i = 0; i < 100; ++i) {
    text << fake_md5(i) << '\n';
  }
  for (const bool with_records: { true, false }) {
    std::istringstream in(text.str());
    write_hset(
      in, htypes, make_text_converters(htypes),
      "md5 only", "md5 only", "test/md5_only_vec.hset", "test",
      with_records, true, BOTH
    );
    const auto buf = read_file("test/md5_only_vec.hset");
    const auto toc = ftoc_of(buf);
    CHECK(count_type(toc, Chunk::TVEC) == 0);
    CHECK(count_type(toc, Chunk::TIVF) == 0);
    const auto hset = load(buf);
    const int midx = sfhash_hashset_index_for_type(hset.get(), SFHASH_MD5);
    REQUIRE(midx == 0);
    CHECK(sfhash_hashset_count(hset.get(), midx) == 100);
  }
}

TEST_CASE("hset_tlsh_knn_index_matches_brute") {
  const Built b = build(true, "test/tlsh_vec_knn.hset", true, true, BOTH);
  const SFHASH_Hashset* hset = b.hset.get();
  const size_t tidx = b.tidx;
  const uint64_t n = sfhash_hashset_count(hset, tidx);
  const TlshDigest* rows = rows_of(hset, tidx);

  REQUIRE(sfhash_hashset_tlsh_knn_strategies(hset, tidx) == (SFHASH_TLSH_KNN_BRUTE | SFHASH_TLSH_KNN_INDEX));

  const auto queries = perturb_tlsh_corpus(7, corpus(), 30, 0.03);
  REQUIRE(queries.size() == 30);

  for (const auto& q: queries) {
    for (const size_t k: { 1u, 10u, 50u }) {
      for (const uint32_t maxd: { 30u, 100u, 144u }) {
        for (const bool incl: { true, false }) {
          const auto exp = tlsh_knn_brute(rows, rows + n, q, k, maxd, incl);
          const auto brute = knn_with(hset, tidx, q, k, maxd, incl, SFHASH_TLSH_KNN_BRUTE);
          const auto index = knn_with(hset, tidx, q, k, maxd, incl, SFHASH_TLSH_KNN_INDEX);
          const auto chosen = knn(hset, tidx, q, k, maxd, incl);
          CHECK(same_matches(brute, exp));
          CHECK(same_matches(index, exp));
          CHECK(same_matches(chosen, exp));

          for (size_t i = 1; i < chosen.size(); ++i) {
            CHECK(
              std::tie(chosen[i - 1].distance, chosen[i - 1].index) <
              std::tie(chosen[i].distance, chosen[i].index)
            );
          }
          for (const auto& m: chosen) {
            CHECK(m.distance <= maxd);
            CHECK(m.index < n);
          }
        }
      }
    }
  }

  // a member is found at distance 0
  {
    const auto r = knn(hset, tidx, rows[1234], 1, 0, true);
    REQUIRE(r.size() == 1);
    CHECK(r[0].distance == 0);
    CHECK(rows[r[0].index] == rows[1234]);
  }

  // unknown strategies are unsupported
  SFHASH_TlshMatch out[4];
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &queries[0], 4, 100, true, 0, out) == 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &queries[0], 4, 100, true, 4, out) == 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &queries[0], 4, 100, true, SFHASH_TLSH_KNN_BRUTE | SFHASH_TLSH_KNN_INDEX, out) == 0);

  // degenerate inputs
  const TlshDigest null{};
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &null, 4, 100, true, SFHASH_TLSH_KNN_INDEX, out) == 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, nullptr, 4, 100, true, SFHASH_TLSH_KNN_INDEX, out) == 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &queries[0], 0, 100, true, SFHASH_TLSH_KNN_INDEX, out) == 0);
  const int midx = sfhash_hashset_index_for_type(hset, SFHASH_MD5);
  REQUIRE(midx >= 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, midx, &queries[0], 4, 100, true, SFHASH_TLSH_KNN_BRUTE, out) == 0);
  CHECK(sfhash_hashset_tlsh_knn_with(hset, 99, &queries[0], 4, 100, true, SFHASH_TLSH_KNN_BRUTE, out) == 0);
}

TEST_CASE("hset_tlsh_knn_index_clamps_max_distance_with_length") {
  const Built b = build(true, "test/tlsh_vec_knn.hset", true, true, BOTH);
  const SFHASH_Hashset* hset = b.hset.get();
  const size_t tidx = b.tidx;
  const uint64_t n = sfhash_hashset_count(hset, tidx);
  const TlshDigest* rows = rows_of(hset, tidx);

  const auto q = perturb_tlsh_corpus(9, corpus(), 1, 0.2).front();

  // with the length the index answers up to 144 only
  const auto chosen = knn(hset, tidx, q, 1000, 100000, true);
  for (const auto& m: chosen) {
    CHECK(m.distance <= TLSH_EMBED_MAX_BOUNDED_DIFF);
  }
  CHECK(same_matches(chosen, tlsh_knn_brute(rows, rows + n, q, 1000, TLSH_EMBED_MAX_BOUNDED_DIFF, true)));
  CHECK(same_matches(chosen, knn_with(hset, tidx, q, 1000, 100000, true, SFHASH_TLSH_KNN_INDEX)));

  // explicit brute force honours the threshold
  const auto brute = knn_with(hset, tidx, q, 1000, 100000, true, SFHASH_TLSH_KNN_BRUTE);
  CHECK(same_matches(brute, tlsh_knn_brute(rows, rows + n, q, 1000, 100000, true)));
  CHECK(brute.size() >= chosen.size());

  // without the length there is no cap
  const auto chosen_x = knn(hset, tidx, q, 1000, 100000, false);
  CHECK(same_matches(chosen_x, tlsh_knn_brute(rows, rows + n, q, 1000, 100000, false)));
}

TEST_CASE("hset_tlsh_knn_without_index_is_brute") {
  for (const uint32_t opts: { 0u, uint32_t(SFHASH_HSET_TLSH_VECTORS) }) {
    const Built b = build(true, "test/tlsh_vec_noidx.hset", true, true, opts);
    const SFHASH_Hashset* hset = b.hset.get();
    const size_t tidx = b.tidx;
    const uint64_t n = sfhash_hashset_count(hset, tidx);
    const TlshDigest* rows = rows_of(hset, tidx);

    CHECK(sfhash_hashset_tlsh_knn_strategies(hset, tidx) == SFHASH_TLSH_KNN_BRUTE);

    const auto queries = perturb_tlsh_corpus(8, corpus(), 5, 0.03);
    SFHASH_TlshMatch out[8];
    for (const auto& q: queries) {
      for (const uint32_t maxd: { 50u, 200u }) {
        for (const bool incl: { true, false }) {
          const auto exp = tlsh_knn_brute(rows, rows + n, q, 8, maxd, incl);
          CHECK(same_matches(knn(hset, tidx, q, 8, maxd, incl), exp));
          CHECK(same_matches(knn_with(hset, tidx, q, 8, maxd, incl, SFHASH_TLSH_KNN_BRUTE), exp));
          // the index strategy is unsupported
          CHECK(sfhash_hashset_tlsh_knn_with(hset, tidx, &q, 8, maxd, incl, SFHASH_TLSH_KNN_INDEX, out) == 0);
        }
      }
    }
  }
}

TEST_CASE("hset_tlsh_vectors_decode_rejects_corruption") {
  const Built b = build(true, "test/tlsh_vec_bad.hset", true, true, BOTH);

  const size_t vi = find_type(b.toc, Chunk::TVEC);
  const size_t ii = find_type(b.toc, Chunk::TIVF);
  const size_t vdata = b.toc.entries[vi].first + 12; // TVEC payload
  const size_t idata = b.toc.entries[ii].first + 12; // TIVF payload
  const size_t ftoc_data = 8 + 32 + 12;              // first FTOC entry

  const auto fails = [](const std::vector<char>& buf) {
    SFHASH_Error* err = nullptr;
    HsetPtr hset(
      sfhash_load_hashset(buf.data(), buf.data() + buf.size(), &err),
      sfhash_destroy_hashset
    );
    const bool failed = !hset && err;
    if (err) {
      sfhash_free_error(err);
    }
    return failed;
  };

  // the pristine copy loads
  CHECK(!fails(b.buf));

  // TVEC version
  {
    auto buf = b.buf;
    buf[vdata] = 2;
    CHECK(fails(buf));
  }
  // TVEC variant
  {
    auto buf = b.buf;
    buf[vdata + 2] = 1;
    CHECK(fails(buf));
  }
  // TVEC dims
  {
    auto buf = b.buf;
    buf[vdata + 4] = 0x00;
    buf[vdata + 5] = 0x02; // 512
    CHECK(fails(buf));
  }
  // TVEC dtype
  {
    auto buf = b.buf;
    buf[vdata + 16] = 2;
    CHECK(fails(buf));
  }
  // TVEC row count disagrees with HDAT
  {
    auto buf = b.buf;
    uint64_t n;
    std::memcpy(&n, buf.data() + vdata + 8, 8);
    --n;
    std::memcpy(buf.data() + vdata + 8, &n, 8);
    CHECK(fails(buf));
  }
  // TIVF version
  {
    auto buf = b.buf;
    buf[idata] = 3;
    CHECK(fails(buf));
  }
  // TIVF dims
  {
    auto buf = b.buf;
    buf[idata + 4] = 0x07;
    CHECK(fails(buf));
  }
  // TIVF row count disagrees with HDAT
  {
    auto buf = b.buf;
    uint64_t n;
    std::memcpy(&n, buf.data() + idata + 16, 8);
    ++n;
    std::memcpy(buf.data() + idata + 16, &n, 8);
    CHECK(fails(buf));
  }
  // TIVF before TVEC: swap the two FTOC entries
  {
    auto buf = b.buf;
    std::vector<char> ve(buf.begin() + ftoc_data + vi * 12, buf.begin() + ftoc_data + (vi + 1) * 12);
    std::vector<char> ie(buf.begin() + ftoc_data + ii * 12, buf.begin() + ftoc_data + (ii + 1) * 12);
    std::copy(ie.begin(), ie.end(), buf.begin() + ftoc_data + vi * 12);
    std::copy(ve.begin(), ve.end(), buf.begin() + ftoc_data + ii * 12);
    CHECK(fails(buf));
  }
  // TVEC on a hashset that is not TLSH: retype the TLSH set as blake3
  // (HH0f -> HH0a) in both the FTOC and the chunk header
  {
    auto buf = b.buf;
    const size_t hi = find_type(b.toc, Chunk::HHDR | 15); // SFHASH_TLSH == 1 << 15
    const size_t entry = ftoc_data + hi * 12 + 8;
    REQUIRE(buf[entry + 3] == 0x0f);
    buf[entry + 3] = 0x0a;
    buf[b.toc.entries[hi].first + 3] = 0x0a;
    CHECK(fails(buf));
  }
}
