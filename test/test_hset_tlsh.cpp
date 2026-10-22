#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <tlsh.h> // reference implementation, for conformance only

#include "helper.h"
#include "hex.h"
#include "rwutil.h"
#include "tlsh_digest.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hasher/tlsh.h"
#include "hashset/hset.h"
#include "hashset/hset_decoder_chunks.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_encoder_chunks.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ls.h"
#include "hashset/tlsh_search.h"
#include "hashset/util.h"

namespace {

const std::string TLSH_EXP = "vendors/tlsh/Testing/exp/example_data.128.1.len.out_EXP";

// the 80 hex digests from the reference test data, in file order
std::vector<std::string> read_example_digests() {
  std::vector<std::string> v;
  std::ifstream in(TLSH_EXP);
  REQUIRE(in);
  std::string hex, path;
  while (in >> hex >> path) {
    v.push_back(hex);
  }
  REQUIRE(v.size() == 80);
  return v;
}

// a distinct, deterministic 32-char hex "md5" per index
std::string fake_md5(size_t i) {
  std::ostringstream ss;
  ss << std::hex << std::setw(32) << std::setfill('0') << (i * 2654435761ULL + 0x9E3779B9ULL);
  return ss.str();
}

struct Fixture {
  std::string text;                 // the input text
  std::vector<std::string> digests; // the 80 example digests
  size_t tlsh_rows;                 // TLSH rows expected in a records+hashsets file
  size_t unique_tlsh;               // distinct TLSH digests
  size_t records;                   // distinct records
  // hex digest -> set of hex md5s appearing with it
  std::map<std::string, std::set<std::string>> md5s_for;
};

Fixture make_fixture(bool tlsh_first) {
  Fixture f;
  f.digests = read_example_digests();

  std::ostringstream out;
  const auto line = [&](const std::string& md5, const std::string& tlsh) {
    if (tlsh_first) {
      out << tlsh << ' ' << md5 << '\n';
    }
    else {
      out << md5 << ' ' << tlsh << '\n';
    }
  };

  size_t i = 0;
  for (; i < f.digests.size(); ++i) {
    line(fake_md5(i), f.digests[i]);
    f.md5s_for[f.digests[i]].insert(fake_md5(i));
  }

  // null digest: a record, but no TLSH row
  line(fake_md5(i++), "TNULL");
  // empty TLSH column: a record, but no TLSH row
  line(fake_md5(i++), "");
  // duplicate digest with a different md5: a second TLSH row
  line(fake_md5(i), f.digests[7]);
  f.md5s_for[f.digests[7]].insert(fake_md5(i));
  ++i;

  f.text = out.str();
  f.tlsh_rows = 81;
  f.unique_tlsh = 80;
  f.records = i;
  return f;
}

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

std::pair<std::vector<char>, HsetPtr> build_and_load(
  const std::string& text,
  const std::vector<SFHASH_HashAlgorithm>& htypes,
  const std::string& outpath,
  bool with_records,
  bool with_hashsets)
{
  std::istringstream in(text);

  write_hset(
    in,
    htypes,
    make_text_converters(htypes),
    "TLSH test",
    "TLSH digests paired with fake md5s",
    outpath,
    "test",
    with_records,
    with_hashsets
  );

  auto buf = read_file(outpath);

  SFHASH_Error* err = nullptr;
  HsetPtr hset(
    sfhash_load_hashset(buf.data(), buf.data() + buf.size(), &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(hset);

  return { std::move(buf), std::move(hset) };
}

TlshDigest digest_of(const std::string& hex) {
  TlshDigest d;
  REQUIRE(tlsh_from_hex(hex.c_str(), d));
  return d;
}

const TlshDigest* rows_of(const SFHASH_Hashset* hset, size_t tidx) {
  return static_cast<const TlshDigest*>(
    std::get<ConstHashsetData>(hset->holder.hsets[tidx]).beg
  );
}

std::vector<uint64_t> cells_of(const SFHASH_Hashset* hset, size_t tidx) {
  const auto& hnt = std::get<HashsetHint>(hset->holder.hsets[tidx]);
  REQUIRE(hnt.hint_type == 0x7400);
  REQUIRE(
    static_cast<const uint8_t*>(hnt.end) - static_cast<const uint8_t*>(hnt.beg) ==
    static_cast<ptrdiff_t>(65537 * sizeof(uint64_t))
  );
  std::vector<uint64_t> cells(65537);
  std::memcpy(cells.data(), hnt.beg, 65537 * sizeof(uint64_t));
  return cells;
}

void check_cell_index(const std::vector<uint64_t>& cells, const TlshDigest* beg, const TlshDigest* end) {
  const uint64_t n = end - beg;
  REQUIRE(cells.size() == 65537);
  CHECK(cells[0] == 0);
  CHECK(cells[65536] == n);
  for (size_t c = 0; c < 65536; ++c) {
    CHECK(cells[c] <= cells[c + 1]);
  }
  for (const TlshDigest* d = beg; d != end; ++d) {
    const uint64_t i = d - beg;
    const uint32_t c = tlsh_cell_id(*d);
    CHECK(cells[c] <= i);
    CHECK(i < cells[c + 1]);
  }
}

// naive kNN for comparison
std::vector<SFHASH_TlshMatch> naive_knn(
  const TlshDigest* beg,
  const TlshDigest* end,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length)
{
  std::vector<SFHASH_TlshMatch> all;
  for (const TlshDigest* d = beg; d != end; ++d) {
    const int dist = sfhash_tlsh_diff(&q, d, include_length);
    REQUIRE(dist >= 0);
    if (static_cast<uint32_t>(dist) <= max_distance) {
      all.push_back({ static_cast<uint64_t>(d - beg), static_cast<uint32_t>(dist) });
    }
  }
  std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) {
    return std::tie(a.distance, a.index) < std::tie(b.distance, b.index);
  });
  if (all.size() > k) {
    all.resize(k);
  }
  return all;
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

TEST_CASE("tlsh_cell_id") {
  TlshDigest d{};
  d.L = 0x12;
  d.Q = 0x34;
  CHECK(tlsh_cell_id(d) == 0x1234);
  d.L = 0xFF;
  d.Q = 0xFF;
  CHECK(tlsh_cell_id(d) == 0xFFFF);
}

TEST_CASE("make_tlsh_cell_index_empty") {
  const auto cells = make_tlsh_cell_index(nullptr, nullptr);
  REQUIRE(cells.size() == 65537);
  CHECK(std::all_of(cells.begin(), cells.end(), [](uint64_t c) { return c == 0; }));
}

TEST_CASE("make_tlsh_cell_index_small") {
  std::vector<TlshDigest> v(5, TlshDigest{});
  // cells 0x0000, 0x0000, 0x0102, 0x0102, 0xFFFF
  v[2].L = 0x01; v[2].Q = 0x02;
  v[3].L = 0x01; v[3].Q = 0x02; v[3].checksum = 1;
  v[4].L = 0xFF; v[4].Q = 0xFF;

  const auto cells = make_tlsh_cell_index(v.data(), v.data() + v.size());
  REQUIRE(cells.size() == 65537);
  CHECK(cells[0] == 0);
  CHECK(cells[1] == 2);
  CHECK(cells[0x0102] == 2);
  CHECK(cells[0x0103] == 4);
  CHECK(cells[0xFFFF] == 4);
  CHECK(cells[0x10000] == 5);
  check_cell_index(cells, v.data(), v.data() + v.size());
}

TEST_CASE("make_tlsh_cell_index_example_data") {
  std::vector<TlshDigest> v;
  for (const auto& hex: read_example_digests()) {
    v.push_back(digest_of(hex));
  }
  std::sort(v.begin(), v.end());
  check_cell_index(make_tlsh_cell_index(v.data(), v.data() + v.size()), v.data(), v.data() + v.size());
}

TEST_CASE("length_hint_tlsh") {
  CHECK(length_hint_data(SFHASH_TLSH) == 2 + 65537 * 8);
  CHECK(length_hint(SFHASH_TLSH) == 12 + 2 + 65537 * 8);
  // everything else is unchanged
  CHECK(length_hint_data(SFHASH_MD5) == 4098);
  CHECK(length_hint(SFHASH_SHA_1) == 4110);
}

TEST_CASE("write_tlsh_hint_data") {
  std::vector<uint64_t> cells(65537);
  for (size_t i = 0; i < cells.size(); ++i) {
    cells[i] = i * 3;
  }

  std::vector<char> buf(length_hint_data(SFHASH_TLSH));
  REQUIRE(write_tlsh_hint_data(cells, buf.data()) == buf.size());

  // hint type, big-endian
  CHECK(static_cast<uint8_t>(buf[0]) == 0x74);
  CHECK(static_cast<uint8_t>(buf[1]) == 0x00);

  // offsets, little-endian
  const char* cur = buf.data() + 2;
  for (size_t i = 0; i < cells.size(); ++i) {
    uint64_t v;
    std::memcpy(&v, cur, 8);
    cur += 8;
    CHECK(v == cells[i]);
  }
}

TEST_CASE("parse_hint_tlsh") {
  std::vector<uint8_t> data(2 + 65537 * 8, 0);
  data[0] = 0x74;
  data[1] = 0x00;

  const Chunk ch{ Chunk::HINT, data.data(), data.data() + data.size() };
  const auto hnt = parse_hint(ch);
  CHECK(hnt.hint_type == 0x7400);
  CHECK(hnt.beg == data.data() + 2);
  CHECK(hnt.end == data.data() + data.size());
}

namespace {

template <size_t N>
struct DispatchProbe {
  size_t operator()() const { return N; }
};

} // namespace

TEST_CASE("hashset_dispatcher_36") {
  // dispatches for the TLSH digest length
  CHECK(hashset_dispatcher<DispatchProbe>(36) == 36);
  CHECK(hashset_dispatcher<DispatchProbe>(32) == 32);
}

TEST_CASE("tlsh_text_converter") {
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_TLSH };
  const auto conv = make_text_converters(htypes);
  REQUIRE(conv.size() == 1);
  CHECK(conv[0].second == 36);

  const auto digests = read_example_digests();
  TlshDigest exp = digest_of(digests[0]);

  TlshDigest got;
  // with T1 prefix
  conv[0].first(reinterpret_cast<uint8_t*>(&got), digests[0].c_str(), 36);
  CHECK(got == exp);

  // without T1 prefix
  conv[0].first(reinterpret_cast<uint8_t*>(&got), digests[0].c_str() + 2, 36);
  CHECK(got == exp);

  // followed by a space, as in a multi-column line
  const std::string line = digests[0] + " deadbeef";
  conv[0].first(reinterpret_cast<uint8_t*>(&got), line.c_str(), 36);
  CHECK(got == exp);

  // garbage
  CHECK_THROWS(conv[0].first(reinterpret_cast<uint8_t*>(&got), "T1xyz", 36));
  CHECK_THROWS(conv[0].first(reinterpret_cast<uint8_t*>(&got), digests[0].substr(0, 40).c_str(), 36));
  CHECK_THROWS(conv[0].first(reinterpret_cast<uint8_t*>(&got), "", 36));
}

TEST_CASE("hset_tlsh_bad_digest_throws") {
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5, SFHASH_TLSH };
  std::istringstream in(fake_md5(0) + " T1notatlsh\n");
  CHECK_THROWS(
    write_hset(
      in, htypes, make_text_converters(htypes),
      "bad", "bad", "test/tlsh_bad.hset", "test", true, true
    )
  );
}

TEST_CASE("hset_tlsh_round_trip_records_and_hashsets") {
  for (const bool tlsh_first: { false, true }) {
    const Fixture f = make_fixture(tlsh_first);

    const std::vector<SFHASH_HashAlgorithm> htypes = tlsh_first ?
      std::vector<SFHASH_HashAlgorithm>{ SFHASH_TLSH, SFHASH_MD5 } :
      std::vector<SFHASH_HashAlgorithm>{ SFHASH_MD5, SFHASH_TLSH };

    auto [buf, hset] = build_and_load(
      f.text, htypes,
      tlsh_first ? "test/tlsh_md5.hset" : "test/md5_tlsh.hset",
      true, true
    );

    // index for type
    const int tidx = sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH);
    REQUIRE(tidx == (tlsh_first ? 0 : 1));
    const int midx = sfhash_hashset_index_for_type(hset.get(), SFHASH_MD5);
    REQUIRE(midx == (tlsh_first ? 1 : 0));

    // counts: duplicates are separate rows, TNULL and empty are not rows
    CHECK(sfhash_hashset_count(hset.get(), tidx) == f.tlsh_rows);
    CHECK(sfhash_hashset_count(hset.get(), midx) == f.records);
    CHECK(hset->holder.rhdr.record_count == f.records);

    // hint is the cell index
    const auto cells = cells_of(hset.get(), tidx);
    const TlshDigest* beg = rows_of(hset.get(), tidx);
    const TlshDigest* end = beg + f.tlsh_rows;
    check_cell_index(cells, beg, end);

    // rows are sorted, no nulls
    for (const TlshDigest* d = beg; d != end; ++d) {
      CHECK(!d->is_null());
      if (d != beg) {
        CHECK(!(*d < *(d - 1)));
      }
    }

    // the duplicated digest appears twice
    const TlshDigest dup = digest_of(f.digests[7]);
    CHECK(std::count(beg, end, dup) == 2);

    // sfhash_hashset_hash returns rows in order
    for (size_t i = 0; i < f.tlsh_rows; ++i) {
      CHECK(sfhash_hashset_hash(hset.get(), tidx, i) == beg + i);
    }

    // lookup: every digest present
    for (const auto& hex: f.digests) {
      const TlshDigest d = digest_of(hex);
      CHECK(sfhash_hashset_lookup(hset.get(), tidx, &d));
    }

    // lookup: perturbed digests absent
    for (const auto& hex: f.digests) {
      TlshDigest d = digest_of(hex);
      d.lo[5] ^= 0x10;
      CHECK(!sfhash_hashset_lookup(hset.get(), tidx, &d));
      d = digest_of(hex);
      d.L ^= 0x01; // moves to a different cell
      CHECK(!sfhash_hashset_lookup(hset.get(), tidx, &d));
      d = digest_of(hex);
      d.checksum ^= 0x80;
      CHECK(!sfhash_hashset_lookup(hset.get(), tidx, &d));
    }

    // null digest is never present
    const TlshDigest null{};
    CHECK(!sfhash_hashset_lookup(hset.get(), tidx, &null));

    // record for each TLSH row contains that row and a matching md5
    const int toff = sfhash_hashset_record_field_index_for_type(hset.get(), SFHASH_TLSH);
    const int moff = sfhash_hashset_record_field_index_for_type(hset.get(), SFHASH_MD5);
    REQUIRE(toff >= 0);
    REQUIRE(moff >= 0);

    std::set<std::string> md5s_seen_for_dup;

    for (size_t i = 0; i < f.tlsh_rows; ++i) {
      const auto* rec = sfhash_hashset_record_for_hash(hset.get(), tidx, i);
      const uint8_t* tf = static_cast<const uint8_t*>(sfhash_hashset_record_field(rec, toff));
      const uint8_t* mf = static_cast<const uint8_t*>(sfhash_hashset_record_field(rec, moff));

      REQUIRE(tf[0] == 0x01);
      REQUIRE(mf[0] == 0x01);
      CHECK(!std::memcmp(tf + 1, beg + i, 36));

      const std::string hex = tlsh_to_hex(beg[i]);
      const std::string md5 = to_hex(mf + 1, mf + 17);
      const auto it = f.md5s_for.find(hex);
      REQUIRE(it != f.md5s_for.end());
      CHECK(it->second.count(md5) == 1);

      if (beg[i] == dup) {
        md5s_seen_for_dup.insert(md5);
      }
    }

    // the two duplicate rows map to two different records
    CHECK(md5s_seen_for_dup.size() == 2);

    // the lookup strategy is the TLSH one
    const auto& ls = std::get<std::unique_ptr<LookupStrategy>>(hset->holder.hsets[tidx]);
    const auto* tls = dynamic_cast<const TlshLookupStrategy*>(ls.get());
    REQUIRE(tls);
    CHECK(tls->begin() == beg);
    CHECK(tls->end() == end);
    REQUIRE(tls->cells());
    CHECK(tls->cells()[0] == 0);
    CHECK(tls->cells()[65536] == f.tlsh_rows);
  }
}

TEST_CASE("hset_tlsh_hashsets_only") {
  const Fixture f = make_fixture(false);
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5, SFHASH_TLSH };

  auto [buf, hset] = build_and_load(f.text, htypes, "test/md5_tlsh_ho.hset", false, true);

  const int tidx = sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH);
  REQUIRE(tidx == 1);

  // hashsets-only files are deduplicated
  CHECK(sfhash_hashset_count(hset.get(), tidx) == f.unique_tlsh);
  CHECK(hset->holder.rhdr.record_count == 0);
  CHECK(hset->holder.rdat.beg == nullptr);

  const TlshDigest* beg = rows_of(hset.get(), tidx);
  const TlshDigest* end = beg + f.unique_tlsh;
  check_cell_index(cells_of(hset.get(), tidx), beg, end);

  for (const TlshDigest* d = beg + 1; d != end; ++d) {
    CHECK(*(d - 1) < *d);
  }

  for (const auto& hex: f.digests) {
    const TlshDigest d = digest_of(hex);
    CHECK(sfhash_hashset_lookup(hset.get(), tidx, &d));
  }

  TlshDigest d = digest_of(f.digests[3]);
  d.hi[0] ^= 0x01;
  CHECK(!sfhash_hashset_lookup(hset.get(), tidx, &d));
}

TEST_CASE("hset_tlsh_records_only") {
  const Fixture f = make_fixture(false);
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5, SFHASH_TLSH };

  auto [buf, hset] = build_and_load(f.text, htypes, "test/md5_tlsh_ro.hset", true, false);

  CHECK(sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH) == -1);
  CHECK(hset->holder.hsets.empty());
  CHECK(hset->holder.rhdr.record_count == f.records);
  REQUIRE(hset->holder.rhdr.fields.size() == 2);
  CHECK(hset->holder.rhdr.fields[1].type == SFHASH_TLSH);
  CHECK(hset->holder.rhdr.fields[1].name == "tlsh");
  CHECK(hset->holder.rhdr.fields[1].length == 36);
  CHECK(hset->holder.rhdr.record_length == 1 + 16 + 1 + 36);

  // the TNULL and empty records have the TLSH field absent
  const int toff = sfhash_hashset_record_field_index_for_type(hset.get(), SFHASH_TLSH);
  REQUIRE(toff >= 0);
  size_t absent = 0;
  const uint8_t* r = hset->holder.rdat.beg;
  for (size_t i = 0; i < f.records; ++i, r += hset->holder.rhdr.record_length) {
    if (r[toff] == 0) {
      ++absent;
      CHECK(std::all_of(r + toff + 1, r + toff + 1 + 36, [](uint8_t b) { return b == 0; }));
    }
  }
  CHECK(absent == 2);
}

TEST_CASE("hset_tlsh_basic_fallback_without_hint") {
  // A TLSH hashset decoded without a hint still works via the basic strategy
  std::vector<TlshDigest> v;
  for (const auto& hex: read_example_digests()) {
    v.push_back(digest_of(hex));
  }
  std::sort(v.begin(), v.end());

  const HashsetHeader hsh{ SFHASH_TLSH, "tlsh", 36, v.size() };
  const HashsetHint hnt{ 0, nullptr, nullptr };
  const ConstHashsetData hsd{ v.data(), v.data() + v.size() };

  const auto ls = make_lookup_strategy(hsh, hnt, hsd);
  REQUIRE(ls);
  CHECK(!dynamic_cast<const TlshLookupStrategy*>(ls.get()));
  for (const auto& d: v) {
    CHECK(ls->contains(reinterpret_cast<const uint8_t*>(&d)));
  }
  TlshDigest d = v[0];
  d.checksum ^= 0x01;
  CHECK(!ls->contains(reinterpret_cast<const uint8_t*>(&d)));
}

TEST_CASE("tlsh_lookup_strategy_null_cells") {
  std::vector<TlshDigest> v;
  for (const auto& hex: read_example_digests()) {
    v.push_back(digest_of(hex));
  }
  std::sort(v.begin(), v.end());

  const TlshLookupStrategy ls(v.data(), v.data() + v.size(), nullptr);
  CHECK(ls.cells() == nullptr);
  for (const auto& d: v) {
    CHECK(ls.contains(reinterpret_cast<const uint8_t*>(&d)));
  }
  TlshDigest d = v[0];
  d.lo[0] ^= 0x01;
  CHECK(!ls.contains(reinterpret_cast<const uint8_t*>(&d)));
}

TEST_CASE("tlsh_lookup_strategy_unaligned_cells") {
  std::vector<TlshDigest> v;
  for (const auto& hex: read_example_digests()) {
    v.push_back(digest_of(hex));
  }
  std::sort(v.begin(), v.end());

  const auto cells = make_tlsh_cell_index(v.data(), v.data() + v.size());

  // place the cells at an odd offset, as in a mapped HINT payload
  std::vector<uint8_t> raw(2 + 65537 * 8 + 8);
  for (size_t shift = 0; shift < 8; ++shift) {
    std::memcpy(raw.data() + shift, cells.data(), 65537 * 8);
    const TlshLookupStrategy ls(v.data(), v.data() + v.size(), raw.data() + shift);
    REQUIRE(ls.cells());
    CHECK(ls.cells()[0] == 0);
    CHECK(ls.cells()[65536] == v.size());
    for (const auto& d: v) {
      CHECK(ls.contains(reinterpret_cast<const uint8_t*>(&d)));
    }
    TlshDigest d = v[1];
    d.hi[3] ^= 0x40;
    CHECK(!ls.contains(reinterpret_cast<const uint8_t*>(&d)));
  }
}

TEST_CASE("tlsh_knn_brute_matches_naive_and_reference") {
  const Fixture f = make_fixture(false);
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5, SFHASH_TLSH };

  auto [buf, hset] = build_and_load(f.text, htypes, "test/md5_tlsh_knn.hset", true, true);

  const int tidx = sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH);
  REQUIRE(tidx == 1);
  const TlshDigest* beg = rows_of(hset.get(), tidx);
  const TlshDigest* end = beg + f.tlsh_rows;

  // reference objects for every row; Tlsh's copy constructor is shallow
  std::vector<std::unique_ptr<Tlsh>> ref;
  for (const TlshDigest* d = beg; d != end; ++d) {
    ref.emplace_back(new Tlsh());
    REQUIRE(ref.back()->fromTlshStr(tlsh_to_hex(*d).c_str()) == 0);
  }

  // queries: some members, a perturbed member, and a far-away digest
  std::vector<TlshDigest> queries;
  for (const size_t i: { 0u, 7u, 13u, 42u, 79u }) {
    queries.push_back(digest_of(f.digests[i]));
  }
  {
    TlshDigest q = digest_of(f.digests[20]);
    q.lo[2] ^= 0x33;
    q.hi[9] ^= 0x81;
    queries.push_back(q);
  }
  {
    TlshDigest q = digest_of(f.digests[50]);
    q.L = static_cast<uint8_t>(q.L + 100);
    q.Q ^= 0x77;
    queries.push_back(q);
  }

  const size_t ks[] = { 0, 1, 2, 5, 10, f.tlsh_rows, f.tlsh_rows + 50 };
  const uint32_t maxds[] = { 0, 1, 30, 100, 200, std::numeric_limits<uint32_t>::max() };

  for (const auto& q: queries) {
    std::unique_ptr<Tlsh> rq(new Tlsh());
    REQUIRE(rq->fromTlshStr(tlsh_to_hex(q).c_str()) == 0);

    for (const bool include_length: { true, false }) {
      for (const size_t k: ks) {
        for (const uint32_t maxd: maxds) {
          const auto exp = naive_knn(beg, end, q, k, maxd, include_length);

          // C++ API
          const auto got = tlsh_knn_brute(beg, end, q, k, maxd, include_length);
          CHECK(same_matches(got, exp));

          // C API, explicit brute force
          std::vector<SFHASH_TlshMatch> out(k + 1);
          const size_t n = sfhash_hashset_tlsh_knn_with(
            hset.get(), tidx, &q, k, maxd, include_length, SFHASH_TLSH_KNN_BRUTE, out.data()
          );
          REQUIRE(n <= k);
          out.resize(n);
          CHECK(same_matches(out, exp));

          // C API, default strategy: the file has a TIVF index, which is
          // exact up to distance 144 when the length is included
          {
            const uint32_t clamped = include_length ? std::min(maxd, 144u) : maxd;
            std::vector<SFHASH_TlshMatch> aout(k + 1);
            const size_t an = sfhash_hashset_tlsh_knn(
              hset.get(), tidx, &q, k, maxd, include_length, aout.data()
            );
            REQUIRE(an <= k);
            aout.resize(an);
            CHECK(same_matches(aout, naive_knn(beg, end, q, k, clamped, include_length)));
          }

          // results agree with the reference implementation
          for (const auto& m: out) {
            REQUIRE(m.index < f.tlsh_rows);
            CHECK(
              static_cast<int>(m.distance) ==
              rq->totalDiff(ref[m.index].get(), include_length)
            );
            CHECK(m.distance <= maxd);
          }

          // nearest first, ties by index
          for (size_t i = 1; i < out.size(); ++i) {
            CHECK(
              std::tie(out[i - 1].distance, out[i - 1].index) <
              std::tie(out[i].distance, out[i].index)
            );
          }
        }
      }
    }
  }

  // a member query finds itself (and its duplicate, for the duplicated digest) at distance 0
  {
    const TlshDigest q = digest_of(f.digests[7]);
    SFHASH_TlshMatch out[3];
    const size_t n = sfhash_hashset_tlsh_knn(hset.get(), tidx, &q, 3, 0, true, out);
    REQUIRE(n == 2);
    CHECK(out[0].distance == 0);
    CHECK(out[1].distance == 0);
    CHECK(out[0].index + 1 == out[1].index);
    CHECK(*static_cast<const TlshDigest*>(sfhash_hashset_hash(hset.get(), tidx, out[0].index)) == q);
    CHECK(*static_cast<const TlshDigest*>(sfhash_hashset_hash(hset.get(), tidx, out[1].index)) == q);
  }
}

TEST_CASE("tlsh_knn_degenerate") {
  const Fixture f = make_fixture(false);
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_MD5, SFHASH_TLSH };

  auto [buf, hset] = build_and_load(f.text, htypes, "test/md5_tlsh_knn.hset", true, true);

  const int tidx = sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH);
  const int midx = sfhash_hashset_index_for_type(hset.get(), SFHASH_MD5);
  REQUIRE(tidx == 1);
  REQUIRE(midx == 0);

  const TlshDigest q = digest_of(f.digests[0]);
  SFHASH_TlshMatch out[8];

  // non-TLSH hashset
  CHECK(sfhash_hashset_tlsh_knn(hset.get(), midx, &q, 8, 1000, true, out) == 0);

  // null pointer
  CHECK(sfhash_hashset_tlsh_knn(hset.get(), tidx, nullptr, 8, 1000, true, out) == 0);

  // null digest
  const TlshDigest null{};
  CHECK(sfhash_hashset_tlsh_knn(hset.get(), tidx, &null, 8, 1000, true, out) == 0);

  // k == 0
  CHECK(sfhash_hashset_tlsh_knn(hset.get(), tidx, &q, 0, 1000, true, out) == 0);

  // empty range
  CHECK(tlsh_knn_brute(nullptr, nullptr, q, 5, 1000, true).empty());
}
