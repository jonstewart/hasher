#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "helper.h"
#include "util.h"
#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hasher/hasher.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_decoder.h"
#include "hashset/hset_decoder_chunks.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_merge.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

/*
 * Merge-based set operations: the output of sfhash_hashset_merge is checked
 * against the set operation computed independently over the inputs' rows
 * (hashsets-only) or records, and every derived TLSH structure carried
 * through the merge is validated against the output rows.
 */

namespace {

constexpr uint32_t BOTH = SFHASH_HSET_TLSH_VECTORS | SFHASH_HSET_TLSH_INDEX;
constexpr uint32_t NONE = 0;
constexpr uint32_t INHERIT = SFHASH_HSET_TLSH_INHERIT;

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

struct Loaded {
  std::vector<char> buf;
  HsetPtr hset{ nullptr, sfhash_destroy_hashset };
  TableOfContents toc;

  const SFHASH_Hashset* get() const { return hset.get(); }
};

TableOfContents ftoc_of(const std::vector<char>& buf) {
  const uint8_t* beg = reinterpret_cast<const uint8_t*>(buf.data());
  const uint8_t* end = beg + buf.size();
  const uint8_t* cur = beg + 8 + 32; // magic, hset hash
  const Chunk ch = decode_chunk(beg, cur, end);
  REQUIRE(ch.type == Chunk::FTOC);
  return parse_ftoc(ch);
}

Loaded load_file(const std::string& path) {
  Loaded l;
  l.buf = read_file(path);
  SFHASH_Error* err = nullptr;
  l.hset.reset(sfhash_load_hashset(l.buf.data(), l.buf.data() + l.buf.size(), &err));
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(l.hset);
  l.toc = ftoc_of(l.buf);
  return l;
}

const std::vector<TlshDigest>& corpus() {
  static const std::vector<TlshDigest> c = make_tlsh_corpus(31, 9000);
  return c;
}

// a distinct, deterministic hex "hash" of 2 * bytes chars per corpus index
std::string fake_hex(size_t i, size_t bytes) {
  std::ostringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t b = 0; b < bytes; b += 8) {
    ss << std::setw(16) << ((i + 1) * 0x9E3779B97F4A7C15ULL + b * 0xBF58476D1CE4E5B9ULL);
  }
  return ss.str().substr(0, 2 * bytes);
}

// writes an hset of the corpus rows [beg, end) with the given field types
// (TLSH plus hex hashes), as records + hashsets or hashsets only
Loaded build_input(
  const std::string& path,
  const std::vector<TlshDigest>& c,
  size_t beg,
  size_t end,
  const std::vector<SFHASH_HashAlgorithm>& htypes,
  bool with_records,
  bool with_hashsets,
  uint32_t opts)
{
  std::ostringstream text;
  for (size_t i = beg; i < end; ++i) {
    for (size_t f = 0; f < htypes.size(); ++f) {
      if (f) {
        text << ' ';
      }
      switch (htypes[f]) {
      case SFHASH_TLSH:
        text << tlsh_to_hex(c[i]);
        break;
      case SFHASH_MD5:
        text << fake_hex(i, 16);
        break;
      case SFHASH_SHA_1:
        text << fake_hex(i, 20);
        break;
      default:
        FAIL("unexpected type");
      }
    }
    text << '\n';
  }

  std::istringstream in(text.str());
  write_hset(
    in, htypes, make_text_converters(htypes),
    "input", "merge test input", path, "test",
    with_records, with_hashsets, opts
  );
  return load_file(path);
}

Loaded build_input(const std::string& path, size_t beg, size_t end, bool with_records, uint32_t opts) {
  return build_input(path, corpus(), beg, end, { SFHASH_MD5, SFHASH_TLSH }, with_records, true, opts);
}

Loaded merge(const Loaded& l, const Loaded& r, uint32_t op, const std::string& path, uint32_t opts) {
  SFHASH_Error* err = nullptr;
  const uint64_t size = sfhash_hashset_merge(
    l.get(), r.get(), op, "merged", "merge test output", path.c_str(), opts, SFHASH_HSET_COALESCE_DEFAULT, &err
  );
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(size > 0);
  Loaded o = load_file(path);
  REQUIRE(o.buf.size() == size);
  return o;
}

//
// independent computation of the expected output
//

using Rows = std::vector<std::string>; // sorted byte strings

Rows rows_of(const SFHASH_Hashset* hset, SFHASH_HashAlgorithm type) {
  Rows rows;
  const int tidx = sfhash_hashset_index_for_type(hset, type);
  if (tidx < 0) {
    return rows;
  }
  const auto& hhdr = std::get<HashsetHeader>(hset->holder.hsets[tidx]);
  const auto& hdat = std::get<ConstHashsetData>(hset->holder.hsets[tidx]);
  const char* p = static_cast<const char*>(hdat.beg);
  for (uint64_t i = 0; i < hhdr.hash_count; ++i) {
    rows.emplace_back(p + i * hhdr.hash_length, hhdr.hash_length);
  }
  return rows;
}

Rows set_op(uint32_t op, const Rows& a, const Rows& b) {
  Rows out;
  switch (op) {
  case SFHASH_HSET_OP_UNION:
    std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    break;
  case SFHASH_HSET_OP_INTERSECT:
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    break;
  case SFHASH_HSET_OP_DIFFERENCE:
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    break;
  default:
    FAIL("bad op");
  }
  return out;
}

Rows unique_rows(Rows rows) {
  std::sort(rows.begin(), rows.end());
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  return rows;
}

// the output fields of merging two record tables: left's, then right's extras
std::vector<RecordFieldDescriptor> expected_fields(const RecordHeader& l, const RecordHeader& r) {
  std::vector<RecordFieldDescriptor> f = l.fields;
  for (const auto& rf: r.fields) {
    if (std::none_of(f.begin(), f.end(), [&](const auto& x) { return x.type == rf.type; })) {
      f.push_back(rf);
    }
  }
  return f;
}

// records of hset rewritten to the given fields, as byte strings
Rows widened_records(const SFHASH_Hashset* hset, const std::vector<RecordFieldDescriptor>& fields) {
  const auto& rhdr = hset->holder.rhdr;
  const auto& rdat = hset->holder.rdat;
  Rows out;
  for (const uint8_t* rec = rdat.beg; rec < rdat.end; rec += rhdr.record_length) {
    std::string w;
    for (const auto& f: fields) {
      const int off = sfhash_hashset_record_field_index_for_type(hset, static_cast<SFHASH_HashAlgorithm>(f.type));
      if (off < 0) {
        w.append(1 + f.length, '\0');
      }
      else {
        w.append(reinterpret_cast<const char*>(rec) + off, 1 + f.length);
      }
    }
    out.push_back(std::move(w));
  }
  return out;
}

// the rows of the field in sorted records (presence byte 1), as a sorted multiset
Rows rows_from_records(const Rows& records, const std::vector<RecordFieldDescriptor>& fields, uint32_t type) {
  size_t off = 0;
  size_t len = 0;
  bool found = false;
  for (const auto& f: fields) {
    if (f.type == type) {
      len = f.length;
      found = true;
      break;
    }
    off += 1 + f.length;
  }
  Rows out;
  if (!found) {
    return out;
  }
  for (const auto& r: records) {
    if (r[off] == 1) {
      out.push_back(r.substr(off + 1, len));
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

struct Expected {
  bool records = false;
  std::vector<RecordFieldDescriptor> fields;
  Rows recs;                                   // widened, sorted, unique
  std::vector<std::pair<uint32_t, Rows>> rows; // per output type
};

Expected expected_output(const Loaded& l, const Loaded& r, uint32_t op) {
  Expected e;
  const Holder& lh = l.get()->holder;
  const Holder& rh = r.get()->holder;
  e.records = !lh.rhdr.fields.empty() && !rh.rhdr.fields.empty();

  // output types: left's sections, then right's extras
  std::vector<uint32_t> types;
  for (const Holder* h: { &lh, &rh }) {
    for (const auto& hs: h->hsets) {
      const uint32_t t = std::get<HashsetHeader>(hs).hash_type;
      if (std::find(types.begin(), types.end(), t) == types.end()) {
        types.push_back(t);
      }
    }
  }

  if (e.records) {
    e.fields = expected_fields(lh.rhdr, rh.rhdr);
    const Rows lr = unique_rows(widened_records(l.get(), e.fields));
    const Rows rr = unique_rows(widened_records(r.get(), e.fields));
    e.recs = set_op(op, lr, rr);
    if (!types.empty()) {
      // records-only inputs give a records-only output
      for (const auto& f: e.fields) {
        e.rows.emplace_back(f.type, rows_from_records(e.recs, e.fields, f.type));
      }
    }
  }
  else {
    for (const uint32_t t: types) {
      const auto ht = static_cast<SFHASH_HashAlgorithm>(t);
      e.rows.emplace_back(t, set_op(op, unique_rows(rows_of(l.get(), ht)), unique_rows(rows_of(r.get(), ht))));
    }
  }
  return e;
}

//
// output validation
//

size_t count_type(const TableOfContents& toc, uint32_t type) {
  return std::count_if(toc.entries.begin(), toc.entries.end(), [type](const auto& e) { return e.second == type; });
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

std::vector<SFHASH_TlshMatch> knn_with(const SFHASH_Hashset* hset, size_t tidx, const TlshDigest& q, size_t k, uint32_t maxd, bool incl, uint32_t strategy) {
  std::vector<SFHASH_TlshMatch> out(k + 1);
  const size_t n = sfhash_hashset_tlsh_knn_with(hset, tidx, &q, k, maxd, incl, strategy, out.data());
  REQUIRE(n <= k);
  out.resize(n);
  return out;
}

// whether the inputs' TLSH sections both have an index, so that the output
// index is merged (and coalesced) rather than built from scratch
bool has_index(const Loaded& x) {
  const int tidx = sfhash_hashset_index_for_type(x.get(), SFHASH_TLSH);
  return tidx < 0 || !std::get<TlshIvfView>(x.get()->holder.hsets[tidx]).empty();
}

void check_tlsh_section(const Loaded& o, size_t tidx, bool want_vec, bool want_idx, bool merged_index) {
  const SFHASH_Hashset* hset = o.get();
  const auto& hs = hset->holder.hsets[tidx];
  const uint64_t n = std::get<HashsetHeader>(hs).hash_count;
  const TlshDigest* rows = static_cast<const TlshDigest*>(std::get<ConstHashsetData>(hs).beg);

  // cell index: the 0x7400 hint equals the prefix sums over the rows
  {
    const auto& hnt = std::get<HashsetHint>(hs);
    REQUIRE(hnt.hint_type == TLSH_CELL_HINT_TYPE);
    std::vector<uint64_t> cells(TLSH_CELL_COUNT + 1);
    REQUIRE(static_cast<size_t>(static_cast<const uint8_t*>(hnt.end) - static_cast<const uint8_t*>(hnt.beg)) == cells.size() * 8);
    std::memcpy(cells.data(), hnt.beg, cells.size() * 8);
    CHECK(cells == make_tlsh_cell_index(rows, rows + n));
    for (uint64_t i = 0; i < n; ++i) {
      CHECK(sfhash_hashset_lookup(hset, tidx, rows + i));
    }
  }

  // vectors
  const auto& tv = std::get<ConstTlshVectors>(hs);
  CHECK(count_type(o.toc, Chunk::TVEC) == (want_vec ? 1u : 0u));
  if (want_vec) {
    REQUIRE(tv.data);
    CHECK(tv.n == n);
    CHECK(tv.dims == TLSH_EMBED_DIMS);
    const ptrdiff_t off = reinterpret_cast<const char*>(tv.data) - o.buf.data();
    CHECK(off % 4096 == 0);
    float exp[TLSH_EMBED_DIMS];
    for (uint64_t r = 0; r < n; ++r) {
      tlsh_embed(rows[r], exp);
      REQUIRE(std::memcmp(exp, tv.data + r * TLSH_EMBED_DIMS, sizeof(exp)) == 0);
    }
  }
  else {
    CHECK(!tv.data);
  }

  // index
  const auto& ivf = std::get<TlshIvfView>(hs);
  CHECK(count_type(o.toc, Chunk::TIVF) == (want_idx ? 1u : 0u));
  if (want_idx) {
    REQUIRE(!ivf.empty());
    CHECK(ivf.n == n);
    REQUIRE(ivf.cell_lists[0] == 0);
    REQUIRE(ivf.cell_lists[TLSH_CELL_COUNT] == ivf.lists);
    REQUIRE(ivf.list_start[0] == 0);
    REQUIRE(ivf.list_start[ivf.lists] == n);

    // every id exactly once
    std::vector<uint32_t> ids(ivf.ids, ivf.ids + n);
    std::sort(ids.begin(), ids.end());
    for (size_t i = 0; i < ids.size(); ++i) {
      REQUIRE(ids[i] == i);
    }

    // lists: nonempty, ascending, inside their cell, within radius of the medoid
    for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
      REQUIRE(ivf.cell_lists[c] <= ivf.cell_lists[c + 1]);
      for (uint32_t l = ivf.cell_lists[c]; l < ivf.cell_lists[c + 1]; ++l) {
        const uint64_t lb = ivf.list_start[l], le = ivf.list_start[l + 1];
        REQUIRE(lb < le);
        uint32_t tight = 0;
        for (uint64_t i = lb; i < le; ++i) {
          if (i > lb) {
            REQUIRE(ivf.ids[i - 1] < ivf.ids[i]);
          }
          REQUIRE(ivf.ids[i] < n);
          REQUIRE(tlsh_cell_id(rows[ivf.ids[i]]) == c);
          REQUIRE(tlsh_embed_body_dist2(ivf.medoids[l], rows[ivf.ids[i]]) <= ivf.radius2[l]);
          tight = std::max(tight, tlsh_embed_body_dist2(ivf.medoids[l], rows[ivf.ids[i]]));
        }
        // radii are exact: a fresh build computes them, a merge recomputes
        // the radius of a list that lost members and of a coalesced pair
        CHECK(ivf.radius2[l] == tight);
      }
    }
    // a merged index is coalesced at TLSH_IVF_DEFAULT_COALESCE; a fresh
    // build need not satisfy the invariant at that threshold (BISECT
    // coalesces at T, KMEANS list sizes are whatever the clustering gives)
    if (merged_index) {
      CHECK(tlsh_ivf_check_invariant(ivf, TLSH_IVF_DEFAULT_COALESCE));
    }

    // search: index == brute == index over a from-scratch rebuild
    CHECK(sfhash_hashset_tlsh_knn_strategies(hset, tidx) == (SFHASH_TLSH_KNN_BRUTE | SFHASH_TLSH_KNN_INDEX));
    const TlshIvf fresh = build_tlsh_ivf(rows, rows + n, TLSH_IVF_TARGET_LIST_SIZE);
    const TlshIvfView fresh_view = make_tlsh_ivf_view(fresh);
    const std::vector<TlshDigest> seeds(rows, rows + n);
    const auto queries = n ? perturb_tlsh_corpus(77, seeds, 30, 0.03) : std::vector<TlshDigest>();
    for (const auto& q: queries) {
      for (const size_t k: { 1u, 10u, 50u }) {
        for (const uint32_t maxd: { 30u, 144u, 1000u }) {
          for (const bool incl: { true, false }) {
            const auto brute = knn_with(hset, tidx, q, k, maxd, incl, SFHASH_TLSH_KNN_BRUTE);
            const auto index = knn_with(hset, tidx, q, k, maxd, incl, SFHASH_TLSH_KNN_INDEX);
            const auto rebuilt = tlsh_knn_ivf(fresh_view, rows, q, k, maxd, incl);
            CHECK(same_matches(index, brute));
            CHECK(same_matches(rebuilt, brute));
          }
        }
      }
    }
  }
  else {
    CHECK(ivf.empty());
    CHECK(sfhash_hashset_tlsh_knn_strategies(hset, tidx) == SFHASH_TLSH_KNN_BRUTE);
  }
}

void check_output(const Loaded& o, const Loaded& l, const Loaded& r, uint32_t op, bool want_vec, bool want_idx) {
  const SFHASH_Hashset* hset = o.get();
  const Holder& h = hset->holder;
  const Expected e = expected_output(l, r, op);

  // FTOC offsets ascend and the file hash is right
  for (size_t i = 1; i < o.toc.entries.size(); ++i) {
    REQUIRE(o.toc.entries[i - 1].first < o.toc.entries[i].first);
  }
  {
    auto hasher = make_unique_del(sfhash_create_hasher(SFHASH_SHA_2_256), sfhash_destroy_hasher);
    sfhash_update_hasher(hasher.get(), o.buf.data() + 40, o.buf.data() + o.buf.size());
    SFHASH_HashValues hashes;
    sfhash_get_hashes(hasher.get(), &hashes);
    CHECK(std::memcmp(hashes.Sha2_256, sfhash_hashset_sha2_256(hset), 32) == 0);
  }
  CHECK(std::string(sfhash_hashset_name(hset)) == "merged");

  // sections: one per expected type, in order, with exactly the expected rows
  REQUIRE(h.hsets.size() == e.rows.size());
  for (size_t i = 0; i < e.rows.size(); ++i) {
    const auto& [type, exp] = e.rows[i];
    const auto& hhdr = std::get<HashsetHeader>(h.hsets[i]);
    CHECK(hhdr.hash_type == type);
    CHECK(hhdr.hash_count == exp.size());
    const Rows got = rows_of(hset, static_cast<SFHASH_HashAlgorithm>(type));
    REQUIRE(got == exp);
    REQUIRE(std::is_sorted(got.begin(), got.end()));
    if (!e.records) {
      CHECK(std::adjacent_find(got.begin(), got.end()) == got.end());
    }
    // every row is found
    for (const auto& row: exp) {
      CHECK(sfhash_hashset_lookup(hset, i, row.data()));
    }
  }

  // records
  CHECK(count_type(o.toc, Chunk::RHDR) == (e.records ? 1u : 0u));
  CHECK(count_type(o.toc, Chunk::RDAT) == (e.records ? 1u : 0u));
  CHECK(count_type(o.toc, Chunk::RIDX) == (e.records ? h.hsets.size() : 0u));
  if (e.records) {
    REQUIRE(h.rhdr.fields == e.fields);
    CHECK(h.rhdr.record_count == e.recs.size());
    Rows recs;
    for (const uint8_t* rec = h.rdat.beg; rec < h.rdat.end; rec += h.rhdr.record_length) {
      recs.emplace_back(reinterpret_cast<const char*>(rec), h.rhdr.record_length);
    }
    REQUIRE(recs == e.recs);

    // every RIDX entry names a record whose field equals the row
    for (size_t i = 0; i < h.hsets.size(); ++i) {
      const auto& hhdr = std::get<HashsetHeader>(h.hsets[i]);
      const auto& ridx = std::get<ConstRecordIndex>(h.hsets[i]);
      REQUIRE(ridx.beg);
      const int foff = sfhash_hashset_record_field_index_for_type(hset, static_cast<SFHASH_HashAlgorithm>(hhdr.hash_type));
      REQUIRE(foff >= 0);
      for (uint64_t k = 0; k < hhdr.hash_count; ++k) {
        uint64_t rec;
        std::memcpy(&rec, static_cast<const uint8_t*>(ridx.beg) + k * 8, 8);
        REQUIRE(rec < h.rhdr.record_count);
        const uint8_t* f = h.rdat.beg + rec * h.rhdr.record_length + foff;
        REQUIRE(f[0] == 1);
        REQUIRE(std::memcmp(f + 1, sfhash_hashset_hash(hset, i, k), hhdr.hash_length) == 0);
      }
    }
  }

  // TLSH derived structures
  const int tidx = sfhash_hashset_index_for_type(hset, SFHASH_TLSH);
  if (tidx >= 0) {
    check_tlsh_section(o, tidx, want_vec, want_idx, has_index(l) && has_index(r));
  }
  else {
    CHECK(count_type(o.toc, Chunk::TVEC) == 0);
    CHECK(count_type(o.toc, Chunk::TIVF) == 0);
  }
}

const uint32_t OPS[] = { SFHASH_HSET_OP_UNION, SFHASH_HSET_OP_INTERSECT, SFHASH_HSET_OP_DIFFERENCE };

// the input/option matrix of the two main test cases
void run_matrix(bool with_records) {
  const std::string tag = with_records ? "rec" : "ho";

  // overlapping halves of the corpus
  const auto a = [&](uint32_t opts) { return build_input("test/merge_a_" + tag + ".hset", 0, 6000, with_records, opts); };
  const auto b = [&](uint32_t opts) { return build_input("test/merge_b_" + tag + ".hset", 3000, 9000, with_records, opts); };

  struct Case {
    uint32_t aopts, bopts, merge_opts;
    bool want_vec, want_idx;
  };
  const Case cases[] = {
    { BOTH, BOTH, INHERIT, true, true },                            // both on, carried through
    { NONE, NONE, INHERIT, false, false },                          // both off
    { BOTH, SFHASH_HSET_TLSH_INDEX, INHERIT, false, true },         // b lacks vectors: index merged, no vectors
    { BOTH, SFHASH_HSET_TLSH_INDEX, BOTH, true, true },             // ... vectors embedded for b
    { BOTH, SFHASH_HSET_TLSH_VECTORS, INHERIT, true, false },       // b lacks index: vectors carried, no index
    { BOTH, SFHASH_HSET_TLSH_VECTORS, BOTH, true, true },           // ... index rebuilt from scratch
    { NONE, NONE, BOTH, true, true },                               // everything computed for the output
    { BOTH, BOTH, NONE, false, false },                             // everything dropped
  };

  for (const auto& c: cases) {
    const Loaded la = a(c.aopts);
    const Loaded lb = b(c.bopts);
    for (const uint32_t op: OPS) {
      const Loaded o = merge(la, lb, op, "test/merge_out_" + tag + ".hset", c.merge_opts);
      check_output(o, la, lb, op, c.want_vec, c.want_idx);
    }
  }
}

} // namespace

TEST_CASE("merge_rows_sets") {
  // 2-byte rows
  const uint8_t l[] = { 0,1, 0,3, 0,3, 0,5, 0,9 };
  const uint8_t r[] = { 0,3, 0,4, 0,9, 0,9, 1,0 };
  std::vector<uint32_t> lm, rm;

  REQUIRE(merge_rows(MergeOp::UNION, l, 5, r, 5, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 6);
  CHECK(lm == std::vector<uint32_t>{ 0, 1, MERGE_DROPPED, 3, 4 });
  CHECK(rm == std::vector<uint32_t>{ MERGE_DROPPED, 2, MERGE_DROPPED, MERGE_DROPPED, 5 });

  REQUIRE(merge_rows(MergeOp::INTERSECT, l, 5, r, 5, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 2);
  CHECK(lm == std::vector<uint32_t>{ MERGE_DROPPED, 0, MERGE_DROPPED, MERGE_DROPPED, 1 });
  CHECK(std::all_of(rm.begin(), rm.end(), [](uint32_t m) { return m == MERGE_DROPPED; }));

  REQUIRE(merge_rows(MergeOp::DIFFERENCE, l, 5, r, 5, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 2);
  CHECK(lm == std::vector<uint32_t>{ 0, MERGE_DROPPED, MERGE_DROPPED, 1, MERGE_DROPPED });
  CHECK(std::all_of(rm.begin(), rm.end(), [](uint32_t m) { return m == MERGE_DROPPED; }));

  // empty sides
  REQUIRE(merge_rows(MergeOp::UNION, l, 5, nullptr, 0, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 4);
  REQUIRE(merge_rows(MergeOp::INTERSECT, l, 5, nullptr, 0, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 0);
  REQUIRE(merge_rows(MergeOp::DIFFERENCE, nullptr, 0, r, 5, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 0);
  REQUIRE(merge_rows(MergeOp::UNION, nullptr, 0, r, 5, 2, nullptr, nullptr, nullptr, nullptr, lm, rm) == 4);
  CHECK(rm == std::vector<uint32_t>{ 0, 1, 2, MERGE_DROPPED, 3 });
}

TEST_CASE("merge_rows_records") {
  // rows owned by records: fates come from the record maps, equal rows stay
  const uint8_t l[] = { 0,1, 0,3, 0,3, 0,5 };
  const uint64_t lridx[] = { 0, 1, 2, 3 };
  const uint64_t lrecmap[] = { 0, MERGE_RECORD_DROPPED, 2, 3 };
  const uint8_t r[] = { 0,3, 0,4 };
  const uint64_t rridx[] = { 0, 1 };
  const uint64_t rrecmap[] = { 1, MERGE_RECORD_DROPPED };
  std::vector<uint32_t> lm, rm;

  REQUIRE(merge_rows(MergeOp::UNION, l, 4, r, 2, 2, lridx, lrecmap, rridx, rrecmap, lm, rm) == 4);
  // 0,1 (l0) 0,3 (l2) 0,3 (r0) 0,5 (l3): left before right on ties
  CHECK(lm == std::vector<uint32_t>{ 0, MERGE_DROPPED, 1, 3 });
  CHECK(rm == std::vector<uint32_t>{ 2, MERGE_DROPPED });
}

TEST_CASE("merge_tlsh_ivf_remaps_and_drops") {
  auto rows = make_tlsh_corpus(5, 3000);
  std::sort(rows.begin(), rows.end());
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  const auto ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), 16);
  const auto view = make_tlsh_ivf_view(ivf);

  // keep every other row; the kept rows are renumbered densely
  std::vector<uint32_t> map(rows.size(), TLSH_IVF_DROPPED);
  std::vector<TlshDigest> kept;
  for (size_t i = 0; i < rows.size(); i += 2) {
    map[i] = static_cast<uint32_t>(kept.size());
    kept.push_back(rows[i]);
  }

  const TlshIvf m = merge_tlsh_ivf(view, map.data(), TlshIvfView(), nullptr, kept.data(), kept.size());
  CHECK(m.n == kept.size());
  CHECK(m.ids.size() == kept.size());
  CHECK(m.lists() <= ivf.lists());
  CHECK(m.cell_lists.back() == m.lists());
  for (size_t l = 0; l < m.lists(); ++l) {
    REQUIRE(m.list_start[l] < m.list_start[l + 1]);
    for (uint64_t i = m.list_start[l]; i < m.list_start[l + 1]; ++i) {
      if (i > m.list_start[l]) {
        CHECK(m.ids[i - 1] < m.ids[i]);
      }
      CHECK(tlsh_embed_body_dist2(m.medoids[l], kept[m.ids[i]]) <= m.radius2[l]);
    }
  }

  // the merged index searches exactly
  const auto mv = make_tlsh_ivf_view(m);
  const auto queries = perturb_tlsh_corpus(6, kept, 20, 0.05);
  for (const auto& q: queries) {
    for (const uint32_t T: { 40u, 200u }) {
      CHECK(same_matches(
        tlsh_knn_ivf(mv, kept.data(), q, 10, T, true),
        tlsh_knn_brute(kept.data(), kept.data() + kept.size(), q, 10, T, true)
      ));
    }
  }

  // wrong maps are rejected: a row count that disagrees with the map, and a
  // map that is not increasing within a list
  CHECK_THROWS(merge_tlsh_ivf(view, map.data(), TlshIvfView(), nullptr, kept.data(), kept.size() + 1));
  for (size_t l = 0; l < ivf.lists(); ++l) {
    std::vector<uint32_t> kept_members;
    for (uint64_t i = ivf.list_start[l]; i < ivf.list_start[l + 1]; ++i) {
      if (map[ivf.ids[i]] != TLSH_IVF_DROPPED) {
        kept_members.push_back(ivf.ids[i]);
      }
    }
    if (kept_members.size() >= 2) {
      std::vector<uint32_t> bad(map);
      std::swap(bad[kept_members[0]], bad[kept_members[1]]);
      CHECK_THROWS(merge_tlsh_ivf(view, bad.data(), TlshIvfView(), nullptr, kept.data(), kept.size()));
      break;
    }
  }
}

TEST_CASE("hset_merge_hashsets_only") {
  run_matrix(false);
}

TEST_CASE("hset_merge_records") {
  run_matrix(true);
}

TEST_CASE("hset_merge_algebra") {
  for (const bool with_records: { false, true }) {
    const std::string tag = with_records ? "rec" : "ho";
    const Loaded a = build_input("test/merge_alg_a_" + tag + ".hset", 0, 6000, with_records, BOTH);
    const Loaded b = build_input("test/merge_alg_b_" + tag + ".hset", 3000, 9000, with_records, BOTH);

    // union is commutative
    const Loaded ab = merge(a, b, SFHASH_HSET_OP_UNION, "test/merge_alg_ab.hset", INHERIT);
    const Loaded ba = merge(b, a, SFHASH_HSET_OP_UNION, "test/merge_alg_ba.hset", INHERIT);
    for (const auto t: { SFHASH_MD5, SFHASH_TLSH }) {
      CHECK(rows_of(ab.get(), t) == rows_of(ba.get(), t));
    }
    CHECK(ab.get()->holder.rhdr.record_count == ba.get()->holder.rhdr.record_count);
    check_output(ba, b, a, SFHASH_HSET_OP_UNION, true, true);

    // a - a is empty
    const Loaded aa = merge(a, a, SFHASH_HSET_OP_DIFFERENCE, "test/merge_alg_a-a.hset", INHERIT);
    REQUIRE(aa.get()->holder.hsets.size() == 2);
    for (size_t i = 0; i < 2; ++i) {
      CHECK(sfhash_hashset_count(aa.get(), i) == 0);
    }
    CHECK(aa.get()->holder.rhdr.record_count == 0);
    check_output(aa, a, a, SFHASH_HSET_OP_DIFFERENCE, true, true);

    // a & a is a
    const Loaded ai = merge(a, a, SFHASH_HSET_OP_INTERSECT, "test/merge_alg_a&a.hset", INHERIT);
    for (const auto t: { SFHASH_MD5, SFHASH_TLSH }) {
      CHECK(rows_of(ai.get(), t) == rows_of(a.get(), t));
    }
    check_output(ai, a, a, SFHASH_HSET_OP_INTERSECT, true, true);

    // (a | b) - b == a - b
    const Loaded ab_b = merge(ab, b, SFHASH_HSET_OP_DIFFERENCE, "test/merge_alg_ab-b.hset", INHERIT);
    const Loaded a_b = merge(a, b, SFHASH_HSET_OP_DIFFERENCE, "test/merge_alg_a-b.hset", INHERIT);
    for (const auto t: { SFHASH_MD5, SFHASH_TLSH }) {
      CHECK(rows_of(ab_b.get(), t) == rows_of(a_b.get(), t));
    }
    check_output(ab_b, ab, b, SFHASH_HSET_OP_DIFFERENCE, true, true);
  }
}

TEST_CASE("hset_merge_records_differing_fields") {
  // left has md5 + tlsh, right sha1 + tlsh: records widen to md5, tlsh, sha1
  const Loaded a = build_input("test/merge_df_a.hset", corpus(), 0, 4000, { SFHASH_MD5, SFHASH_TLSH }, true, true, BOTH);
  const Loaded b = build_input("test/merge_df_b.hset", corpus(), 2000, 6000, { SFHASH_SHA_1, SFHASH_TLSH }, true, true, BOTH);

  for (const uint32_t op: OPS) {
    const Loaded o = merge(a, b, op, "test/merge_df_out.hset", INHERIT);
    REQUIRE(o.get()->holder.rhdr.fields.size() == 3);
    CHECK(o.get()->holder.rhdr.fields[0].type == SFHASH_MD5);
    CHECK(o.get()->holder.rhdr.fields[1].type == SFHASH_TLSH);
    CHECK(o.get()->holder.rhdr.fields[2].type == SFHASH_SHA_1);
    check_output(o, a, b, op, true, true);
    if (op == SFHASH_HSET_OP_UNION) {
      // no record of one side can equal a record of the other
      CHECK(o.get()->holder.rhdr.record_count == 4000 + 4000);
    }
  }

  // the reverse order widens the other way and must re-sort the right side
  const Loaded o = merge(b, a, SFHASH_HSET_OP_UNION, "test/merge_df_out2.hset", INHERIT);
  CHECK(o.get()->holder.rhdr.fields[0].type == SFHASH_SHA_1);
  check_output(o, b, a, SFHASH_HSET_OP_UNION, true, true);
}

TEST_CASE("hset_merge_mixed_records_and_hashsets_only") {
  // one side has records, the other does not: the output is hashsets only
  // and rows deduplicate, including the record side's duplicate rows
  const Loaded a = build_input("test/merge_mx_a.hset", 0, 6000, true, BOTH);
  const Loaded b = build_input("test/merge_mx_b.hset", 3000, 9000, false, BOTH);

  for (const uint32_t op: OPS) {
    const Loaded o = merge(a, b, op, "test/merge_mx_out.hset", INHERIT);
    CHECK(o.get()->holder.rhdr.fields.empty());
    check_output(o, a, b, op, true, true);
    const Loaded p = merge(b, a, op, "test/merge_mx_out2.hset", INHERIT);
    check_output(p, b, a, op, true, true);
  }
}

TEST_CASE("hset_merge_type_only_on_one_side") {
  // hashsets only: left md5 + tlsh, right tlsh only
  const Loaded a = build_input("test/merge_t1_a.hset", corpus(), 0, 5000, { SFHASH_MD5, SFHASH_TLSH }, false, true, BOTH);
  const Loaded b = build_input("test/merge_t1_b.hset", corpus(), 2500, 7500, { SFHASH_TLSH }, false, true, BOTH);

  for (const uint32_t op: OPS) {
    const Loaded o = merge(a, b, op, "test/merge_t1_out.hset", INHERIT);
    REQUIRE(o.get()->holder.hsets.size() == 2);
    const int midx = sfhash_hashset_index_for_type(o.get(), SFHASH_MD5);
    REQUIRE(midx >= 0);
    // union and difference copy the left md5 section, intersection empties it
    CHECK(sfhash_hashset_count(o.get(), midx) == (op == SFHASH_HSET_OP_INTERSECT ? 0u : 5000u));
    check_output(o, a, b, op, true, true);
  }
}

TEST_CASE("hset_merge_errors") {
  const Loaded a = build_input("test/merge_err_a.hset", 0, 100, true, BOTH);
  const Loaded b = build_input("test/merge_err_b.hset", 50, 150, true, BOTH);

  SFHASH_Error* err = nullptr;

  // unknown op
  CHECK(sfhash_hashset_merge(a.get(), b.get(), 7, "x", "y", "test/merge_err_out.hset", INHERIT, SFHASH_HSET_COALESCE_DEFAULT, &err) == 0);
  REQUIRE(err);
  sfhash_free_error(err);
  err = nullptr;

  // null operand
  CHECK(sfhash_hashset_merge(a.get(), nullptr, SFHASH_HSET_OP_UNION, "x", "y", "test/merge_err_out.hset", INHERIT, SFHASH_HSET_COALESCE_DEFAULT, &err) == 0);
  REQUIRE(err);
  sfhash_free_error(err);
  err = nullptr;

  // records-only against a file with hash sections
  const Loaded ro = build_input("test/merge_err_ro.hset", corpus(), 0, 100, { SFHASH_MD5, SFHASH_TLSH }, true, false, BOTH);
  CHECK(ro.get()->holder.hsets.empty());
  CHECK(sfhash_hashset_merge(a.get(), ro.get(), SFHASH_HSET_OP_UNION, "x", "y", "test/merge_err_out.hset", INHERIT, SFHASH_HSET_COALESCE_DEFAULT, &err) == 0);
  REQUIRE(err);
  sfhash_free_error(err);
  err = nullptr;

  // two records-only files merge to a records-only file
  const Loaded ro2 = build_input("test/merge_err_ro2.hset", corpus(), 50, 150, { SFHASH_MD5, SFHASH_TLSH }, true, false, BOTH);
  const Loaded o = merge(ro, ro2, SFHASH_HSET_OP_UNION, "test/merge_err_out.hset", INHERIT);
  CHECK(o.get()->holder.hsets.empty());
  CHECK(o.get()->holder.rhdr.record_count == 150);
  check_output(o, ro, ro2, SFHASH_HSET_OP_UNION, false, false);
}

TEST_CASE("hset_merge_timing") {
  // merge vs from-scratch build of a 200k + 200k union; printed, not asserted
  using clock = std::chrono::steady_clock;
  const auto ms = [](clock::duration d) {
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(d).count();
  };

  const size_t N = 200000, OVERLAP = 100000;
  const auto big = make_tlsh_corpus(41, 2 * N - OVERLAP);
  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_TLSH };

  const Loaded a = build_input("test/merge_big_a.hset", big, 0, N, htypes, false, true, BOTH);
  const Loaded b = build_input("test/merge_big_b.hset", big, N - OVERLAP, big.size(), htypes, false, true, BOTH);

  const auto t0 = clock::now();
  SFHASH_Error* err = nullptr;
  const uint64_t size = sfhash_hashset_merge(
    a.get(), b.get(), SFHASH_HSET_OP_UNION, "big", "big union",
    "test/merge_big_out.hset", INHERIT, SFHASH_HSET_COALESCE_DEFAULT, &err
  );
  const auto t1 = clock::now();
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(size > 0);

  // from scratch: the same rows through the builder (sort, dedup, embed,
  // k-means), fed as binary digests so no text parsing is timed
  const auto t2 = clock::now();
  {
    auto bctx = make_unique_del(
      sfhash_hashset_builder_open("big", "big union", htypes.data(), htypes.size(), false, true, "test/merge_big_rebuilt.hset", "test", &err),
      sfhash_hashset_builder_destroy
    );
    REQUIRE(!err);
    for (const auto& d: big) {
      sfhash_hashset_builder_add_hash(bctx.get(), &d, sizeof(d));
    }
    REQUIRE(sfhash_hashset_builder_write(bctx.get(), &err) > 0);
    REQUIRE(!err);
  }
  const auto t3 = clock::now();

  const Loaded o = load_file("test/merge_big_out.hset");
  const Loaded rebuilt = load_file("test/merge_big_rebuilt.hset");
  CHECK(rows_of(o.get(), SFHASH_TLSH) == rows_of(rebuilt.get(), SFHASH_TLSH));
  CHECK(count_type(o.toc, Chunk::TVEC) == 1);
  CHECK(count_type(o.toc, Chunk::TIVF) == 1);

  // the same without the vectors, whose 1 KiB per row dominates the output
  const auto t4 = clock::now();
  REQUIRE(sfhash_hashset_merge(
    a.get(), b.get(), SFHASH_HSET_OP_UNION, "big", "big union",
    "test/merge_big_out_idx.hset", SFHASH_HSET_TLSH_INDEX, SFHASH_HSET_COALESCE_DEFAULT, &err
  ) > 0);
  const auto t5 = clock::now();
  REQUIRE(!err);
  {
    auto bctx = make_unique_del(
      sfhash_hashset_builder_open("big", "big union", htypes.data(), htypes.size(), false, true, "test/merge_big_rebuilt_idx.hset", "test", &err),
      sfhash_hashset_builder_destroy
    );
    REQUIRE(!err);
    sfhash_hashset_builder_set_tlsh_options(bctx.get(), SFHASH_HSET_TLSH_INDEX);
    for (const auto& d: big) {
      sfhash_hashset_builder_add_hash(bctx.get(), &d, sizeof(d));
    }
    REQUIRE(sfhash_hashset_builder_write(bctx.get(), &err) > 0);
    REQUIRE(!err);
  }
  const auto t6 = clock::now();

  std::cout << "hset_merge_timing: union of " << sfhash_hashset_count(a.get(), 0) << " + "
            << sfhash_hashset_count(b.get(), 0) << " TLSH rows -> " << sfhash_hashset_count(o.get(), 0)
            << " rows\n  with TVEC + TIVF: merge " << std::fixed << std::setprecision(1) << ms(t1 - t0)
            << " ms, from-scratch build " << ms(t3 - t2) << " ms (" << o.buf.size() / (1024 * 1024) << " MiB file)"
            << "\n  TIVF only:        merge " << ms(t5 - t4)
            << " ms, from-scratch build " << ms(t6 - t5) << " ms" << std::endl;
}

namespace {

using SetopOpen = SFHASH_HashsetBuildCtx* (*)(
  const SFHASH_Hashset*, const SFHASH_Hashset*, const char*, const char*,
  bool, bool, const char*, const char*, SFHASH_Error**
);

const std::pair<SetopOpen, uint32_t> SETOPS[] = {
  { sfhash_hashset_builder_union_open, SFHASH_HSET_OP_UNION },
  { sfhash_hashset_builder_intersect_open, SFHASH_HSET_OP_INTERSECT },
  { sfhash_hashset_builder_subtract_open, SFHASH_HSET_OP_DIFFERENCE }
};

// the builder-shaped set operation: open, optional setup, write, load
Loaded setop(SetopOpen open, const Loaded& l, const Loaded& r, bool write_records, bool write_hashsets, const std::string& path, uint32_t tlsh_options) {
  SFHASH_Error* err = nullptr;
  auto bctx = make_unique_del(
    open(l.get(), r.get(), "merged", "builder set operation", write_records, write_hashsets, path.c_str(), "test", &err),
    sfhash_hashset_builder_destroy
  );
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(bctx);
  sfhash_hashset_builder_set_tlsh_options(bctx.get(), tlsh_options);
  const uint64_t size = sfhash_hashset_builder_write(bctx.get(), &err);
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(size > 0);
  Loaded o = load_file(path);
  REQUIRE(o.buf.size() == size);
  return o;
}

} // namespace

TEST_CASE("hset_builder_setops_are_merges") {
  // the builder-shaped set operations write what sfhash_hashset_merge
  // writes: same rows, records and derived structures
  for (const bool with_records: { true, false }) {
    const std::string tag = with_records ? "rec" : "ho";
    const Loaded a = build_input("test/setop_a_" + tag + ".hset", 0, 6000, with_records, BOTH);
    const Loaded b = build_input("test/setop_b_" + tag + ".hset", 3000, 9000, with_records, BOTH);

    for (const auto& [open, op]: SETOPS) {
      const Loaded o = setop(open, a, b, true, true, "test/setop_out_" + tag + ".hset", INHERIT);
      check_output(o, a, b, op, true, true);

      const Loaded m = merge(a, b, op, "test/setop_merge_" + tag + ".hset", INHERIT);
      for (const auto t: { SFHASH_MD5, SFHASH_TLSH }) {
        CHECK(rows_of(o.get(), t) == rows_of(m.get(), t));
      }
      CHECK(o.get()->holder.rhdr.fields == m.get()->holder.rhdr.fields);
      CHECK(o.get()->holder.rhdr.record_count == m.get()->holder.rhdr.record_count);
      // the files differ only in the FHDR timestamp and description
      CHECK(o.buf.size() == m.buf.size());
      const auto& ohs = o.get()->holder.hsets;
      const auto& mhs = m.get()->holder.hsets;
      REQUIRE(ohs.size() == mhs.size());
      for (size_t i = 0; i < ohs.size(); ++i) {
        const auto& oi = std::get<TlshIvfView>(ohs[i]);
        const auto& mi = std::get<TlshIvfView>(mhs[i]);
        CHECK(oi.lists == mi.lists);
        if (!oi.empty() && !mi.empty()) {
          CHECK(std::memcmp(oi.radius2, mi.radius2, oi.lists * sizeof(uint32_t)) == 0);
          CHECK(std::memcmp(oi.ids, mi.ids, oi.n * sizeof(uint32_t)) == 0);
        }
      }
    }
  }
}

TEST_CASE("hset_builder_setops_write_flags") {
  const Loaded a = build_input("test/setop_fl_a.hset", 0, 6000, true, BOTH);
  const Loaded b = build_input("test/setop_fl_b.hset", 3000, 9000, true, BOTH);

  for (const auto& [open, op]: SETOPS) {
    // hashsets only: the operation is applied to the records, rows follow
    // their records and are then written once each
    {
      const Loaded o = setop(open, a, b, false, true, "test/setop_fl_ho.hset", INHERIT);
      CHECK(o.get()->holder.rhdr.fields.empty());
      CHECK(count_type(o.toc, Chunk::RIDX) == 0);
      const Loaded full = merge(a, b, op, "test/setop_fl_full.hset", INHERIT);
      REQUIRE(o.get()->holder.hsets.size() == full.get()->holder.hsets.size());
      for (const auto t: { SFHASH_MD5, SFHASH_TLSH }) {
        CHECK(rows_of(o.get(), t) == unique_rows(rows_of(full.get(), t)));
      }
      const int tidx = sfhash_hashset_index_for_type(o.get(), SFHASH_TLSH);
      REQUIRE(tidx >= 0);
      check_tlsh_section(o, tidx, true, true, true);
    }

    // records only
    {
      const Loaded o = setop(open, a, b, true, false, "test/setop_fl_ro.hset", INHERIT);
      CHECK(o.get()->holder.hsets.empty());
      const Loaded full = merge(a, b, op, "test/setop_fl_full.hset", INHERIT);
      CHECK(o.get()->holder.rhdr.fields == full.get()->holder.rhdr.fields);
      CHECK(o.get()->holder.rhdr.record_count == full.get()->holder.rhdr.record_count);
      CHECK(std::equal(o.get()->holder.rdat.beg, o.get()->holder.rdat.end, full.get()->holder.rdat.beg, full.get()->holder.rdat.end));
    }
  }

  // the TLSH options apply as for the builder: the default writes both
  // sections even when the inputs lack them
  {
    const Loaded na = build_input("test/setop_fl_na.hset", 0, 3000, true, NONE);
    const Loaded nb = build_input("test/setop_fl_nb.hset", 1000, 4000, true, NONE);
    const Loaded both = setop(sfhash_hashset_builder_union_open, na, nb, true, true, "test/setop_fl_both.hset", BOTH);
    check_output(both, na, nb, SFHASH_HSET_OP_UNION, true, true);
    const Loaded none = setop(sfhash_hashset_builder_union_open, na, nb, true, true, "test/setop_fl_none.hset", INHERIT);
    check_output(none, na, nb, SFHASH_HSET_OP_UNION, false, false);
  }

  // adding to a set-operation context is an error at write
  {
    SFHASH_Error* err = nullptr;
    auto bctx = make_unique_del(
      sfhash_hashset_builder_union_open(a.get(), b.get(), "x", "y", true, true, "test/setop_fl_err.hset", "test", &err),
      sfhash_hashset_builder_destroy
    );
    REQUIRE(bctx);
    REQUIRE(!err);
    const uint8_t hash[16] = {};
    sfhash_hashset_builder_add_hash(bctx.get(), hash, sizeof(hash));
    CHECK(sfhash_hashset_builder_write(bctx.get(), &err) == 0);
    REQUIRE(err);
    sfhash_free_error(err);
  }
}
