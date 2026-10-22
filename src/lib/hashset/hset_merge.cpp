#include "hashset/hset_merge.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <numeric>
#include <tuple>
#include <utility>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include "error.h"
#include "throw.h"
#include "util.h"
#include "hasher/hasher.h"
#include "hashset/hset.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_encoder_chunks.h"
#include "hashset/tlsh_cells.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"

namespace bip = boost::interprocess;

MergeOp make_merge_op(uint32_t op) {
  switch (op) {
  case SFHASH_HSET_OP_UNION:
    return MergeOp::UNION;
  case SFHASH_HSET_OP_INTERSECT:
    return MergeOp::INTERSECT;
  case SFHASH_HSET_OP_DIFFERENCE:
    return MergeOp::DIFFERENCE;
  default:
    THROW("unknown set operation " << op);
  }
}

uint64_t merge_rows(
  MergeOp op,
  const uint8_t* lbeg,
  uint64_t ln,
  const uint8_t* rbeg,
  uint64_t rn,
  size_t len,
  const uint64_t* lridx,
  const uint64_t* lrecmap,
  const uint64_t* rridx,
  const uint64_t* rrecmap,
  std::vector<uint32_t>& lmap,
  std::vector<uint32_t>& rmap,
  bool collapse_equal)
{
  THROW_IF(len == 0, "zero-length rows");
  THROW_IF(ln && !lbeg, "left rows are missing");
  THROW_IF(rn && !rbeg, "right rows are missing");

  lmap.assign(ln, MERGE_DROPPED);
  rmap.assign(rn, MERGE_DROPPED);

  const auto row = [len](const uint8_t* b, uint64_t i) { return b + i * len; };

  uint64_t out = 0;
  uint64_t i = 0, j = 0;

  if (lrecmap || rrecmap) {
    // rows belong to records; the records' fates decide
    THROW_IF(ln && !(lridx && lrecmap), "left rows have no record index");
    THROW_IF(rn && !(rridx && rrecmap), "right rows have no record index");

    const auto lkept = [&](uint64_t k) { return lrecmap[lridx[k]] != MERGE_RECORD_DROPPED; };
    const auto rkept = [&](uint64_t k) { return rrecmap[rridx[k]] != MERGE_RECORD_DROPPED; };

    const uint8_t* last = nullptr; // the previous emitted row

    while (true) {
      while (i < ln && !lkept(i)) {
        ++i;
      }
      while (j < rn && !rkept(j)) {
        ++j;
      }
      if (i == ln && j == rn) {
        break;
      }

      bool take_left;
      if (i < ln && j < rn) {
        take_left = std::memcmp(row(lbeg, i), row(rbeg, j), len) <= 0;
      }
      else {
        take_left = i < ln;
      }

      const uint8_t* r = take_left ? row(lbeg, i) : row(rbeg, j);
      if (collapse_equal && last && std::memcmp(r, last, len) == 0) {
        // equal to the previous emitted row: dropped
        take_left ? ++i : ++j;
        continue;
      }
      last = r;

      if (take_left) {
        lmap[i++] = static_cast<uint32_t>(out++);
      }
      else {
        rmap[j++] = static_cast<uint32_t>(out++);
      }
      THROW_IF(out >= MERGE_DROPPED, "too many rows in merged hashset");
    }
  }
  else {
    // set semantics: equal rows collapse
    const bool emit_left_only = op != MergeOp::INTERSECT;
    const bool emit_right_only = op == MergeOp::UNION;
    const bool emit_both = op != MergeOp::DIFFERENCE;

    // advances k past the run of rows equal to row k
    const auto skip_run = [&](const uint8_t* b, uint64_t n, uint64_t& k) {
      const uint8_t* v = row(b, k);
      do {
        ++k;
      } while (k < n && std::memcmp(row(b, k), v, len) == 0);
    };

    while (i < ln || j < rn) {
      const int c = (i < ln && j < rn) ?
        std::memcmp(row(lbeg, i), row(rbeg, j), len) :
        (i < ln ? -1 : 1);

      if (c < 0) {
        if (emit_left_only) {
          lmap[i] = static_cast<uint32_t>(out++);
        }
        skip_run(lbeg, ln, i);
      }
      else if (c > 0) {
        if (emit_right_only) {
          rmap[j] = static_cast<uint32_t>(out++);
        }
        skip_run(rbeg, rn, j);
      }
      else {
        if (emit_both) {
          lmap[i] = static_cast<uint32_t>(out++);
        }
        skip_run(lbeg, ln, i);
        skip_run(rbeg, rn, j);
      }
      THROW_IF(out >= MERGE_DROPPED, "too many rows in merged hashset");
    }
  }

  return out;
}

namespace {

uint64_t record_length_of(const std::vector<RecordFieldDescriptor>& fields) {
  return std::accumulate(
    fields.begin(), fields.end(), uint64_t(0),
    [](uint64_t a, const RecordFieldDescriptor& f) { return a + 1 + f.length; }
  );
}

// records of (rhdr, rdat) rewritten to the output fields; absent fields are
// a zero presence byte and zero value
std::vector<uint8_t> widen_records(
  const RecordHeader& rhdr,
  const ConstRecordData& rdat,
  const std::vector<RecordFieldDescriptor>& ofields,
  uint64_t olen)
{
  const uint64_t ilen = rhdr.record_length;
  THROW_IF(ilen != record_length_of(rhdr.fields), "record length disagrees with the fields");
  const uint64_t n = rhdr.record_count;
  THROW_IF(
    static_cast<uint64_t>(rdat.end - rdat.beg) != n * ilen,
    "record data length disagrees with the record count"
  );

  // (output offset, input offset or -1, bytes) per output field
  std::vector<std::tuple<uint64_t, int64_t, uint64_t>> moves;
  uint64_t ooff = 0;
  for (const auto& of: ofields) {
    int64_t ioff = -1;
    uint64_t pos = 0;
    for (const auto& f: rhdr.fields) {
      if (f.type == of.type) {
        ioff = static_cast<int64_t>(pos);
        break;
      }
      pos += 1 + f.length;
    }
    if (ioff >= 0) {
      moves.emplace_back(ooff, ioff, 1 + of.length);
    }
    ooff += 1 + of.length;
  }

  std::vector<uint8_t> out(n * olen, 0);
  for (uint64_t r = 0; r < n; ++r) {
    const uint8_t* src = rdat.beg + r * ilen;
    uint8_t* dst = out.data() + r * olen;
    for (const auto& [o, in, bytes]: moves) {
      std::memcpy(dst + o, src + in, bytes);
    }
  }
  return out;
}

// the records of w (olen bytes each) in sorted order; the identity when they
// are already sorted, which they are unless widening reordered the fields
std::vector<uint64_t> sorted_order(const std::vector<uint8_t>& w, uint64_t olen) {
  const uint64_t n = olen ? w.size() / olen : 0;
  std::vector<uint64_t> order(n);
  std::iota(order.begin(), order.end(), uint64_t(0));

  const auto less = [&](uint64_t a, uint64_t b) {
    return std::memcmp(w.data() + a * olen, w.data() + b * olen, olen) < 0;
  };

  if (!std::is_sorted(order.begin(), order.end(), less)) {
    std::sort(order.begin(), order.end(), less);
  }
  return order;
}

} // namespace

std::vector<RecordFieldDescriptor> merged_record_fields(
  const RecordHeader& lrhdr,
  const RecordHeader& rrhdr)
{
  // the left fields, then the right fields the left lacks
  std::vector<RecordFieldDescriptor> fields = lrhdr.fields;
  for (const auto& f: rrhdr.fields) {
    const auto i = std::find_if(
      fields.begin(), fields.end(),
      [&f](const RecordFieldDescriptor& o) { return o.type == f.type; }
    );
    if (i == fields.end()) {
      fields.push_back(f);
    }
    else {
      THROW_IF(
        i->length != f.length,
        "field " << f.name << " has length " << i->length << " on the left and " << f.length << " on the right"
      );
    }
  }
  return fields;
}

RecordMerge merge_records(
  MergeOp op,
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  RecordMerge rm;
  rm.fields = merged_record_fields(lrhdr, rrhdr);
  rm.record_length = record_length_of(rm.fields);
  const uint64_t olen = rm.record_length;

  const std::vector<uint8_t> lw = widen_records(lrhdr, lrdat, rm.fields, olen);
  const std::vector<uint8_t> rw = widen_records(rrhdr, rrdat, rm.fields, olen);
  const std::vector<uint64_t> lord = sorted_order(lw, olen);
  const std::vector<uint64_t> rord = sorted_order(rw, olen);
  const uint64_t ln = lord.size(), rn = rord.size();

  rm.lmap.assign(ln, MERGE_RECORD_DROPPED);
  rm.rmap.assign(rn, MERGE_RECORD_DROPPED);
  rm.rdat.reserve((op == MergeOp::UNION ? ln + rn : ln) * olen);

  const auto emit = [&](const std::vector<uint8_t>& w, uint64_t idx, std::vector<uint64_t>& map) {
    map[idx] = rm.rdat.size() / olen;
    rm.rdat.insert(rm.rdat.end(), w.begin() + idx * olen, w.begin() + (idx + 1) * olen);
  };

  uint64_t i = 0, j = 0;
  while (i < ln || j < rn) {
    const int c = (i < ln && j < rn) ?
      std::memcmp(lw.data() + lord[i] * olen, rw.data() + rord[j] * olen, olen) :
      (i < ln ? -1 : 1);

    if (c < 0) {
      if (op != MergeOp::INTERSECT) {
        emit(lw, lord[i], rm.lmap);
      }
      ++i;
    }
    else if (c > 0) {
      if (op == MergeOp::UNION) {
        emit(rw, rord[j], rm.rmap);
      }
      ++j;
    }
    else {
      // identical records: the left copy stands for both, so the right
      // record's rows are dropped whatever the operation
      if (op != MergeOp::DIFFERENCE) {
        emit(lw, lord[i], rm.lmap);
      }
      ++i;
      ++j;
    }
  }

  return rm;
}

namespace {

using HashsetTuple = decltype(Holder::hsets)::value_type;

bool has_records(const Holder& h) {
  return !h.rhdr.fields.empty();
}

const HashsetTuple* find_section(const Holder& h, uint32_t type) {
  for (const auto& hs: h.hsets) {
    if (std::get<HashsetHeader>(hs).hash_type == type) {
      return &hs;
    }
  }
  return nullptr;
}

bool has_field(const Holder& h, uint32_t type) {
  return std::any_of(
    h.rhdr.fields.begin(), h.rhdr.fields.end(),
    [type](const RecordFieldDescriptor& f) { return f.type == type; }
  );
}

const uint8_t* rows_of(const HashsetTuple* s) {
  return s ? static_cast<const uint8_t*>(std::get<ConstHashsetData>(*s).beg) : nullptr;
}

uint64_t count_of(const HashsetTuple* s) {
  return s ? std::get<HashsetHeader>(*s).hash_count : 0;
}

const uint64_t* ridx_of(const HashsetTuple* s) {
  return s ? static_cast<const uint64_t*>(std::get<ConstRecordIndex>(*s).beg) : nullptr;
}

bool has_tvec(const HashsetTuple* s) {
  return s && !std::get<ConstTlshVectors>(*s).empty();
}

bool has_tivf(const HashsetTuple* s) {
  return s && !std::get<TlshIvfView>(*s).empty();
}

// an output hash section and how it is assembled from the inputs
struct OutSection {
  RecordFieldDescriptor field;
  const HashsetTuple* ls = nullptr;
  const HashsetTuple* rs = nullptr;
  uint64_t n = 0;
  std::vector<uint32_t> lmap, rmap;
  bool tvec = false;
  bool tivf = false;
  TlshIvf ivf;
  uint64_t hint_off = 0; // chunk offsets, filled in by the layout
  uint64_t hdat_off = 0;

  OutSection(const RecordFieldDescriptor& f): field(f) {}
};

// copies every kept row of both sides to its output position
template <class Copy>
void for_each_kept_row(const OutSection& s, Copy copy) {
  for (const auto& [side, map]: { std::pair{ s.ls, &s.lmap }, std::pair{ s.rs, &s.rmap } }) {
    if (!side) {
      continue;
    }
    for (uint64_t i = 0; i < map->size(); ++i) {
      if ((*map)[i] != MERGE_DROPPED) {
        copy(side, i, (*map)[i]);
      }
    }
  }
}

} // namespace

uint64_t write_merged_hset(
  const SFHASH_Hashset& l,
  const SFHASH_Hashset& r,
  MergeOp op,
  const std::string& name,
  const std::string& desc,
  const std::filesystem::path& outfile,
  const MergeOptions& options)
{
  const Holder& lh = l.holder;
  const Holder& rh = r.holder;
  const uint32_t tlsh_options = options.tlsh_options;

  THROW_IF(name.size() > std::numeric_limits<uint16_t>::max(), "name is too long, maximum length is 65535 chars");
  THROW_IF(desc.size() > std::numeric_limits<uint16_t>::max(), "desc is too long, maximum length is 65535 chars");

  // the operation is applied to the records when both sides have them
  const bool record_merge = has_records(lh) && has_records(rh);
  THROW_IF(
    lh.hsets.empty() != rh.hsets.empty(),
    "cannot merge a records-only hashset with one that has hash sections"
  );
  THROW_IF(!record_merge && lh.hsets.empty(), "the inputs have neither records nor hash sections in common");

  // what the output gets
  const bool with_records = record_merge && options.write_records;
  const bool with_hashsets = !lh.hsets.empty() && options.write_hashsets;
  THROW_IF(!with_records && !with_hashsets, "neither records nor hash sections are to be written");

  //
  // merge the records
  //
  RecordMerge rm;
  if (record_merge) {
    rm = merge_records(op, lh.rhdr, lh.rdat, rh.rhdr, rh.rdat);
  }

  //
  // merge the hash sections
  //
  std::vector<RecordFieldDescriptor> ofields;
  if (record_merge) {
    ofields = rm.fields;
  }
  else {
    for (const Holder* h: { &lh, &rh }) {
      for (const auto& hs: h->hsets) {
        const auto& hhdr = std::get<HashsetHeader>(hs);
        if (!std::any_of(ofields.begin(), ofields.end(), [&](const RecordFieldDescriptor& f) { return f.type == hhdr.hash_type; })) {
          ofields.emplace_back(hhdr.hash_type, hhdr.hash_name, hhdr.hash_length);
        }
      }
    }
  }

  std::vector<OutSection> secs;
  if (with_hashsets) {
    for (const auto& f: ofields) {
      OutSection s(f);
      s.ls = find_section(lh, f.type);
      s.rs = find_section(rh, f.type);

      for (const auto& [side, h, sname]: { std::tuple{ s.ls, &lh, "left" }, std::tuple{ s.rs, &rh, "right" } }) {
        if (side) {
          const auto& hhdr = std::get<HashsetHeader>(*side);
          THROW_IF(
            hhdr.hash_length != f.length,
            sname << " " << f.name << " hashset has hash length " << hhdr.hash_length << ", expected " << f.length
          );
          THROW_IF(
            record_merge && !ridx_of(side),
            sname << " " << f.name << " hashset has no record index"
          );
        }
        else {
          THROW_IF(
            record_merge && has_field(*h, f.type),
            sname << " has a " << f.name << " field but no " << f.name << " hashset"
          );
        }
      }

      s.n = merge_rows(
        op,
        rows_of(s.ls), count_of(s.ls),
        rows_of(s.rs), count_of(s.rs),
        f.length,
        record_merge ? ridx_of(s.ls) : nullptr,
        record_merge ? rm.lmap.data() : nullptr,
        record_merge ? ridx_of(s.rs) : nullptr,
        record_merge ? rm.rmap.data() : nullptr,
        s.lmap, s.rmap,
        record_merge && !with_records // hashsets-only output: equal rows once
      );

      if (f.type == SFHASH_TLSH) {
        if (tlsh_options & SFHASH_HSET_TLSH_INHERIT) {
          // what every present side has
          s.tvec = (!s.ls || has_tvec(s.ls)) && (!s.rs || has_tvec(s.rs));
          s.tivf = (!s.ls || has_tivf(s.ls)) && (!s.rs || has_tivf(s.rs));
        }
        else {
          s.tvec = (tlsh_options & SFHASH_HSET_TLSH_VECTORS) != 0;
          s.tivf = (tlsh_options & SFHASH_HSET_TLSH_INDEX) != 0;
        }

        if (s.tivf) {
          // the merged rows, in output order
          std::vector<TlshDigest> rows(s.n);
          for_each_kept_row(s, [&](const HashsetTuple* side, uint64_t i, uint32_t k) {
            std::memcpy(&rows[k], rows_of(side) + i * sizeof(TlshDigest), sizeof(TlshDigest));
          });

          if ((!s.ls || has_tivf(s.ls)) && (!s.rs || has_tivf(s.rs))) {
            // carry the lists through the merge, coalescing small ones
            s.ivf = merge_tlsh_ivf(
              s.ls ? std::get<TlshIvfView>(*s.ls) : TlshIvfView(),
              s.lmap.data(),
              s.rs ? std::get<TlshIvfView>(*s.rs) : TlshIvfView(),
              s.rmap.data(),
              rows.data(),
              s.n,
              options.coalesce_threshold
            );
          }
          else {
            // a side lacks an index: cluster the merged rows from scratch
            s.ivf = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), TLSH_IVF_TARGET_LIST_SIZE);
          }
        }
      }

      secs.push_back(std::move(s));
    }
  }

  //
  // layout
  //
  const FileHeader fhdr{ 2, name, make_timestamp(), desc, {} };

  size_t chunk_count = 3 + (with_records ? 2 : 0); // FTOC, FHDR, [RHDR, RDAT], FEND
  for (const auto& s: secs) {
    chunk_count += 2 + (s.field.type != SFHASH_SIZE) + with_records + s.tvec + s.tivf;
  }

  TableOfContents ftoc;
  std::vector<std::pair<uint64_t, size_t>> off2sec; // chunk offset -> section

  uint64_t off = length_magic() + length_hset_hash();

  ftoc.entries.emplace_back(off, Chunk::Type::FTOC);
  off += length_ftoc(chunk_count);

  ftoc.entries.emplace_back(off, Chunk::Type::FHDR);
  off += length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

  if (with_records) {
    ftoc.entries.emplace_back(off, Chunk::Type::RHDR);
    off += length_rhdr(rm.fields);

    ftoc.entries.emplace_back(off, Chunk::Type::RDAT);
    off += length_rdat(rm.fields, rm.record_count());
  }

  for (size_t i = 0; i < secs.size(); ++i) {
    auto& s = secs[i];

    ftoc.entries.emplace_back(off, make_hhnn_type(s.field.type));
    off2sec.emplace_back(off, i);
    off += length_hhnn(s.field);

    if (s.field.type != SFHASH_SIZE) {
      s.hint_off = off;
      ftoc.entries.emplace_back(off, Chunk::Type::HINT);
      off2sec.emplace_back(off, i);
      off += length_hint(s.field.type);
    }

    off += length_alignment_padding(off, 4096);
    s.hdat_off = off;
    ftoc.entries.emplace_back(off, Chunk::Type::HDAT);
    off2sec.emplace_back(off, i);
    off += length_hdat(s.n, s.field.length);

    if (with_records) {
      ftoc.entries.emplace_back(off, Chunk::Type::RIDX);
      off2sec.emplace_back(off, i);
      off += length_ridx(s.n);
    }

    if (s.tvec) {
      off += length_tvec_alignment_padding(off);
      ftoc.entries.emplace_back(off, Chunk::Type::TVEC);
      off2sec.emplace_back(off, i);
      off += length_tvec(s.n);
    }

    if (s.tivf) {
      ftoc.entries.emplace_back(off, Chunk::Type::TIVF);
      off2sec.emplace_back(off, i);
      off += length_tivf(static_cast<uint32_t>(s.ivf.lists()), s.n);
    }
  }

  ftoc.entries.emplace_back(off, Chunk::Type::FEND);
  off += length_fend();

  const uint64_t total = off;
  THROW_IF(ftoc.entries.size() != chunk_count, "chunk count mismatch, should be impossible");

  const auto section_at = [&off2sec](uint64_t choff) -> size_t {
    const auto i = std::find_if(
      off2sec.begin(), off2sec.end(),
      [choff](const auto& e) { return e.first == choff; }
    );
    THROW_IF(i == off2sec.end(), "no section for chunk at " << choff << ", should be impossible");
    return i->second;
  };

  //
  // write
  //
  {
    std::ofstream of;
    of.exceptions(std::ofstream::failbit);
    of.open(outfile, std::ios::binary | std::ios::trunc);
  }
  std::filesystem::resize_file(outfile, total);

  {
    bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    char* beg = static_cast<char*>(mr.get_address());
    write_magic(beg);

    for (const auto& [choff, chtype]: ftoc.entries) {
      char* out = beg + choff;

      switch (chtype) {
      case Chunk::Type::FTOC:
        write_ftoc(ftoc, out);
        break;

      case Chunk::Type::FHDR:
        write_fhdr(fhdr.version, fhdr.name, fhdr.desc, fhdr.time, out);
        break;

      case Chunk::Type::RHDR:
        write_rhdr(rm.fields, rm.record_count(), out);
        break;

      case Chunk::Type::RDAT:
        write_chunk(
          [&rm](char* o) -> size_t {
            std::memcpy(o, rm.rdat.data(), rm.rdat.size());
            return rm.rdat.size();
          },
          out, "RDAT"
        );
        break;

      case Chunk::Type::HINT:
        // written once the HDAT exists, below
        break;

      case Chunk::Type::HDAT:
        {
          const OutSection& s = secs[section_at(choff)];
          const size_t len = s.field.length;
          write_chunk(
            [&](char* o) -> size_t {
              for_each_kept_row(s, [&](const HashsetTuple* side, uint64_t i, uint32_t k) {
                std::memcpy(o + k * len, rows_of(side) + i * len, len);
              });
              return s.n * len;
            },
            out, "HDAT"
          );
        }
        break;

      case Chunk::Type::RIDX:
        {
          const OutSection& s = secs[section_at(choff)];
          write_chunk(
            [&](char* o) -> size_t {
              for_each_kept_row(s, [&](const HashsetTuple* side, uint64_t i, uint32_t k) {
                const uint64_t* recmap = side == s.ls ? rm.lmap.data() : rm.rmap.data();
                const uint64_t rec = recmap[ridx_of(side)[i]];
                THROW_IF(rec == MERGE_RECORD_DROPPED, "kept row points at a dropped record, should be impossible");
                std::memcpy(o + k * sizeof(uint64_t), &rec, sizeof(rec));
              });
              return s.n * sizeof(uint64_t);
            },
            out, "RIDX"
          );
        }
        break;

      case Chunk::Type::TVEC:
        {
          const OutSection& s = secs[section_at(choff)];
          write_chunk(
            [&](char* o) -> size_t {
              char* data = o + write_tvec_header(s.n, o);
              constexpr size_t ROW = TLSH_EMBED_DIMS * sizeof(float);
              for_each_kept_row(s, [&](const HashsetTuple* side, uint64_t i, uint32_t k) {
                const auto& tv = std::get<ConstTlshVectors>(*side);
                if (tv.data) {
                  // carry the stored vector through
                  std::memcpy(data + k * ROW, tv.data + i * TLSH_EMBED_DIMS, ROW);
                }
                else {
                  // this side has no vectors: embed its row
                  float row[TLSH_EMBED_DIMS];
                  TlshDigest d;
                  std::memcpy(&d, rows_of(side) + i * sizeof(TlshDigest), sizeof(d));
                  tlsh_embed(d, row);
                  std::memcpy(data + k * ROW, row, ROW);
                }
              });
              return TVEC_HEADER_LENGTH + s.n * ROW;
            },
            out, "TVEC"
          );
        }
        break;

      case Chunk::Type::TIVF:
        write_tivf(secs[section_at(choff)].ivf, out);
        break;

      case Chunk::Type::FEND:
        write_fend(out);
        break;

      default:
        // HHnn
        {
          const OutSection& s = secs[section_at(choff)];
          write_hhnn(s.field, s.n, out);
        }
        break;
      }
    }

    // the hints are computed from the written rows
    for (const auto& s: secs) {
      if (s.field.type == SFHASH_SIZE) {
        continue;
      }
      uint8_t* rows = reinterpret_cast<uint8_t*>(beg + s.hdat_off + 12);
      if (s.field.type == SFHASH_TLSH) {
        const auto* tbeg = reinterpret_cast<const TlshDigest*>(rows);
        write_tlsh_hint(make_tlsh_cell_index(tbeg, tbeg + s.n), beg + s.hint_off);
      }
      else {
        write_hint(
          make_block_bounds<8>(
            RecordIterator(rows, s.field.length),
            RecordIterator(rows + s.n * s.field.length, s.field.length)
          ),
          beg + s.hint_off
        );
      }
    }

    // hash everything after the hash
    auto hasher = make_unique_del(
      sfhash_create_hasher(SFHASH_SHA_2_256), sfhash_destroy_hasher
    );
    const char* hset_data = beg + length_magic() + length_hset_hash();
    sfhash_update_hasher(hasher.get(), hset_data, beg + total);

    SFHASH_HashValues hashes;
    sfhash_get_hashes(hasher.get(), &hashes);
    write_bytes(hashes.Sha2_256, std::size(hashes.Sha2_256), beg + length_magic());
  }

  return total;
}

uint64_t sfhash_hashset_merge(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  uint32_t op,
  const char* name,
  const char* desc,
  const char* output_file,
  uint32_t tlsh_options,
  uint32_t coalesce_threshold,
  SFHASH_Error** err)
{
  try {
    THROW_IF(!l || !r, "null hashset operand");
    THROW_IF(!name || !desc || !output_file, "null name, desc or output_file");
    MergeOptions options;
    options.tlsh_options = tlsh_options;
    options.coalesce_threshold = coalesce_threshold == SFHASH_HSET_COALESCE_DEFAULT ?
      TLSH_IVF_DEFAULT_COALESCE : coalesce_threshold;
    return write_merged_hset(*l, *r, make_merge_op(op), name, desc, output_file, options);
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return 0;
  }
}
