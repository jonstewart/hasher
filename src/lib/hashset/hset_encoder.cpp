#include "hashset/hset_encoder.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <istream>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <ostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace bip = boost::interprocess;

#include "error.h"
#include "hex.h"
#include "rwutil.h"
#include "util.h"
#include "hashset/hset_encoder_chunks.h"
#include "hashset/record_iterator.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/util.h"
#include "tlsh_digest.h"
#include "hasher/hasher.h"
#include "hasher/hashset.h"
#include "util/istream_line_range.h"

const std::map<
  SFHASH_HashAlgorithm,
  std::pair<
    RecordFieldDescriptor,
    void (*)(uint8_t* dst, const char* src, size_t dlen)
  >
> FIELDS{
  { SFHASH_MD5,       { RecordFieldDescriptor{SFHASH_MD5, "md5", 16 }, from_hex } },
  { SFHASH_SHA_1,     { RecordFieldDescriptor{SFHASH_SHA_1, "sha1", 20 }, from_hex } },
  { SFHASH_SHA_2_224, { RecordFieldDescriptor{SFHASH_SHA_2_224, "sha2_224", 28 }, from_hex } },
  { SFHASH_SHA_2_256, { RecordFieldDescriptor{SFHASH_SHA_2_256, "sha2_256", 32 }, from_hex } },
  { SFHASH_SHA_2_384, { RecordFieldDescriptor{SFHASH_SHA_2_384, "sha2_384", 48 }, from_hex } },
  { SFHASH_SHA_2_512, { RecordFieldDescriptor{SFHASH_SHA_2_512, "sha2_512", 64 }, from_hex } },
  { SFHASH_SHA_3_224, { RecordFieldDescriptor{SFHASH_SHA_3_224, "sha3_224", 28 }, from_hex } },
  { SFHASH_SHA_3_256, { RecordFieldDescriptor{SFHASH_SHA_3_256, "sha3_256", 32 }, from_hex } },
  { SFHASH_SHA_3_384, { RecordFieldDescriptor{SFHASH_SHA_3_384, "sha3_384", 48 }, from_hex } },
  { SFHASH_SHA_3_512, { RecordFieldDescriptor{SFHASH_SHA_3_512, "sha3_512", 64 }, from_hex } },
  { SFHASH_BLAKE3,    { RecordFieldDescriptor{SFHASH_BLAKE3, "blake3", 32 }, from_hex } },
  { SFHASH_SIZE,      { RecordFieldDescriptor{SFHASH_SIZE, "sizes", 8 }, size_to_u64 } },
  { SFHASH_TLSH,      { RecordFieldDescriptor{SFHASH_TLSH, "tlsh", 36 }, tlsh_hex_to_digest } }
};

void size_to_u64(uint8_t* dst, const char* src, size_t /* dlen */) {
  THROW_IF(std::strchr(src, '-'), src << " is not nonnegative");
  *reinterpret_cast<uint64_t*>(dst) = boost::lexical_cast<uint64_t>(src);
}

void tlsh_hex_to_digest(uint8_t* dst, const char* src, size_t /* dlen */) {
  // src is a column in a line, so it ends at a space or NUL
  TlshDigest& d = *reinterpret_cast<TlshDigest*>(dst);
  THROW_IF(
    !tlsh_from_hex(src, d),
    std::string_view(src, std::strcspn(src, " ")) << " is not a TLSH digest"
  );
}

// TODO: unused?
template <>
size_t write_to(char* out, const void* buf, size_t len) {
  std::memcpy(out, buf, len);
  return len;
}

template <size_t BlockBits>
std::vector<std::pair<int64_t, int64_t>> make_block_bounds(
  RecordIterator beg,
  RecordIterator end)
{
  std::vector<std::pair<int64_t, int64_t>> block_bounds(
    1 << BlockBits,
    {
      std::numeric_limits<int64_t>::max(),
      std::numeric_limits<int64_t>::min()
    }
  );

  const auto count = end - beg;

  for (auto i = beg; i != end; ++i) {
    const size_t e = expected_index(reinterpret_cast<const uint8_t*>(i->rec.data()), count);
    const int64_t delta = static_cast<int64_t>(i - beg) - static_cast<int64_t>(e);

    const size_t bi = static_cast<uint8_t>(i->rec[0]) >> (8 - BlockBits);
    block_bounds[bi].first = std::min(block_bounds[bi].first, delta);
    block_bounds[bi].second = std::max(block_bounds[bi].second, delta);
  }

  return block_bounds;
}



// TIVF lists hold about this many rows each
constexpr size_t TLSH_IVF_TARGET_LIST_SIZE = 32;

bool wants_tvec(const RecordFieldDescriptor& field, uint32_t tlsh_options) {
  return field.type == SFHASH_TLSH && (tlsh_options & SFHASH_HSET_TLSH_VECTORS);
}

bool wants_tivf(const RecordFieldDescriptor& field, uint32_t tlsh_options) {
  return field.type == SFHASH_TLSH && (tlsh_options & SFHASH_HSET_TLSH_INDEX);
}

// The FTOC is sized when the builder is opened, before the TLSH options can
// be set, so room is reserved for both optional TLSH chunks of every TLSH
// field; the FTOC chunk is simply shorter than its reservation when they
// are not written.
size_t count_chunks(const std::vector<RecordFieldDescriptor>& fields) {
  size_t chunk_count = 5 + 3 * fields.size();

  for (const auto& hi: fields) {
    if (hi.type != SFHASH_SIZE) {
      ++chunk_count;
    }
    if (hi.type == SFHASH_TLSH) {
      chunk_count += 2; // TVEC, TIVF
    }
  }

  return chunk_count;
}

size_t count_chunks_hashsets_only(const std::vector<RecordFieldDescriptor>& fields) {
  size_t chunk_count = 4 + 2 * fields.size();

  for (const auto& hi: fields) {
    if (hi.type != SFHASH_SIZE) {
      ++chunk_count;
    }
    if (hi.type == SFHASH_TLSH) {
      chunk_count += 2; // TVEC, TIVF
    }
  }

  return chunk_count;
}

/*
 * Lays out the optional TVEC and TIVF chunks of a field following its
 * HDAT/RIDX at off, recording them in ftoc and off2hbidx when those are
 * given. Returns the offset following them. Non-TLSH fields have none.
 */
uint64_t layout_tlsh_chunks(
  uint64_t off,
  const RecordFieldDescriptor& field,
  uint64_t hash_count,
  const TlshIvf& ivf,
  uint32_t tlsh_options,
  size_t hbidx,
  TableOfContents* ftoc,
  std::map<uint64_t, size_t>* off2hbidx)
{
  if (wants_tvec(field, tlsh_options)) {
    // the float data must start on a page boundary
    off += length_tvec_alignment_padding(off);
    if (ftoc) {
      ftoc->entries.emplace_back(off, Chunk::Type::TVEC);
      (*off2hbidx)[off] = hbidx;
    }
    off += length_tvec(hash_count);
  }

  if (wants_tivf(field, tlsh_options)) {
    THROW_IF(
      ivf.n != hash_count,
      "TIVF index has " << ivf.n << " rows, expected " << hash_count
    );
    if (ftoc) {
      ftoc->entries.emplace_back(off, Chunk::Type::TIVF);
      (*off2hbidx)[off] = hbidx;
    }
    off += length_tivf(static_cast<uint32_t>(ivf.lists()), hash_count);
  }

  return off;
}

/*
 * Counts the hashes present per field in the sorted records [rbeg, rend) and
 * builds the TIVF index of each TLSH field that gets one. The index is
 * built from a sorted copy of the field's digests, which has the same rows
 * in the same order as the HDAT that scatter_records_to_hashset produces.
 */
void count_hashes_and_build_indexes(
  const RecordHeader& rhdr,
  RecordIterator rbeg,
  RecordIterator rend,
  uint32_t tlsh_options,
  std::vector<uint64_t>& hash_counts,
  std::vector<TlshIvf>& ivfs)
{
  const size_t nfields = rhdr.fields.size();
  hash_counts.assign(nfields, 0);
  ivfs.assign(nfields, TlshIvf());

  std::vector<std::vector<TlshDigest>> tlsh_rows(nfields);

  for (auto i = rbeg; i != rend; ++i) {
    size_t roff = 0;
    for (size_t f = 0; f < nfields; ++f) {
      // the presence byte of a field precedes its value
      const uint8_t* fld = i->rec.data() + roff;
      if (fld[0] == 0x01) {
        ++hash_counts[f];
        if (wants_tivf(rhdr.fields[f], tlsh_options)) {
          TlshDigest d;
          std::memcpy(&d, fld + 1, sizeof(d));
          tlsh_rows[f].push_back(d);
        }
      }
      roff += 1 + rhdr.fields[f].length;
    }
  }

  for (size_t f = 0; f < nfields; ++f) {
    if (wants_tivf(rhdr.fields[f], tlsh_options)) {
      auto& rows = tlsh_rows[f];
      std::sort(rows.begin(), rows.end());
      ivfs[f] = build_tlsh_ivf(rows.data(), rows.data() + rows.size(), TLSH_IVF_TARGET_LIST_SIZE);
      rows.clear();
      rows.shrink_to_fit();
    }
  }
}

size_t length_hset(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count,
  const std::vector<uint64_t>& hash_counts,
  const std::vector<TlshIvf>& ivfs,
  uint32_t tlsh_options)
{
  size_t chunk_count = count_chunks(fields);

  size_t len = length_magic() +
               length_hset_hash() +
               length_ftoc(chunk_count) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields) +
               length_rdat(fields, record_count);

  for (size_t i = 0; i < fields.size(); ++i) {
    const auto& hi = fields[i];

    len += length_hhnn(hi);

    if (hi.type != SFHASH_SIZE) {
      len += length_hint(hi.type);
    }

    len += length_alignment_padding(len, 4096);

    len += length_hdat(hash_counts[i], hi.length) +
           length_ridx(hash_counts[i]);

    len = layout_tlsh_chunks(len, hi, hash_counts[i], ivfs[i], tlsh_options, i, nullptr, nullptr);
  }

  len += length_fend();

  return len;
}

size_t length_hset_records_only(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count)
{
  size_t len = length_magic() +
               length_hset_hash() +
               length_ftoc(5) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields) +
               length_rdat(fields, record_count);

  len += length_fend();

  return len;
}

size_t length_hset_hashsets_only(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  const decltype(SFHASH_HashsetBuildCtx::hsets)& hsets,
  const std::vector<TlshIvf>& ivfs,
  uint32_t tlsh_options)
{
  size_t chunk_count = count_chunks_hashsets_only(fields);

  size_t len = length_magic() +
               length_hset_hash() +
               length_ftoc(chunk_count) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields);

  for (size_t i = 0; i < fields.size(); ++i) {
    const auto& hhdr = std::get<HashsetHeader>(hsets[i]);

    len += length_hhnn(fields[i]);

    if (fields[i].type != SFHASH_SIZE) {
      len += length_hint(fields[i].type);
    }

    len += length_alignment_padding(len, 4096);
    len += length_hdat(hhdr.hash_count, hhdr.hash_length);

    len = layout_tlsh_chunks(len, fields[i], hhdr.hash_count, ivfs[i], tlsh_options, i, nullptr, nullptr);
  }

  len += length_fend();

  return len;
}

std::string make_timestamp(std::time_t tt = std::time(nullptr)) {
  // set the timestamp
  const auto tm = std::gmtime(&tt);

  // 0000-00-00T00:00:00Z
  std::string ts(21, '\0'); // max length + 1; strftime wants to write a null

  const auto len = std::strftime(ts.data(), ts.size(), "%Y-%m-%dT%H:%M:%SZ", tm);
  THROW_IF(len == 0, "buffer too short for timestamp, should be impossible");
  ts.resize(len);
  return ts;
}

void check_strlen(const char* s, const char* sname) {
  THROW_IF(
    std::strlen(s) > std::numeric_limits<uint16_t>::max(),
    sname << " is too long, maximum length is 65535 chars"
  );
}

void write_chunks(
  char* beg,
  const TableOfContents& ftoc,
  const FileHeader& fhdr,
  const RecordHeader& rhdr,
  const RecordData& rdat,
  const std::vector<
    std::tuple<
      uint64_t,
      RecordIterator,
      RecordIterator,
      uint64_t*,
      uint64_t*
    >
  >& hb,
  const std::map<uint64_t, size_t>& off2hbidx,
  const std::vector<TlshIvf>& ivfs
)
{
  char* out = beg;

  // magic
  out += write_magic(out);

  // note the start of the hset hash
  char* hset_hash = out;
  // note the start of the data to be hashed
  const char* hset_data = hset_hash + length_hset_hash();

  // write the chunks
  for (const auto& [choff, chtype]: ftoc.entries) {
    out = beg + choff;

    switch (chtype) {
    case Chunk::Type::FTOC:
      write_ftoc(ftoc, out);
      break;

    case Chunk::Type::FHDR:
      write_fhdr(fhdr.version, fhdr.name, fhdr.desc, fhdr.time, out);
      break;

    case Chunk::Type::RHDR:
      write_rhdr(rhdr.fields, rhdr.record_count, out);
      break;

    case Chunk::Type::RDAT:
      write_rdat(rdat, out);
      break;

    case Chunk::Type::HINT:
      {
        const size_t i = off2hbidx.at(choff);
        if (rhdr.fields[i].type == SFHASH_TLSH) {
          // cell index over the sorted rows
          const auto* tbeg = reinterpret_cast<const TlshDigest*>(std::get<1>(hb[i])->rec.data());
          const auto* tend = reinterpret_cast<const TlshDigest*>(std::get<2>(hb[i])->rec.data());
          write_tlsh_hint(make_tlsh_cell_index(tbeg, tend), out);
        }
        else {
          write_hint(make_block_bounds<8>(std::get<1>(hb[i]), std::get<2>(hb[i])), out);
        }
      }
      break;

    case Chunk::Type::HDAT:
      {
        const size_t i = off2hbidx.at(choff);
        HashsetData hdat{
          std::get<1>(hb[i])->rec.data(),
          std::get<2>(hb[i])->rec.data()
        };
        write_hdat(hdat, out);
      }
      break;

    case Chunk::Type::FEND:
      out += write_fend(out);
      break;

    case Chunk::Type::RIDX:
      {
        const size_t i = off2hbidx.at(choff);
        const RecordIndex ridx{
          std::get<3>(hb[i]),
          std::get<4>(hb[i])
        };
        write_ridx(ridx, out);
      }
      break;

    case Chunk::Type::TVEC:
      {
        // embeddings of the sorted rows
        const size_t i = off2hbidx.at(choff);
        const auto* tbeg = reinterpret_cast<const TlshDigest*>(std::get<1>(hb[i])->rec.data());
        const auto* tend = reinterpret_cast<const TlshDigest*>(std::get<2>(hb[i])->rec.data());
        write_tvec(tbeg, tend, out);
      }
      break;

    case Chunk::Type::TIVF:
      write_tivf(ivfs[off2hbidx.at(choff)], out);
      break;

    default:
      // HHnn
      {
        const size_t i = off2hbidx.at(choff);
        write_hhnn(rhdr.fields[i], std::get<2>(hb[i]) - std::get<1>(hb[i]), out);
      }
      break;
    }
  }

  // hash the hset data
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_SHA_2_256), sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), hset_data, out);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  write_bytes(hashes.Sha2_256, std::size(hashes.Sha2_256), hset_hash);
}

void scatter_records_to_hashset(
  const RecordHeader& rhdr,
  RecordData& rdat,
  std::vector<
    std::tuple<
      uint64_t,
      RecordIterator,
      RecordIterator,
      uint64_t*,
      uint64_t*
    >
  >& hb)
{
  RecordIterator rbeg(rdat.beg, rhdr.record_length);
  RecordIterator rend(rdat.end, rhdr.record_length);
  size_t recno = 0;
  // Scatter each record out to the hash sections
  for (auto i = rbeg; i != rend; ++i) {
    size_t roff = 1;
    for (auto& [hlen, hbeg, hi, ibeg, ii]: hb) {
      // the presence byte of this field precedes its value
      if (i->rec.data()[roff - 1] == 0x01) {
        // write the hash to its HDAT section
        std::memcpy(hi->rec.data(), i->rec.data() + roff, hlen);
        ++hi;

        // write the record index to its RIDX section
        *ii++ = i - rbeg;
      }

      roff += hlen + 1;
    }

    ++recno;
/*
    if (recno % 10000 == 0) {
      std::cerr << "scattered " << recno << " records\n";
    }
*/
  }

//  std::cerr << "scattered " << recno << " records\n";

  for (auto& [hlen, hbeg, hend, ibeg, iend]: hb) {
    // Sort hashes and ridx together
    HashRecordIterator hrbeg(0, hbeg->rec.data(), hlen, ibeg);
    HashRecordIterator hrend(iend - ibeg, hbeg->rec.data(), hlen, ibeg);
    std::sort(hrbeg, hrend);
  }

//  std::cerr << "sorted HDAT blocks\n";
}

// TODO: switch to a std::view for producing these lazily
std::vector<std::string_view> split(std::string_view s, char delim) {
  std::vector<std::string_view> splits;

  // a trailing delimiter yields a final empty column, so that an absent
  // last field ("<md5> ") is distinguishable from a missing column
  auto i = s.begin();
  while (true) {
    auto j = std::find(i, s.end(), delim);
    /*
    * This is a workaround for clang <= 14. Once 15 is out
    * we should remove this #if.
    */
// C++20: #if defined __clang__ && __clang_major__ <= 14
    splits.emplace_back(i, std::distance(i, j));
// C++20: #else
// C++20: splits.emplace_back(i, j);
// C++20: #endif
    if (j == s.end()) {
      break;
    }
    i = j + 1;
  }

  return splits;
}

void write_hset(
  std::istream& in,
  const std::vector<SFHASH_HashAlgorithm>& htypes,
  const std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>& conv,
  const char* hset_name,
  const char* hset_desc,
  const std::filesystem::path& outfile,
  const std::filesystem::path& tmpdir,
  bool with_records,
  bool with_hashsets,
  uint32_t tlsh_options)
{
  SFHASH_Error* err = nullptr;

  auto bctx = make_unique_del(
    sfhash_hashset_builder_open(
      hset_name,
      hset_desc,
      htypes.data(),
      htypes.size(),
      with_records,
      with_hashsets,
      outfile.string().c_str(),
      tmpdir.string().c_str(),
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  THROW_IF(err, err->message);

  sfhash_hashset_builder_set_tlsh_options(bctx.get(), tlsh_options);

  std::vector<uint8_t> rec;
  std::string line;
  size_t lineno = 0;
  while (in) {
    std::getline(in, line);

    ++lineno;
  //    if (lineno % 10000 == 0) {
  //      std::cerr << "read " << lineno << " lines\n";
  //    }

    if (line.empty()) {
      continue;
    }

    const auto& cols = split(line, ' ');

    THROW_IF(cols.size() > htypes.size(), "too many columns at line " << lineno);
    THROW_IF(cols.size() < htypes.size(), "too few columns at line " << lineno);

    for (size_t i = 0; i < cols.size(); ++i) {
      // a null TLSH digest has no row, so treat it like an absent field
      if (cols[i].empty() || (htypes[i] == SFHASH_TLSH && cols[i] == "TNULL")) {
        rec.clear();
      }
      else {
        rec.resize(conv[i].second);
        conv[i].first(
          rec.data(),
          cols[i].data(),
          conv[i].second
        );
      }

      sfhash_hashset_builder_add_hash(bctx.get(), rec.data(), rec.size());
    }

//  if (lineno % 10000) {
//  std::cerr << "read " << lineno << " lines\n";
//  }
  }

  sfhash_hashset_builder_write(bctx.get(), &err);

  THROW_IF(err, err->message);
}

SFHASH_HashsetBuildCtx* hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* tmp_dir)
{
  auto bctx = make_unique_del(
    new SFHASH_HashsetBuildCtx{
      {},
      { 2, hashset_name, make_timestamp(), hashset_desc, {} },
      { 0, 0, {} },
      {},
      {},
      write_records,
      write_hashsets,
      {},
      {},
      {},
      {},
      0
    },
    sfhash_hashset_builder_destroy
  );

  auto& rhdr = bctx->rhdr;

  // validate the args
  check_strlen(hashset_name, "hashset_name");
  check_strlen(hashset_desc, "hashset_desc");

  THROW_IF(
    record_order_length == 0,
    "record_order_length == 0, but there must be at least one record type"
  );

  std::set<SFHASH_HashAlgorithm> tset;

  for (size_t i = 0; i < record_order_length; ++i) {
    try {
      THROW_IF(
        !tset.emplace(record_order[i]).second,
        "duplicate hash type " << std::to_string(record_order[i])
      );

      const auto& hi = FIELDS.at(record_order[i]).first;
      rhdr.fields.emplace_back(hi);
      rhdr.record_length += 1 + hi.length;
    }
    catch (const std::out_of_range&) {
      THROW("uknown hash type " << std::to_string(record_order[i]));
    }
  }

  THROW_IF(
    !write_records && !write_hashsets,
    "at least one of records and hashsets must be written"
  );

  bctx->outfile = output_file;
  auto& outfile = bctx->outfile;

  // touch the output file so it exists (can't resize a file ab initio)
  {
    std::ofstream of;
    of.exceptions(std::ofstream::failbit);
    of.open(outfile);
  }

  // establish locations of initial chunks

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;

  uint64_t off = 0;

  off += length_magic();
  off += length_hset_hash();

  // FTOC; reserve room for the chunks this mode will write, matching the
  // length_hset* function used by hashset_builder_write
  const size_t chunk_count = write_records ?
    (write_hashsets ? count_chunks(rhdr.fields) : 5) :
    count_chunks_hashsets_only(rhdr.fields);

  ftoc.entries.emplace_back(off, Chunk::Type::FTOC);
  off += length_ftoc(chunk_count);

  // FHDR
  ftoc.entries.emplace_back(off, Chunk::Type::FHDR);
  off += length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

  if (write_records) {
    // RHDR
    ftoc.entries.emplace_back(off, Chunk::Type::RHDR);
    off += length_rhdr(rhdr.fields);

    // RDAT
    ftoc.entries.emplace_back(off, Chunk::Type::RDAT);

    // resize the output file so the start of the RDAT data is at the end
    std::filesystem::resize_file(outfile, off + 12);

    // open the output file ready for appending
    auto& out = bctx->out;
    out.exceptions(std::ofstream::failbit);
    out.open(outfile, std::ios::binary | std::ios::app);
  }
  else { // write_hashsets
    auto& hsets = bctx->hsets;
    auto& tmp_hashes_files = bctx->tmp_hashes_files;
    auto& tmp_hashes_out = bctx->tmp_hashes_out;

    for (const auto& field: rhdr.fields) {
      // initialize the hashsets from the RHDR fields
      hsets.emplace_back(
        HashsetHeader{ field.type, field.name, field.length, 0 },
        HashsetHint{},
        HashsetData{},
        RecordIndex{}
      );

      // open the temp files for receiving the hashes
      const auto f = std::string(tmp_dir) + "/tmp_" + std::to_string(field.type);
      const auto& p = tmp_hashes_files.emplace_back(f);

      std::ofstream tof;
      tof.exceptions(std::ofstream::failbit);
      tof.open(p, std::ios::binary | std::ios::trunc);
      tmp_hashes_out.push_back(std::move(tof));
    }
  }

  return bctx.release();
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* tmp_dir,
  SFHASH_Error** err)
{
  try {
    return hashset_builder_open(
      hashset_name,
      hashset_desc,
      record_order,
      record_order_length,
      write_records,
      write_hashsets,
      output_file,
      tmp_dir
    );
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return 0;
  }
}

void sfhash_hashset_builder_set_tlsh_options(
  SFHASH_HashsetBuildCtx* bctx,
  uint32_t options)
{
  bctx->tlsh_options = options;
}

void sfhash_hashset_builder_add_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record)
{
  auto& rhdr = bctx->rhdr;
  auto& field_pos = bctx->field_pos;

  if (bctx->with_records) {
    auto& out = bctx->out;
    out.write(static_cast<const char*>(record), rhdr.record_length);
  }
  else { // with_hashsets
    // TODO: implement
  }

  // advance the field position
  field_pos = 0;
  // advance the record count
  ++rhdr.record_count;
}

void sfhash_hashset_builder_add_hash(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record,
  size_t length)
{
// TODO: check length?

  auto& field_pos = bctx->field_pos;
  auto& rhdr = bctx->rhdr;

  if (bctx->with_records) {
    auto& out = bctx->out;
    if (length > 0) {
      out.put(1);
      out.write(static_cast<const char*>(record), length);
    }
    else {
      // absent field: presence byte and value are all zero
      const std::vector<char> buf(1 + rhdr.fields[field_pos].length, 0);
      out.write(buf.data(), buf.size());
    }
  }
  else { // with_hashsets
    if (length > 0) {
      auto& out = bctx->tmp_hashes_out[field_pos];
      out.write(static_cast<const char*>(record), length);
      ++std::get<HashsetHeader>(bctx->hsets[field_pos]).hash_count;
    }
  }

  // advance the field position
  ++field_pos;
  // advance the record count if we've finished a record
  if ((field_pos %= rhdr.fields.size()) == 0) {
    ++rhdr.record_count;
  }
}

uint64_t hashset_builder_write(SFHASH_HashsetBuildCtx* bctx) {
  const auto& outfile = bctx->outfile;

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;
  auto& rhdr = bctx->rhdr;
  auto& rdat = bctx->rdat;

  uint64_t off = 0;

  if (bctx->with_records) {
    bctx->out.close();

    const uint64_t rdat_off = ftoc.entries.back().first;

    // Sort and deduplicate the records in place, then count the hashes
    // present per field and build the TLSH indexes: the final file size
    // depends on all of these, so they come before the file is resized.
    std::vector<uint64_t> hash_counts(rhdr.fields.size(), 0);
    bctx->tlsh_ivfs.assign(rhdr.fields.size(), TlshIvf());
    {
      bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
      bip::mapped_region mr(fm, bip::read_write);

      uint8_t* out = static_cast<uint8_t*>(mr.get_address());

      RecordIterator rbeg(out + rdat_off + 12, rhdr.record_length);
      RecordIterator rend(out + rdat_off + 12 + rhdr.record_count * rhdr.record_length, rhdr.record_length);

      std::sort(rbeg, rend);
      rend = std::unique(rbeg, rend);

      rhdr.record_count = rend - rbeg;

      if (bctx->with_hashsets) {
        count_hashes_and_build_indexes(
          rhdr, rbeg, rend, bctx->tlsh_options, hash_counts, bctx->tlsh_ivfs
        );
      }
    }

    const auto hset_size = bctx->with_hashsets ?
      length_hset(
        bctx->fhdr.name,
        bctx->fhdr.desc,
        bctx->fhdr.time,
        bctx->rhdr.fields,
        bctx->rhdr.record_count,
        hash_counts,
        bctx->tlsh_ivfs,
        bctx->tlsh_options
      )
      :
      length_hset_records_only(
        bctx->fhdr.name,
        bctx->fhdr.desc,
        bctx->fhdr.time,
        bctx->rhdr.fields,
        bctx->rhdr.record_count
      );

    std::filesystem::resize_file(outfile, hset_size);

    bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    uint8_t* out = static_cast<uint8_t*>(mr.get_address());

    rdat.beg = out + rdat_off + 12;
    rdat.end = rdat.beg + rhdr.record_count * rhdr.record_length;

    off = rdat_off + length_rdat(rhdr.fields, rhdr.record_count);

    std::vector<
      std::tuple<
        uint64_t,
        RecordIterator,
        RecordIterator,
        uint64_t*,
        uint64_t*
      >
    > hb;

    std::map<uint64_t, size_t> off2hbidx;

    if (bctx->with_hashsets) {
      for (const auto& field: rhdr.fields) {
        // Determine locations for each hash block
        const size_t hbidx = hb.size();

        // HHnn
        ftoc.entries.emplace_back(off, make_hhnn_type(field.type));
        off2hbidx[off] = hbidx;
        off += length_hhnn(field);

        // HINT
        if (field.type != SFHASH_SIZE) {
          ftoc.entries.emplace_back(off, Chunk::Type::HINT);
          off2hbidx[off] = hbidx;
          off += length_hint(field.type);
        }

        // HDAT
        off += length_alignment_padding(off, 4096);
        ftoc.entries.emplace_back(off, Chunk::Type::HDAT);
        off2hbidx[off] = hbidx;

        hb.emplace_back(
          field.length,
          RecordIterator(out + off + 12, field.length),
          RecordIterator(out + off + 12, field.length),
          nullptr,
          nullptr
        );

        off += length_hdat(hash_counts[hbidx], field.length);

        // RIDX
        ftoc.entries.emplace_back(off, Chunk::Type::RIDX);
        off2hbidx[off] = hbidx;

        std::get<4>(hb.back()) = std::get<3>(hb.back()) = reinterpret_cast<uint64_t*>(out + off + 12);

        off += length_ridx(hash_counts[hbidx]);

        // TVEC, TIVF
        off = layout_tlsh_chunks(
          off, field, hash_counts[hbidx], bctx->tlsh_ivfs[hbidx],
          bctx->tlsh_options, hbidx, &ftoc, &off2hbidx
        );
      }
    }

    // FEND
    ftoc.entries.emplace_back(off, Chunk::Type::FEND);
    off += length_fend();

    if (bctx->with_hashsets) {
      scatter_records_to_hashset(rhdr, rdat, hb);
    }

    // Write
    write_chunks(reinterpret_cast<char*>(out), ftoc, fhdr, rhdr, rdat, hb, off2hbidx, bctx->tlsh_ivfs);
  }
  else if (bctx->with_hashsets) {
    // close the temp files
    bctx->tmp_hashes_out.clear();

    bctx->tlsh_ivfs.assign(bctx->hsets.size(), TlshIvf());

    for (size_t i = 0; i < bctx->hsets.size(); ++i) {
      const auto& f = bctx->tmp_hashes_files[i];
      auto fsize = std::filesystem::file_size(f);

      auto& hhdr = std::get<HashsetHeader>(bctx->hsets[i]);

      {
        bip::file_mapping fm(f.string().c_str(), bip::read_write);
        bip::mapped_region mr(fm, bip::read_write);

        uint8_t* out = static_cast<uint8_t*>(mr.get_address());

        RecordIterator hbeg(out, hhdr.hash_length);
        RecordIterator hend(out + fsize, hhdr.hash_length);

        std::sort(hbeg, hend);
        hend = std::unique(hbeg, hend);

        fsize = hend->rec.data() - out;
        hhdr.hash_count = hend - hbeg;

        // the TLSH index is built from the sorted, deduplicated rows, which
        // are copied verbatim into the HDAT below
        if (wants_tivf(rhdr.fields[i], bctx->tlsh_options)) {
          const auto* tbeg = reinterpret_cast<const TlshDigest*>(out);
          bctx->tlsh_ivfs[i] = build_tlsh_ivf(tbeg, tbeg + hhdr.hash_count, TLSH_IVF_TARGET_LIST_SIZE);
        }
      }

      std::filesystem::resize_file(f, fsize);
    }

    const auto hset_size = length_hset_hashsets_only(
      bctx->fhdr.name,
      bctx->fhdr.desc,
      bctx->fhdr.time,
      bctx->rhdr.fields,
      bctx->hsets,
      bctx->tlsh_ivfs,
      bctx->tlsh_options
    );

    std::filesystem::resize_file(outfile, hset_size);

    bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    char* out = static_cast<char*>(mr.get_address());

    std::vector<
      std::tuple<
        uint64_t,
        RecordIterator,
        RecordIterator,
        uint64_t*,
        uint64_t*
      >
    > hb;

    std::map<uint64_t, size_t> off2hbidx;

    off = ftoc.entries.back().first + length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

    for (size_t i = 0; i < rhdr.fields.size(); ++i) {
      const auto& field = rhdr.fields[i];

      // HHnn
      ftoc.entries.emplace_back(off, make_hhnn_type(field.type));
      off2hbidx[off] = i;
      off += length_hhnn(field);

      // HINT
      if (field.type != SFHASH_SIZE) {
        ftoc.entries.emplace_back(off, Chunk::Type::HINT);
        off2hbidx[off] = i;
        off += length_hint(field.type);
      }

      // HDAT
      off += length_alignment_padding(off, 4096);
      ftoc.entries.emplace_back(off, Chunk::Type::HDAT);
      off2hbidx[off] = i;

      auto& hhdr = std::get<HashsetHeader>(bctx->hsets[i]);
      auto& hdat = std::get<HashsetData>(bctx->hsets[i]);

      const auto& f = bctx->tmp_hashes_files[i];

      const auto fsize = std::filesystem::file_size(f);

      {
        std::ifstream tif;
        tif.exceptions(std::ifstream::failbit);
        tif.open(f, std::ios::binary);
        tif.read(out + off + 12, fsize);
      }
      std::filesystem::remove(f);

      hdat.beg = reinterpret_cast<uint8_t*>(out) + off + 12;
      hdat.end = hdat.beg + fsize;

      RecordIterator hbeg(hdat.beg, hhdr.hash_length);
      RecordIterator hend(hdat.end, hhdr.hash_length);

      hhdr.hash_count = hend - hbeg;

      hb.emplace_back(
        field.length,
        hbeg,
        hend,
        nullptr,
        nullptr
      );

      off += length_hdat(hhdr.hash_count, hhdr.hash_length);

      // TVEC, TIVF
      off = layout_tlsh_chunks(
        off, field, hhdr.hash_count, bctx->tlsh_ivfs[i],
        bctx->tlsh_options, i, &ftoc, &off2hbidx
      );
    }

    // FEND
    ftoc.entries.emplace_back(off, Chunk::Type::FEND);
    off += length_fend();

    // Write
    write_chunks(out, ftoc, fhdr, rhdr, rdat, hb, off2hbidx, bctx->tlsh_ivfs);
  }

  std::filesystem::resize_file(outfile, off);

  return off;
}

uint64_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err)
{
  try {
    return hashset_builder_write(bctx);
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return 0;
  }
}

void sfhash_hashset_builder_destroy(SFHASH_HashsetBuildCtx* bctx) {
  delete bctx;
}

const std::map<
  SFHASH_HashAlgorithm,
  std::pair<
    void (*)(uint8_t* dst, const char* src, size_t dlen),
    size_t
  >
> CONV{
  { SFHASH_MD5,       { from_hex, 16 } },
  { SFHASH_SHA_1,     { from_hex, 20 } },
  { SFHASH_SHA_2_224, { from_hex, 28 } },
  { SFHASH_SHA_2_256, { from_hex, 32 } },
  { SFHASH_SHA_2_384, { from_hex, 48 } },
  { SFHASH_SHA_2_512, { from_hex, 64 } },
  { SFHASH_SHA_3_224, { from_hex, 28 } },
  { SFHASH_SHA_3_256, { from_hex, 32 } },
  { SFHASH_SHA_3_384, { from_hex, 48 } },
  { SFHASH_SHA_3_512, { from_hex, 64 } },
  { SFHASH_BLAKE3,    { from_hex, 32 } },
  { SFHASH_SIZE,      { size_to_u64, 8 } },
  { SFHASH_TLSH,      { tlsh_hex_to_digest, 36 } }
};

std::vector<
  std::pair<
    void (*)(uint8_t* dst, const char* src, size_t dlen),
    size_t
  >
>
make_text_converters(const std::vector<SFHASH_HashAlgorithm>& htypes) {
  // collect the converter functions
  std::vector<
    std::pair<
      void (*)(uint8_t* dst, const char* src, size_t dlen),
      size_t
    >
  > conv;

  for (const auto& ht: htypes) {
    conv.push_back(CONV.at(ht));
  }

  return conv;
}
