#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iosfwd>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <algorithm>
#include <ctime>
#include <limits>

#include "rwutil.h"
#include "hasher/hashset.h"
#include "hashset/hset_structs.h"
#include "hashset/record_iterator.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/util.h"

// ISO-8601 UTC timestamp for the FHDR
std::string make_timestamp(std::time_t tt = std::time(nullptr));

// the 0x6208 HINT data: per leading-byte block, the extreme offsets of the
// rows from their expected positions
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

struct SFHASH_HashsetBuildCtx {
  TableOfContents ftoc;
  FileHeader fhdr;
  RecordHeader rhdr;
  RecordData rdat;
  std::vector<
    std::tuple<
      HashsetHeader,
      HashsetHint,
      HashsetData,
      RecordIndex
    >
  > hsets;

  bool with_records;
  bool with_hashsets;

  std::filesystem::path outfile;
  std::ofstream out;

  std::vector<std::filesystem::path> tmp_hashes_files;
  std::vector<std::ofstream> tmp_hashes_out;

  size_t field_pos;

  // which optional TLSH sections to write, SFHASH_HSET_TLSH_* bits
  uint32_t tlsh_options = SFHASH_HSET_TLSH_VECTORS | SFHASH_HSET_TLSH_INDEX;

  // one per field: the TIVF index of a TLSH field that gets one, built from
  // the sorted rows before the layout is computed; empty otherwise
  std::vector<TlshIvf> tlsh_ivfs;

  // the k-means target list size of those indexes (not settable through the
  // C API; benchmarks vary it)
  size_t tlsh_ivf_target_list_size = TLSH_IVF_TARGET_LIST_SIZE;

  // set by the set-operation opens (sfhash_hashset_builder_union_open and
  // friends): write then performs write_merged_hset of these two inputs
  // instead of encoding added records or hashes
  const SFHASH_Hashset* merge_left = nullptr;
  const SFHASH_Hashset* merge_right = nullptr;
  uint32_t merge_op = 0;
  uint32_t coalesce_threshold = TLSH_IVF_DEFAULT_COALESCE;
  bool merge_input_added = false; // add_record/add_hash was called on a set-operation context
};

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::vector<uint8_t>& out
);

void size_to_u64(uint8_t* dst, const char* src, size_t dlen);

// decodes a hex TLSH string (70 hex chars, optional "T1" prefix); throws on
// invalid input
void tlsh_hex_to_digest(uint8_t* dst, const char* src, size_t dlen);

void check_strlen(const char* s, const char* sname);

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
  uint32_t tlsh_options = SFHASH_HSET_TLSH_VECTORS | SFHASH_HSET_TLSH_INDEX
);

std::vector<
  std::pair<
    void (*)(uint8_t* dst, const char* src, size_t dlen),
    size_t
  >
>
make_text_converters(const std::vector<SFHASH_HashAlgorithm>& htypes);
