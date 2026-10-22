#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iosfwd>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "rwutil.h"
#include "hasher/hashset.h"
#include "hashset/hset_structs.h"
#include "hashset/tlsh_ivf.h"

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
