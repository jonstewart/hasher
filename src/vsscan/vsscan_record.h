#pragma once

// One scanned sample: its hashes and the TSV row vsscan writes for it.
// Nothing here touches libarchive, so the unit tests link it directly.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "hasher/hasher.h"

struct SampleRecord {
  std::string zip;     // archive file name (no directory)
  uint64_t index = 0;  // 0-based entry index within the archive
  std::string member;  // member path inside the archive
  uint64_t size = 0;
  uint8_t md5[16] = {};
  uint8_t sha1[20] = {};
  uint8_t sha256[32] = {};
  uint8_t tlsh[36] = {}; // canonical TLSH digest; all zero is TNULL
  std::string ssdeep;
  double entropy = 0.0;
};

// The SFHASH_* algorithms vsscan computes per sample.
uint32_t vsscan_hash_algs();

// Hashes [beg, end) with hasher (created with at least vsscan_hash_algs())
// and fills rec's size and hash fields. The hasher is reset first.
void hash_sample(
  SFHASH_Hasher* hasher,
  const uint8_t* beg,
  const uint8_t* end,
  SampleRecord& rec
);

// The TSV header line (no trailing newline):
// zip index member size md5 sha1 sha256 tlsh ssdeep entropy
const char* tsv_header();

// Backslash-escapes \, TAB, LF and CR so a value fits in one TSV column.
std::string tsv_escape(std::string_view s);
std::string tsv_unescape(std::string_view s);

// The TSV row for rec, with a trailing newline. tlsh is "T1" + 70 hex
// characters or "TNULL"; entropy has 9 decimal places.
std::string format_tsv_row(const SampleRecord& rec);

// Parses a row written by format_tsv_row (with or without the newline).
// Returns false for the header line, a blank line, or a malformed row.
bool parse_tsv_row(std::string_view line, SampleRecord& rec);

// If the basename of member is "VirusShare_" followed by 32 hex digits,
// stores them (lowercased) in md5_hex and returns true.
bool virusshare_name_md5(std::string_view member, std::string& md5_hex);
