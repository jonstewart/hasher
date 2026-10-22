#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "tlsh_digest.h"

/*
 * TLSH cell index
 *
 * TLSH rows in an hset are sorted bytewise, which for the canonical digest
 * layout is (L, Q1, Q2, body, checksum) order. The cell of a digest is its
 * first two bytes, (L << 8) | Q, so each cell is a contiguous run of rows.
 * The cell index records where each run starts: the rows of cell c are
 * [offset[c], offset[c+1]), with offset[0] == 0 and offset[65536] == n.
 */

constexpr size_t TLSH_CELL_COUNT = 65536;

// HINT type for the cell index, stored big-endian
constexpr uint16_t TLSH_CELL_HINT_TYPE = 0x7400;

inline uint32_t tlsh_cell_id(const TlshDigest& d) {
  return (static_cast<uint32_t>(d.L) << 8) | d.Q;
}

// returns TLSH_CELL_COUNT + 1 offsets; [beg, end) must be sorted
std::vector<uint64_t> make_tlsh_cell_index(const TlshDigest* beg, const TlshDigest* end);
