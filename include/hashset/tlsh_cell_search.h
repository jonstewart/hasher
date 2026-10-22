#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "hasher/hashset.h"
#include "tlsh_digest.h"
#include "hashset/tlsh_search.h"

/*
 * Exact k nearest neighbours using the cell index (HINT 0x7400): cells are
 * visited in order of increasing header cost (L, then Q1/Q2) and a cell is
 * skipped once its header cost alone exceeds the k-th best distance found so
 * far. Within a cell only the body kernel runs. Results are identical to
 * tlsh_knn_brute. cells points at TLSH_CELL_COUNT + 1 offsets.
 */
std::vector<SFHASH_TlshMatch> tlsh_knn_cells(
  const TlshDigest* rows,
  const uint64_t* cells,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  TlshKnnStats* stats = nullptr
);
