#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "hasher/hashset.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hashset/tlsh_search.h"

/*
 * Inverted-file index over the body embedding of a sorted TLSH hash set.
 * See docs/TLSH_EMBEDDING.md section 3.
 *
 * Rows are grouped by header cell (L, Q1, Q2), which is contiguous in
 * canonical order, and each cell is split by k-means over the 256-dim body
 * embedding into about cell_size / target_list_size lists. The header part of
 * the TLSH distance is therefore exact per cell, and the embedding is used
 * where it carries information: as a lower bound on the body cost. Each list
 * keeps a medoid (the member nearest the k-means centroid) and the squared
 * embedding radius about it, so the bound for a list is one popcount kernel
 * evaluation (tlsh_embed_body_dist2) and a triangle inequality. The search
 * is exact for every distance, with or without the length term.
 */
struct TlshIvf {
  uint64_t n = 0;
  std::vector<uint32_t> cell_lists;  // TLSH_CELL_COUNT + 1: lists of cell c are [cell_lists[c], cell_lists[c+1])
  std::vector<TlshDigest> medoids;   // lists
  std::vector<uint32_t> radius2;     // lists: max tlsh_embed_body_dist2(medoid, member)
  std::vector<uint64_t> list_start;  // lists + 1
  std::vector<uint32_t> ids;         // n, HDAT row indexes, ascending within a list

  size_t lists() const { return radius2.size(); }
};

// Builds the index over sorted rows [beg, end). Cells are clustered in
// parallel on `threads` threads (0 = hardware concurrency); the result does
// not depend on the thread count.
TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size = 32,
  uint64_t seed = 0x7175657279,
  unsigned threads = 0
);

// Read-only view over a serialized TIVF payload (pointers into mapped memory).
struct TlshIvfView {
  uint32_t lists = 0;
  uint64_t n = 0;
  const uint32_t* cell_lists = nullptr;
  const TlshDigest* medoids = nullptr;
  const uint32_t* radius2 = nullptr;
  const uint64_t* list_start = nullptr;
  const uint32_t* ids = nullptr;

  bool empty() const { return !ids; }
};

TlshIvfView make_tlsh_ivf_view(const TlshIvf& ivf);

size_t length_tivf_data(uint32_t lists, uint64_t n);

size_t write_tivf_data(const TlshIvf& ivf, char* out);

// throws on malformed input; the returned view points into [beg, end)
TlshIvfView parse_tivf_data(const uint8_t* beg, const uint8_t* end);

/*
 * Exact k nearest neighbours by TLSH distance, nearest first, ties by
 * ascending index, at most k, all with distance <= max_distance.
 */
std::vector<SFHASH_TlshMatch> tlsh_knn_ivf(
  const TlshIvfView& ivf,
  const TlshDigest* rows,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  TlshKnnStats* stats = nullptr
);
