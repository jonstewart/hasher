#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "hasher/hashset.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"

/*
 * Inverted-file index over the lower-bound embedding of a sorted TLSH
 * hash set. See docs/TLSH_EMBEDDING.md section 3.
 *
 * Rows are grouped by L (contiguous in canonical order) and each group is
 * split by k-means in embedding space into roughly group_size / target_list_size
 * lists. Because a list never spans L values, its centroid's L coordinate is
 * exactly the members' L, and the list radius is the same with or without the
 * length dimension.
 */
struct TlshIvf {
  uint32_t dims = TLSH_EMBED_DIMS;
  uint64_t n = 0;
  std::vector<float> centroids;     // lists x dims
  std::vector<float> radius;        // lists
  std::vector<uint64_t> list_start; // lists + 1
  std::vector<uint32_t> ids;        // n, HDAT row indexes, ascending within a list

  size_t lists() const { return radius.size(); }
};

TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size = 128,
  uint64_t seed = 0x7175657279
);

// Read-only view over a serialized TIVF payload (pointers into mapped memory).
struct TlshIvfView {
  uint32_t dims = 0;
  uint32_t lists = 0;
  uint64_t n = 0;
  const float* centroids = nullptr;
  const float* radius = nullptr;
  const uint64_t* list_start = nullptr;
  const uint32_t* ids = nullptr;

  bool empty() const { return !ids; }
};

TlshIvfView make_tlsh_ivf_view(const TlshIvf& ivf);

size_t length_tivf_data(uint32_t lists, uint64_t n);

size_t write_tivf_data(const TlshIvf& ivf, char* out);

// throws on malformed input
TlshIvfView parse_tivf_data(const uint8_t* beg, const uint8_t* end);

/*
 * Exact k nearest neighbours by TLSH distance using the index to prune.
 * max_distance is clamped to TLSH_EMBED_MAX_BOUNDED_DIFF when include_length
 * is true (beyond that the embedding is not a lower bound).
 */
std::vector<SFHASH_TlshMatch> tlsh_knn_ivf(
  const TlshIvfView& ivf,
  const TlshDigest* rows,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length
);
