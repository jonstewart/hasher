#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "hasher/hashset.h"
#include "tlsh_digest.h"
#include "tlsh_embedding.h"
#include "hashset/tlsh_search.h"

// TIVF lists hold about this many rows each: the k-means target of
// build_tlsh_ivf (T in docs/TLSH_EMBEDDING.md)
constexpr size_t TLSH_IVF_TARGET_LIST_SIZE = 32;

// default coalescing threshold of merge_tlsh_ivf (C in the docs): two lists
// of a cell are coalesced while both have fewer than C / 2 members
constexpr uint32_t TLSH_IVF_DEFAULT_COALESCE = 2 * TLSH_IVF_TARGET_LIST_SIZE;

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

/*
 * How build_tlsh_ivf partitions a cell into lists. Either way every member
 * of a list lies within the list's radius2 of its medoid, computed with the
 * integer kernel, so the search is exact; the method changes only the
 * partition, hence the rows a query scans and the build time.
 *
 * KMEANS: k-means++ seeding and Lloyd iterations in float over the cell's
 *   256-dim body embeddings, k = ceil(m / T) centroids; the medoid of a list
 *   is its member nearest the centroid. Costs Theta(m^2 / T) per cell of m
 *   rows, and the float accumulation order makes the index bytes depend on
 *   the compiler and platform.
 *
 * BISECT: integer kernel only (no floating point, so the index bytes are
 *   the same everywhere for the same rows and seed). A node of more than
 *   TLSH_IVF_BISECT_FLAT_MAX rows is split in two around two far-apart
 *   member pivots, with a median split when one side would be tiny; O(m)
 *   kernel calls per level. Each remaining node of s rows is clustered flat
 *   by k-medoids into at most ceil(s / T) lists: k-medoids++ seeding, then
 *   up to 10 rounds of nearest-medoid assignment and re-choosing each
 *   list's medoid as its member of least sum of squared distances; O(s / T
 *   + T) kernel calls per row and round, so linear in m for a fixed
 *   TLSH_IVF_BISECT_FLAT_MAX. Lists are in depth-first order of the nodes,
 *   each with its exact 1-center as medoid (the member minimizing the max
 *   distance to the others, which minimizes radius2). Lists smaller than
 *   C / 2, C = TLSH_IVF_BISECT_COALESCE_FACTOR * T, are then coalesced
 *   pairwise exactly as merge_tlsh_ivf does, so
 *   tlsh_ivf_check_invariant(index, C) holds.
 */
enum class TlshIvfBuild : uint8_t { KMEANS, BISECT };

/*
 * BISECT splits a node in two only while it has more than this many rows;
 * a node of at most this many rows is clustered flat by integer k-medoids
 * into at most ceil(s / T) lists. Larger values cut fewer families across a split
 * boundary (fewer rows scanned) but cost O(s / T) kernel calls per row and
 * iteration in the flat clustering. A quality and build-cost knob only.
 */
constexpr size_t TLSH_IVF_BISECT_FLAT_MAX = 4096;

// the coalescing threshold of a BISECT build in units of T: C = factor * T,
// so lists below T / 2 are coalesced. 0 disables coalescing.
constexpr size_t TLSH_IVF_BISECT_COALESCE_FACTOR = 1;

// Builds the index over sorted rows [beg, end) with the given method. Cells
// are clustered in parallel on `threads` threads (0 = hardware concurrency);
// the result does not depend on the thread count.
TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size = TLSH_IVF_TARGET_LIST_SIZE,
  uint64_t seed = 0x7175657279,
  unsigned threads = 0,
  TlshIvfBuild method = TlshIvfBuild::KMEANS
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

/*
 * The id of a row that a merge drops, in the row maps below.
 */
constexpr uint32_t TLSH_IVF_DROPPED = UINT32_MAX;

/*
 * Merges two indexes over hash sets that have been merged into one of n_out
 * rows (rows, in output order), in O(lists + ids) plus the coalescing below,
 * and without re-clustering. a_map[i] (b_map[j]) is the output row of input
 * row i of a (j of b), or TLSH_IVF_DROPPED when the merge dropped it; maps
 * must be increasing over the kept rows of each side, which the sorted
 * two-pointer merge of the rows guarantees.
 *
 * For each cell the output lists are a's lists followed by b's, ids
 * remapped, dropped ids removed and lists that become empty omitted. A list
 * that lost members keeps its medoid and gets its radius2 recomputed exactly
 * over the remaining members; other lists keep medoid and radius2 verbatim
 * (the medoid need not be a member of its list, the search only needs every
 * member within radius2 of it).
 *
 * Then, with coalesce_threshold C > 0, lists of a cell are coalesced so that
 * plain concatenation cannot pile up small lists over repeated merges: while
 * the cell has two lists of fewer than C / 2 members each (so the pair sums
 * to less than C), the pair whose union has the smallest radius is replaced
 * by one list whose medoid is whichever of the two medoids gives that
 * radius (computed exactly with the kernel), radius2 that maximum, and ids
 * the sorted union. On exit at most one list per cell has fewer than C / 2
 * members (tlsh_ivf_check_invariant), which bounds the lists of a cell of m
 * rows by 2m / C + 1; see docs/TLSH_EMBEDDING.md section 3. C == 0 disables
 * coalescing. Either view may be empty (a side with no rows).
 */
TlshIvf merge_tlsh_ivf(
  const TlshIvfView& a,
  const uint32_t* a_map,
  const TlshIvfView& b,
  const uint32_t* b_map,
  const TlshDigest* rows,
  uint64_t n_out,
  uint32_t coalesce_threshold = TLSH_IVF_DEFAULT_COALESCE
);

// The coalescing invariant of merge_tlsh_ivf: at most one list per cell has
// fewer than coalesce_threshold / 2 members. Trivially true for a threshold
// of 0.
bool tlsh_ivf_check_invariant(const TlshIvfView& v, uint32_t coalesce_threshold);

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
