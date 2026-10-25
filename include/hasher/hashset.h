#ifndef HASHER_HASHSET_H_
#define HASHER_HASHSET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <hasher/common.h>
#include <hasher/tlsh.h>

#ifdef __cplusplus
extern "C" {
#endif

struct SFHASH_Hashset;

/*
 * Load a hashset
 *
 * The buffer [beg, end) is used directly and the caller remains responsible
 * for freeing it.
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_Hashset* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Free a hashset
 */
void sfhash_destroy_hashset(SFHASH_Hashset* hset);

/*
 * Returns the name of a hashset.
 */
const char* sfhash_hashset_name(const SFHASH_Hashset* hset);

/*
 * Returns the description of a hashset.
 */
const char* sfhash_hashset_description(const SFHASH_Hashset* hset);

/*
 * Returns the ISO-8601 timestamp of a hashset.
 */
const char* sfhash_hashset_timestamp(const SFHASH_Hashset* hset);

/*
 * Returns the SHA2-256 hash of the hashset data.
 *
 * The hash is produced from the hset file from offset 40 to the end.
 */
const void* sfhash_hashset_sha2_256(const SFHASH_Hashset* hset);

/*
 * Get hashset data index for the given hash type.
 *
 * Returns the index, or -1 if the is no data for the specified type.
 */
int sfhash_hashset_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype
);

/*
 * Get the number of hashes in the hashset with the given index.
 */
uint64_t sfhash_hashset_count(
  const SFHASH_Hashset* hset,
  size_t tidx
);

/*
 *  Check if the given hash is contained in a hashset.
 *
 *  The type index is the index returned by sfhash_hashset_index_for_type.
 */
bool sfhash_hashset_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

void sfhash_hashset_lookup_bulk(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hashes,
  size_t hashes_length,
  bool* results
);

/*
 * Returns a pointer to the idx-th hash (row) of the hashset with index tidx.
 * Rows are sorted bytewise; idx must be less than sfhash_hashset_count.
 */
const void* sfhash_hashset_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t idx
);

/*
 * A TLSH nearest-neighbour match. index is a row index usable with
 * sfhash_hashset_hash and sfhash_hashset_record_for_hash.
 */
struct SFHASH_TlshMatch {
  uint64_t index;
  uint32_t distance;
};

/*
 * k nearest neighbours by TLSH distance (see sfhash_tlsh_diff).
 *
 * Writes to out the rows with distance <= max_distance, nearest first, ties
 * by ascending index, at most k of them. out must have room for k matches.
 *
 * Uses the hashset's TIVF index when the file has one (see
 * sfhash_hashset_tlsh_knn_strategies) and brute force otherwise. Both give
 * identical results for every max_distance, with or without the length.
 *
 * Returns the number of matches written, or 0 if tidx is not a TLSH
 * hashset, digest is null, or digest is the null digest.
 */
size_t sfhash_hashset_tlsh_knn(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* digest,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  SFHASH_TlshMatch* out
);

/*
 * kNN strategies. BRUTE scans every row; INDEX prunes with the TIVF
 * inverted-file index stored in the file. Both are exact.
 */
enum {
  SFHASH_TLSH_KNN_BRUTE = 1,
  SFHASH_TLSH_KNN_INDEX = 2
};

/*
 * Which kNN strategies the hashset supports: the bitwise OR of
 * SFHASH_TLSH_KNN_BRUTE (always, for a TLSH hashset) and
 * SFHASH_TLSH_KNN_INDEX (when the file has a TIVF index). Returns 0 if tidx
 * is not a TLSH hashset.
 */
uint32_t sfhash_hashset_tlsh_knn_strategies(
  const SFHASH_Hashset* hset,
  size_t tidx
);

/*
 * kNN with an explicit strategy (exactly one of the SFHASH_TLSH_KNN_*
 * values). Same results and ordering as sfhash_hashset_tlsh_knn; returns 0
 * if the strategy is not supported by the hashset.
 */
size_t sfhash_hashset_tlsh_knn_with(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* digest,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  uint32_t strategy,
  SFHASH_TlshMatch* out
);

struct SFHASH_HashsetRecordRange {
  size_t beg;
  size_t end;
};

const SFHASH_HashsetRecordRange sfhash_hashset_records_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

struct SFHASH_HashsetRecord;

const SFHASH_HashsetRecord* sfhash_hashset_record_for_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t ridx
);

int sfhash_hashset_record_field_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype
);

const void* sfhash_hashset_record_field(
  const SFHASH_HashsetRecord* rec,
  size_t tidx
);

struct SFHASH_HashsetBuildCtx;

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

/*
 * The optional section of TLSH hashsets: the kNN index (TIVF), written by
 * default. Bit 1 (once the stored embedding vectors, TVEC, no longer part
 * of the format) is reserved and ignored.
 */
enum {
  SFHASH_HSET_TLSH_INDEX = 2,
  /* sfhash_hashset_merge only: write the index iff every input that has a
   * TLSH hashset has one; the other bits are ignored (an index is then
   * always carried through the merge, never rebuilt, so INDEX_KMEANS has
   * nothing to select) */
  SFHASH_HSET_TLSH_INHERIT = 4,
  /* build the TIVF index with the float k-means clustering instead of the
   * default integer build; the index is equally exact, builds in time
   * quadratic in the largest header cell, and its bytes depend on compiler
   * and platform. Applies wherever an index is built from scratch: by the
   * builder, and by a merge that writes an index when an input lacks one */
  SFHASH_HSET_TLSH_INDEX_KMEANS = 8
};

/*
 * Select the optional TLSH sections to write; options is a bitwise OR of
 * SFHASH_HSET_TLSH_* values (0 for none). Only TLSH hashsets are affected,
 * and only when hashsets are written. Call after *_open and before
 * *_write.
 */
void sfhash_hashset_builder_set_tlsh_options(
  SFHASH_HashsetBuildCtx* bctx,
  uint32_t options
);

void sfhash_hashset_builder_add_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record
);

void sfhash_hashset_builder_add_hash(
  SFHASH_HashsetBuildCtx* bctx,
  const void* hash,
  size_t length
);

uint64_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err
);

void sfhash_hashset_builder_destroy(SFHASH_HashsetBuildCtx* bctx);

/*
 * Set operations in the builder's shape: *_open returns a build context
 * for the union, intersection or difference (l minus r) of two loaded
 * hashsets, sfhash_hashset_builder_write writes the result to output_file
 * and sfhash_hashset_builder_destroy frees the context. The result is the
 * merge of the inputs exactly as sfhash_hashset_merge computes it (see
 * HASHSET_FORMAT, "Set operations"): records are written when both inputs
 * have record tables and write_records is set, hash sections when the
 * inputs have them and write_hashsets is set. The TLSH index is written by
 * default (sfhash_hashset_builder_set_tlsh_options changes that,
 * SFHASH_HSET_TLSH_INHERIT included) and the index coalescing threshold is
 * SFHASH_HSET_COALESCE_DEFAULT (sfhash_hashset_builder_set_coalesce_threshold).
 * Nothing can be added to such a context: write fails if
 * sfhash_hashset_builder_add_record or _add_hash was called on it. temp_dir
 * is accepted for compatibility and unused.
 */
SFHASH_HashsetBuildCtx* sfhash_hashset_builder_union_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_intersect_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_subtract_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

/*
 * The coalescing threshold (see SFHASH_HSET_COALESCE_DEFAULT below) of the
 * TLSH kNN index written by a set-operation build context. Call after *_open
 * and before *_write.
 */
void sfhash_hashset_builder_set_coalesce_threshold(
  SFHASH_HashsetBuildCtx* bctx,
  uint32_t coalesce_threshold
);

/*
 * Set operations on whole hashsets by merging.
 */
enum {
  SFHASH_HSET_OP_UNION = 1,
  SFHASH_HSET_OP_INTERSECT = 2,
  SFHASH_HSET_OP_DIFFERENCE = 3
};

/*
 * The coalescing threshold of a merged TLSH kNN index (C in
 * docs/TLSH_EMBEDDING.md section 3): per header cell, lists with fewer than
 * C / 2 rows are coalesced pairwise until at most one remains, which keeps
 * the index within one list per nonempty cell of a from-scratch build over
 * any number of incremental merges. 0 disables coalescing (lists are only
 * concatenated); SFHASH_HSET_COALESCE_DEFAULT selects the library default,
 * twice the target list size of a fresh build (64).
 */
enum {
  SFHASH_HSET_COALESCE_DEFAULT = 0xFFFFFFFF
};

/*
 * Merge-based set operation over two loaded hashsets; writes the result to
 * output_file. op is one of the SFHASH_HSET_OP_* values (DIFFERENCE is
 * l minus r).
 *
 * Every hash section of the output is produced by merging the two inputs'
 * sorted sections; TLSH cell indexes and kNN indexes are carried through
 * the merge rather than rebuilt (see HASHSET_FORMAT, "Set
 * operations"). The output has a record table only when both inputs have
 * one; otherwise it is a hashsets-only file and rows are deduplicated. An
 * input with hash sections cannot be merged with a records-only input.
 *
 * tlsh_options is a bitwise OR of SFHASH_HSET_TLSH_* values selecting the
 * optional TLSH index, or SFHASH_HSET_TLSH_INHERIT to write one iff the
 * inputs have one. coalesce_threshold is described above.
 *
 * Returns the size of the output file, or 0 on error (err set).
 */
uint64_t sfhash_hashset_merge(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  uint32_t op,
  const char* name,
  const char* desc,
  const char* output_file,
  uint32_t tlsh_options,
  uint32_t coalesce_threshold,
  SFHASH_Error** err
);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHSET_H_ */
