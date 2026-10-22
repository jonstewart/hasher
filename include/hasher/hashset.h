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

/*
 * Pointer to the n x dims float32 row-major embedding matrix (TVEC section)
 * of a TLSH hashset, or NULL if the file has no vectors. *dims receives
 * SFHASH_TLSH_EMBEDDING_DIMS (0 when NULL is returned); n is
 * sfhash_hashset_count. Row r is sfhash_tlsh_embed of
 * sfhash_hashset_hash(hset, tidx, r). The data starts on a 4096-byte
 * boundary of the file.
 */
const float* sfhash_hashset_tlsh_vectors(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t* dims
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
 * Optional sections of TLSH hashsets: the embedding vectors (TVEC) and the
 * kNN index (TIVF). The default is both.
 */
enum {
  SFHASH_HSET_TLSH_VECTORS = 1,
  SFHASH_HSET_TLSH_INDEX = 2
};

/*
 * Select which optional TLSH sections to write; options is a bitwise OR of
 * SFHASH_HSET_TLSH_* values (0 for neither). Only TLSH hashsets are
 * affected, and only when hashsets are written. Call after *_open and
 * before *_write.
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

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHSET_H_ */
