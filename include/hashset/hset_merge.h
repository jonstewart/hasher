#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "hasher/hashset.h"
#include "hashset/hset_structs.h"
#include "hashset/tlsh_ivf.h"

/*
 * Merge-based set operations on hset files, see HASHSET_FORMAT "Set
 * operations". The two inputs are loaded hashsets; every output section is
 * produced by a two-pointer merge of the inputs' sorted sections, driven by
 * per-row maps (old row -> new row, or MERGE_DROPPED) that the derived
 * structures (RIDX, TVEC, TIVF) are carried through.
 */

enum class MergeOp {
  UNION = SFHASH_HSET_OP_UNION,
  INTERSECT = SFHASH_HSET_OP_INTERSECT,
  DIFFERENCE = SFHASH_HSET_OP_DIFFERENCE
};

MergeOp make_merge_op(uint32_t op);

// a row that the merge does not emit (same value as TLSH_IVF_DROPPED)
constexpr uint32_t MERGE_DROPPED = UINT32_MAX;

// a record that the merge does not emit
constexpr uint64_t MERGE_RECORD_DROPPED = UINT64_MAX;

/*
 * Merges two sorted runs of fixed-length rows. Fills lmap and rmap with one
 * entry per input row (the output row or MERGE_DROPPED) and returns the
 * output row count; the output row k is the input row mapped to k.
 *
 * Without record maps (lrecmap == rrecmap == nullptr) the runs are treated
 * as sets: equal rows, within a run or across the runs, are emitted once
 * (the left copy for rows on both sides) subject to the operation.
 *
 * With record maps the rows belong to records (lridx[i] is the record of
 * left row i, lrecmap that record's fate) and the operation has already
 * been applied to the records: a row is emitted iff its record was, and
 * equal rows are not collapsed unless collapse_equal is set (for a
 * hashsets-only output of a record-level operation, where equal rows are
 * written once). On ties left rows precede right rows.
 */
uint64_t merge_rows(
  MergeOp op,
  const uint8_t* lbeg,
  uint64_t ln,
  const uint8_t* rbeg,
  uint64_t rn,
  size_t len,
  const uint64_t* lridx,
  const uint64_t* lrecmap,
  const uint64_t* rridx,
  const uint64_t* rrecmap,
  std::vector<uint32_t>& lmap,
  std::vector<uint32_t>& rmap,
  bool collapse_equal = false
);

struct RecordMerge {
  std::vector<RecordFieldDescriptor> fields; // the output fields
  uint64_t record_length = 0;
  std::vector<uint8_t> rdat;                 // output records, sorted and unique
  std::vector<uint64_t> lmap, rmap;          // input record -> output record or MERGE_RECORD_DROPPED
  uint64_t record_count() const { return record_length ? rdat.size() / record_length : 0; }
};

// The output fields of merging two record tables: the left fields followed
// by the right fields the left lacks. Throws if a field has different
// lengths on the two sides.
std::vector<RecordFieldDescriptor> merged_record_fields(
  const RecordHeader& lrhdr,
  const RecordHeader& rrhdr
);

/*
 * Merges two record tables. The output fields are merged_record_fields;
 * records are widened to them (absent fields are zero) and merged in sorted
 * order, identical records collapsing to one. For INTERSECT and DIFFERENCE
 * only left records are emitted, so rmap is all MERGE_RECORD_DROPPED.
 */
RecordMerge merge_records(
  MergeOp op,
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

/*
 * Options of write_merged_hset.
 *
 * tlsh_options is a bitwise OR of SFHASH_HSET_TLSH_* values; with
 * SFHASH_HSET_TLSH_INHERIT each optional TLSH section is written iff every
 * input side that has a TLSH section has it. An index is carried through
 * the merge when every side has one and otherwise built from scratch with
 * the method SFHASH_HSET_TLSH_INDEX_KMEANS selects (tlsh_ivf_build_of).
 *
 * coalesce_threshold is C of merge_tlsh_ivf (0 disables coalescing).
 *
 * The output has a record table iff both inputs have one and write_records
 * is set; hash sections iff the inputs have them and write_hashsets is set.
 * When both inputs have records the operation is applied to the records
 * (rows follow their records) whether or not the table is written; without
 * it the rows are then deduplicated like any hashsets-only file.
 */
struct MergeOptions {
  uint32_t tlsh_options = SFHASH_HSET_TLSH_INHERIT;
  uint32_t coalesce_threshold = TLSH_IVF_DEFAULT_COALESCE;
  bool write_records = true;
  bool write_hashsets = true;
};

// Writes the merge of l and r to outfile and returns its size.
uint64_t write_merged_hset(
  const SFHASH_Hashset& l,
  const SFHASH_Hashset& r,
  MergeOp op,
  const std::string& name,
  const std::string& desc,
  const std::filesystem::path& outfile,
  const MergeOptions& options
);
