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
 * equal rows are not collapsed. On ties left rows precede right rows.
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
  std::vector<uint32_t>& rmap
);

struct RecordMerge {
  std::vector<RecordFieldDescriptor> fields; // the output fields
  uint64_t record_length = 0;
  std::vector<uint8_t> rdat;                 // output records, sorted and unique
  std::vector<uint64_t> lmap, rmap;          // input record -> output record or MERGE_RECORD_DROPPED
  uint64_t record_count() const { return record_length ? rdat.size() / record_length : 0; }
};

/*
 * Merges two record tables. The output fields are the left fields followed
 * by the right fields the left lacks; records are widened to them (absent
 * fields are zero) and merged in sorted order, identical records collapsing
 * to one. For INTERSECT and DIFFERENCE only left records are emitted, so
 * rmap is all MERGE_RECORD_DROPPED.
 */
RecordMerge merge_records(
  MergeOp op,
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

/*
 * Writes the merge of l and r to outfile and returns its size. tlsh_options
 * is a bitwise OR of SFHASH_HSET_TLSH_* values; with SFHASH_HSET_TLSH_INHERIT
 * each optional TLSH section is written iff every input side that has a
 * TLSH section has it.
 */
uint64_t write_merged_hset(
  const SFHASH_Hashset& l,
  const SFHASH_Hashset& r,
  MergeOp op,
  const std::string& name,
  const std::string& desc,
  const std::filesystem::path& outfile,
  uint32_t tlsh_options
);
