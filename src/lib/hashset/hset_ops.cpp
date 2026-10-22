#include "hashset/hset_ops.h"

#include <cstddef>
#include <exception>
#include <memory>
#include <utility>
#include <vector>

#include "error.h"
#include "throw.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_encoder.h"
#include "hashset/hset_merge.h"

/*
 * The builder-shaped set operations: sfhash_hashset_builder_{union,
 * intersect, subtract}_open return a build context that remembers the two
 * inputs and the operation; sfhash_hashset_builder_write then writes the
 * merge of the inputs (write_merged_hset, see HASHSET_FORMAT "Set
 * operations"), so the open/write/destroy sequence of the builder stays
 * while nothing is rebuilt. sfhash_hashset_merge is the one-call form of
 * the same thing.
 */

namespace {

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> apply_op(
  MergeOp op,
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  const RecordMerge rm = merge_records(op, lrhdr, lrdat, rrhdr, rrdat);

  std::vector<std::vector<uint8_t>> records;
  records.reserve(rm.record_count());
  for (uint64_t i = 0; i < rm.record_count(); ++i) {
    const uint8_t* beg = rm.rdat.data() + i * rm.record_length;
    records.emplace_back(beg, beg + rm.record_length);
  }

  std::vector<SFHASH_HashAlgorithm> types;
  for (const auto& f: rm.fields) {
    types.push_back(static_cast<SFHASH_HashAlgorithm>(f.type));
  }

  return { std::move(records), std::move(types) };
}

SFHASH_HashsetBuildCtx* setop_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  uint32_t op,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  SFHASH_Error** err)
{
  try {
    THROW_IF(!l || !r, "null hashset operand");
    check_strlen(result_hashset_name, "result_hashset_name");
    check_strlen(result_hashset_desc, "result_hashset_desc");
    THROW_IF(!output_file, "null output_file");
    THROW_IF(
      !write_records && !write_hashsets,
      "at least one of records and hashsets must be written"
    );

    auto bctx = make_unique_del(
      new SFHASH_HashsetBuildCtx{
        {},
        { 2, result_hashset_name, make_timestamp(), result_hashset_desc, {} },
        { 0, 0, {} },
        {},
        {},
        write_records,
        write_hashsets,
        {},
        {},
        {},
        {},
        0
      },
      sfhash_hashset_builder_destroy
    );

    bctx->outfile = output_file;
    bctx->merge_left = l;
    bctx->merge_right = r;
    bctx->merge_op = op;

    // the output's record fields, as the merge widens them (a field length
    // mismatch between the inputs is rejected here, before any writing)
    const RecordHeader& lrhdr = l->holder.rhdr;
    const RecordHeader& rrhdr = r->holder.rhdr;
    if (!lrhdr.fields.empty() && !rrhdr.fields.empty()) {
      bctx->rhdr.fields = merged_record_fields(lrhdr, rrhdr);
      for (const auto& f: bctx->rhdr.fields) {
        bctx->rhdr.record_length += 1 + f.length;
      }
    }

    return bctx.release();
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

} // namespace

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> union_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op(MergeOp::UNION, lrhdr, lrdat, rrhdr, rrdat);
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> intersect_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op(MergeOp::INTERSECT, lrhdr, lrdat, rrhdr, rrdat);
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> difference_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op(MergeOp::DIFFERENCE, lrhdr, lrdat, rrhdr, rrdat);
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_union_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* /* temp_dir */,
  SFHASH_Error** err)
{
  return setop_open(
    l, r, SFHASH_HSET_OP_UNION,
    result_hashset_name, result_hashset_desc,
    write_records, write_hashsets, output_file, err
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_intersect_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* /* temp_dir */,
  SFHASH_Error** err)
{
  return setop_open(
    l, r, SFHASH_HSET_OP_INTERSECT,
    result_hashset_name, result_hashset_desc,
    write_records, write_hashsets, output_file, err
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_subtract_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* /* temp_dir */,
  SFHASH_Error** err)
{
  return setop_open(
    l, r, SFHASH_HSET_OP_DIFFERENCE,
    result_hashset_name, result_hashset_desc,
    write_records, write_hashsets, output_file, err
  );
}

void sfhash_hashset_builder_set_coalesce_threshold(
  SFHASH_HashsetBuildCtx* bctx,
  uint32_t coalesce_threshold)
{
  bctx->coalesce_threshold = coalesce_threshold == SFHASH_HSET_COALESCE_DEFAULT ?
    TLSH_IVF_DEFAULT_COALESCE : coalesce_threshold;
}
