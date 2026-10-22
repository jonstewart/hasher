#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "hasher/hashset.h"
#include "hashset/hset_structs.h"

/*
 * Record-level set operations of two record tables, as merge_records
 * computes them (HASHSET_FORMAT "Set operations"): the output records
 * widened to the left fields followed by the right fields the left lacks,
 * sorted and unique, with the output field types. These are the
 * sfhash_hashset_builder_*_open operations on the record tables alone;
 * they exist for tests, the library merges whole files.
 */

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> union_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> intersect_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> difference_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);
