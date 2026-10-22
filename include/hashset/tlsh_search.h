#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "tlsh_digest.h"
#include "hasher/hashset.h"

/*
 * Brute-force k nearest neighbours of q in [beg, end) by TLSH distance.
 *
 * Returns up to k matches with distance <= max_distance, nearest first,
 * ties broken by ascending index. Returns nothing if q is the null digest.
 */
std::vector<SFHASH_TlshMatch> tlsh_knn_brute(
  const TlshDigest* beg,
  const TlshDigest* end,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length
);
