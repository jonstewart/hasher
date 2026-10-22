#pragma once

#include <cstddef>
#include <cstdint>

#include "tlsh_digest.h"

/*
 * Lower-bound Euclidean embedding of a TLSH digest.
 *
 * phi: digest -> R^264 (float32), such that for any two digests a, b with
 * TLSH distance diff(a, b) <= 144 (and no L wraparound, see below):
 *
 *   || phi(a) - phi(b) ||^2  <=  diff(a, b)
 *
 * so a Euclidean radius search at radius sqrt(T) misses nothing within TLSH
 * distance T <= 144, and exact TLSH reranking removes the rest.
 *
 * Layout (see docs/TLSH_EMBEDDING.md for the derivation):
 *
 *   dims [0, 256)   body: bucket i occupies dims 2i, 2i+1 with code
 *                   0 -> ( 1, 0)   1 -> (0, 0)   2 -> (0, 1)   3 -> (-1, 1)
 *                   squared distances 1,1,1 (adjacent), 2,2 (two apart),
 *                   5 (0 vs 3) against TLSH costs 1,1,1,2,2,6.
 *   dim  256        L, as a float; squared distance k^2 <= 12k for 2 <= k <= 12,
 *                   = 1 for k = 1. Only valid for |L_a - L_b| <= 12, which
 *                   is implied by diff <= 144 unless L wraps mod 256 (inputs
 *                   of several terabytes); such pairs are not guaranteed.
 *   dims 257, 258   Q1 on a regular 16-gon of radius 1 / (2 sin(pi/16)),
 *                   so adjacent values are exactly distance 1 apart and the
 *                   chord^2 for a (mod 16) difference k is below 12(k - 1).
 *   dims 259, 260   Q2, likewise.
 *   dims 261..263   checksum bits 0, 1, 2, each scaled by 1/sqrt(3), so a
 *                   differing checksum contributes at most 1.
 *
 * Without the length (include_length = false) drop dim 256 from the distance;
 * then the bound holds for every pair, with no 144 cap.
 */

constexpr size_t TLSH_EMBED_DIMS = 264;
constexpr size_t TLSH_EMBED_L_DIM = 256;
constexpr uint32_t TLSH_EMBED_MAX_BOUNDED_DIFF = 144;

void tlsh_embed(const TlshDigest& d, float* out);

// squared Euclidean distance between two embeddings
float tlsh_embed_dist2(const float* a, const float* b, bool include_length = true);

// squared Euclidean distance between the embeddings of two digests, computed
// directly from the digests (no float vectors needed)
float tlsh_embed_dist2(const TlshDigest& a, const TlshDigest& b, bool include_length = true);

// Euclidean distance between a digest's embedding and an arbitrary point
// (e.g. a centroid), computed without materializing the digest's embedding.
float tlsh_embed_dist2_to_point(const TlshDigest& d, const float* p, bool include_length = true);
