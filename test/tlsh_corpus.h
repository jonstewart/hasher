#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "tlsh_digest.h"

/*
 * Synthetic TLSH corpora for tests and benchmarks. Every function is
 * deterministic for a given seed (the generators avoid std::*_distribution
 * so results do not depend on the standard library implementation).
 */

// A base digest and the digests of mutated copies of the same content.
struct TlshFamily {
  TlshDigest base;
  std::vector<TlshDigest> variants;
};

/*
 * For each family: random base content of a log-uniform length in
 * [min_len, max_len] over a per-family byte alphabet (full 256, small
 * alphabets, text-like runs, run-length structured binary), then
 * variants_per_family mutated copies (byte flips over 0.5-5% of bytes,
 * small insertions/deletions, duplicated/moved blocks). Everything is
 * hashed with TlshHasher. Null digests are skipped; families with a null
 * base are dropped.
 */
std::vector<TlshFamily> make_tlsh_families(
  uint64_t seed,
  size_t families,
  size_t variants_per_family,
  size_t min_len = 1024,
  size_t max_len = 65536
);

// make_tlsh_families, flattened: base then variants, family by family.
std::vector<TlshDigest> make_tlsh_family_corpus(
  uint64_t seed,
  size_t families,
  size_t variants_per_family,
  size_t min_len = 1024,
  size_t max_len = 65536
);

/*
 * Digest-space perturbation, for scaling to millions cheaply. Each output
 * picks a random seed digest, moves each bucket code by +-1 with
 * probability bucket_flip_prob (clamped to 0..3), occasionally moves L by
 * +-{1,2} and Q1/Q2 by +-1 (mod 16), and draws a random checksum. Output
 * digests are never null. Duplicates are possible.
 */
std::vector<TlshDigest> perturb_tlsh_corpus(
  uint64_t seed,
  const std::vector<TlshDigest>& seeds,
  size_t target_size,
  double bucket_flip_prob = 0.05
);

/*
 * Convenience: a family corpus of ~min(n, 20000) digests, perturbed up to
 * exactly n digests.
 */
std::vector<TlshDigest> make_tlsh_corpus(uint64_t seed, size_t n);
