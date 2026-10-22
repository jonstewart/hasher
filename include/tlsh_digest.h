#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "hasher/tlsh.h"

/*
 * Canonical 36-byte TLSH digest. See hasher/tlsh.h for the layout.
 */
struct TlshDigest {
  uint8_t L;
  uint8_t Q;
  uint8_t hi[16];
  uint8_t lo[16];
  uint8_t checksum;
  uint8_t reserved;

  uint8_t q1() const { return Q >> 4; }
  uint8_t q2() const { return Q & 0x0F; }

  uint8_t bucket(size_t i) const {
    const uint8_t h = (hi[i >> 3] >> (i & 7)) & 1;
    const uint8_t l = (lo[i >> 3] >> (i & 7)) & 1;
    return (h << 1) | l;
  }

  bool is_null() const {
    static constexpr TlshDigest zero{};
    return std::memcmp(this, &zero, sizeof(TlshDigest)) == 0;
  }

  bool operator==(const TlshDigest& o) const {
    return std::memcmp(this, &o, sizeof(TlshDigest)) == 0;
  }

  bool operator<(const TlshDigest& o) const {
    return std::memcmp(this, &o, sizeof(TlshDigest)) < 0;
  }
};

static_assert(sizeof(TlshDigest) == SFHASH_TLSH_DIGEST_LENGTH);
static_assert(std::is_trivially_copyable_v<TlshDigest>);

/*
 * Build a digest from the reference implementation's internal fields.
 * codes[i] is the 2-bit code of bucket i.
 */
TlshDigest make_tlsh_digest(
  uint8_t L,
  uint8_t q1,
  uint8_t q2,
  uint8_t checksum,
  const uint8_t* codes
);

// Returns false if hex is not a valid TLSH string. "TNULL" yields the null digest.
bool tlsh_from_hex(const char* hex, TlshDigest& out);

// "T1" + 70 uppercase hex chars, or "TNULL"
std::string tlsh_to_hex(const TlshDigest& d);

/*
 * Distance components, matching the reference implementation.
 */

// cost of a (mod 256) L difference of k
constexpr uint32_t tlsh_l_cost(uint32_t k) {
  return k == 0 ? 0 : (k == 1 ? 1 : 12 * k);
}

// cost of a (mod 16) Q difference of k
constexpr uint32_t tlsh_q_cost(uint32_t k) {
  return k <= 1 ? k : 12 * (k - 1);
}

constexpr uint32_t tlsh_mod_diff(uint32_t x, uint32_t y, uint32_t r) {
  const uint32_t d = x > y ? x - y : y - x;
  return d < r - d ? d : r - d;
}

inline uint64_t load_u64(const uint8_t* p) {
  uint64_t v;
  std::memcpy(&v, p, 8);
  return v;
}

/*
 * Body distance over the bit planes. Per bucket the reference charges
 * 0, 1, 2, 6 for |a - b| = 0, 1, 2, 3. With
 *
 *   X = lo_a ^ lo_b, Y = hi_a ^ hi_b, S = ~(lo_a ^ hi_a)
 *
 * this is popcount(X ^ Y) + popcount(Y) + 5 * popcount(X & Y & S).
 */
inline uint32_t tlsh_body_diff(const TlshDigest& a, const TlshDigest& b) {
  uint32_t d = 0;
  for (size_t i = 0; i < 16; i += 8) {
    const uint64_t lo_a = load_u64(a.lo + i);
    const uint64_t hi_a = load_u64(a.hi + i);
    const uint64_t x = lo_a ^ load_u64(b.lo + i);
    const uint64_t y = hi_a ^ load_u64(b.hi + i);
    const uint64_t s = ~(lo_a ^ hi_a);
    d += std::popcount(x ^ y) + std::popcount(y) + 5 * std::popcount(x & y & s);
  }
  return d;
}

inline uint32_t tlsh_header_diff(const TlshDigest& a, const TlshDigest& b, bool include_length) {
  uint32_t d = a.checksum != b.checksum;
  if (include_length) {
    d += tlsh_l_cost(tlsh_mod_diff(a.L, b.L, 256));
  }
  d += tlsh_q_cost(tlsh_mod_diff(a.q1(), b.q1(), 16));
  d += tlsh_q_cost(tlsh_mod_diff(a.q2(), b.q2(), 16));
  return d;
}

inline uint32_t tlsh_diff(const TlshDigest& a, const TlshDigest& b, bool include_length = true) {
  return tlsh_header_diff(a, b, include_length) + tlsh_body_diff(a, b);
}

/*
 * Query-side precomputation for scanning many rows against one digest: the
 * query planes and S = ~(lo ^ hi) are held in registers, and on arm64 the
 * three popcounts are done with NEON byte counts and a single horizontal
 * reduction. body(r) == tlsh_body_diff(q, r) and emb_body(r) ==
 * tlsh_embed_body_dist2(q, r) for every r.
 */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#define TLSH_HAVE_NEON 1
#endif

#ifdef TLSH_HAVE_NEON
#include <arm_neon.h>
#endif

struct TlshBodyQuery {
#ifdef TLSH_HAVE_NEON
  uint8x16_t lo, hi, s;

  explicit TlshBodyQuery(const TlshDigest& q):
    lo(vld1q_u8(q.lo)), hi(vld1q_u8(q.hi)), s(vmvnq_u8(veorq_u8(lo, hi))) {}

  // popcount(X ^ Y) + popcount(Y) + w * popcount(X & Y & S)
  template <int W>
  uint32_t weighted(const TlshDigest& r) const {
    const uint8x16_t x = veorq_u8(lo, vld1q_u8(r.lo));
    const uint8x16_t y = veorq_u8(hi, vld1q_u8(r.hi));
    const uint8x16_t b = vandq_u8(vandq_u8(x, y), s);
    uint8x16_t c = vaddq_u8(vcntq_u8(veorq_u8(x, y)), vcntq_u8(y));
    const uint8x16_t cb = vcntq_u8(b);
    if constexpr (W == 5) {
      c = vaddq_u8(c, vaddq_u8(cb, vshlq_n_u8(cb, 2)));
    }
    else {
      c = vaddq_u8(c, vshlq_n_u8(cb, 2));
    }
    return vaddlvq_u8(c);
  }
#else
  uint64_t lo[2], hi[2], s[2];

  explicit TlshBodyQuery(const TlshDigest& q) {
    for (size_t i = 0; i < 2; ++i) {
      lo[i] = load_u64(q.lo + 8 * i);
      hi[i] = load_u64(q.hi + 8 * i);
      s[i] = ~(lo[i] ^ hi[i]);
    }
  }

  template <int W>
  uint32_t weighted(const TlshDigest& r) const {
    uint32_t d = 0;
    for (size_t i = 0; i < 2; ++i) {
      const uint64_t x = lo[i] ^ load_u64(r.lo + 8 * i);
      const uint64_t y = hi[i] ^ load_u64(r.hi + 8 * i);
      d += std::popcount(x ^ y) + std::popcount(y) + W * std::popcount(x & y & s[i]);
    }
    return d;
  }
#endif

  // TLSH body distance
  uint32_t body(const TlshDigest& r) const { return weighted<5>(r); }

  // squared body-embedding distance
  uint32_t emb_body(const TlshDigest& r) const { return weighted<4>(r); }
};
