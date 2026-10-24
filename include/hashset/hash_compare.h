#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Portable primitives for fast hash comparison and lookup.
//
// Cryptographic hashes are uniformly distributed, so a lexicographic (big-
// endian) comparison of two hashes is decided by the first few bytes almost
// every time. Loading the leading bytes as a single big-endian integer lets the
// hot comparison in a binary search be a single integer compare instead of a
// byte-by-byte loop. All helpers here are standard C++ with correct behavior on
// both little- and big-endian hosts; the only non-standard bits are an optional
// prefetch hint and a byte-swap intrinsic, each guarded with a portable
// fallback.

// --- portable byte swaps ----------------------------------------------------

inline uint64_t bswap64_portable(uint64_t v) {
#if defined(_MSC_VER)
  return _byteswap_uint64(v);
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(v);
#else
  return ((v & 0x00000000000000FFull) << 56) |
         ((v & 0x000000000000FF00ull) << 40) |
         ((v & 0x0000000000FF0000ull) << 24) |
         ((v & 0x00000000FF000000ull) << 8) |
         ((v & 0x000000FF00000000ull) >> 8) |
         ((v & 0x0000FF0000000000ull) >> 24) |
         ((v & 0x00FF000000000000ull) >> 40) |
         ((v & 0xFF00000000000000ull) >> 56);
#endif
}

// Load 8 bytes at p as a big-endian (most-significant-byte-first) integer.
// Uses memcpy so no alignment is assumed; correct on any host endianness.
inline uint64_t load_be64(const uint8_t* p) {
  uint64_t v;
  std::memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return v;
#else
  return bswap64_portable(v);
#endif
}

// Primary sort key for an L-byte hash: the leading min(L, 8) bytes as a big-
// endian integer. Two hashes with different primary keys always order by their
// keys; equal keys require a tie-break on the remaining bytes (L > 8). Reads
// only bytes that belong to the hash, so it is safe for short hashes (e.g.
// L == 4) that must not over-read.
template <size_t L>
inline uint64_t primary_key(const uint8_t* p) {
  if constexpr (L >= 8) {
    return load_be64(p);
  }
  else {
    uint64_t k = 0;
    for (size_t i = 0; i < L; ++i) {
      k = (k << 8) | p[i];
    }
    return k;
  }
}

// Three-way lexicographic comparison of two L-byte hashes (<0, 0, >0),
// equivalent to std::memcmp(a, b, L) but with the common case (differing
// leading bytes) resolved by a single integer compare.
template <size_t L>
inline int fast_hash_cmp(const uint8_t* a, const uint8_t* b) {
  const uint64_t ka = primary_key<L>(a);
  const uint64_t kb = primary_key<L>(b);
  if (ka != kb) {
    return ka < kb ? -1 : 1;
  }
  if constexpr (L <= 8) {
    return 0;
  }
  else {
    return std::memcmp(a + 8, b + 8, L - 8);
  }
}

// --- portable prefetch hint -------------------------------------------------

#if defined(__GNUC__) || defined(__clang__)
  #define HASHER_PREFETCH(p) __builtin_prefetch((const void*)(p))
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  #include <intrin.h>
  #define HASHER_PREFETCH(p) _mm_prefetch((const char*)(p), _MM_HINT_T0)
#else
  #define HASHER_PREFETCH(p) ((void)0)
#endif
