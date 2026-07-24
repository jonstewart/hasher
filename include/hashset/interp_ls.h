// include/hashset/interp_ls.h
#pragma once
#include "hashset/basic_ls.h"
#include "hashset/hash_compare.h"
#include "hashset/hull_lines.h"
#include "hashset/probe.h"
#include "hashset/util.h"
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

template <size_t HashLength>
class InterpLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  InterpLookupStrategy(const void* beg, const void* end, std::array<BlockLine,256> blocks)
    : BasicLookupStrategy<HashLength>(beg, end), Blocks(blocks) {}
  bool contains(const uint8_t* hash) const override {
    size_t lo, hi; window(hash, lo, hi); return interp_search(hash, lo, hi);
  }
protected:
  const uint8_t* base() const { return reinterpret_cast<const uint8_t*>(this->HashesBeg.get()); }
  size_t count() const { return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get()); }

  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const size_t exp = expected_index(hash, static_cast<uint32_t>(n));
    const BlockLine& bl = Blocks[hash[0]];
    if (bl.empty) { lo = hi = 0; return; }
    int64_t l=(int64_t)exp+(int64_t)std::floor(bl.s*(double)exp+bl.c_lo);
    int64_t r=(int64_t)exp+(int64_t)std::ceil (bl.s*(double)exp+bl.c_hi)+1;
    if(l<0)l=0; if(r>(int64_t)n)r=(int64_t)n; lo=(size_t)l; hi=(size_t)(r>l?r:l);
  }

  inline bool interp_search(const uint8_t* hash, size_t lo, size_t hi) const {
    if (lo >= hi) return false;
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);
    size_t l = lo, r = hi;                       // [l, r)
    while (l < r) {
      const uint64_t kl = primary_key<HashLength>(b + l * HashLength);
      HASHER_PROBE_TOUCH(b + l * HashLength);
      if (hk < kl) return false;
      const uint64_t kr = primary_key<HashLength>(b + (r-1) * HashLength);
      HASHER_PROBE_TOUCH(b + (r-1) * HashLength);
      if (hk > kr) return false;
      size_t probe;
      if (kr == kl) { probe = l + ((r - l) >> 1); }
      else {
        // interpolate; long double avoids overflow for 64-bit key spans.
        long double frac = (long double)(hk - kl) / (long double)(kr - kl);
        probe = l + (size_t)(frac * (long double)(r - 1 - l));
        if (probe < l) probe = l; if (probe >= r) probe = r - 1;
      }
      HASHER_PROBE_TOUCH(b + probe * HashLength); HASHER_PROBE_CMP();
      const uint64_t kp = primary_key<HashLength>(b + probe * HashLength);
      if (kp < hk) l = probe + 1;
      else if (kp > hk) r = probe;
      else {
        if constexpr (HashLength <= 8) return true;
        else {                                   // confirm full hash on tie
          for (size_t j = probe; j < hi && primary_key<HashLength>(b+j*HashLength)==hk; ++j)
            if (std::memcmp(b+j*HashLength+8, hash+8, HashLength-8)==0) return true;
          for (size_t j = probe; j-- > lo && primary_key<HashLength>(b+j*HashLength)==hk; )
            if (std::memcmp(b+j*HashLength+8, hash+8, HashLength-8)==0) return true;
          return false;
        }
      }
    }
    return false;
  }
  std::array<BlockLine,256> Blocks;
};
