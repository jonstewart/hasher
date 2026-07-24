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
#include <utility>

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

// C6: Hull-bounded window → one interpolation probe to split into a sub-window
// → verbatim branchless search_window (from block_ls.h) on the sub-window.
// Plus a staged D=32 pipeline for contains_batch: window + one-shot interp
// probe + prefetch during dispatch, then branchless binary loop over the
// narrowed sub-window across rounds.
//
// Correctness invariant (identical to C5): interpolation only picks a split
// point; if hk is present it is guaranteed to be in the chosen sub-window
// because the array is sorted. The branchless tail is exact over that sub-
// window. The L>8 tail-confirm (search run of equal primary keys) is required
// because two hashes can share their leading 8 bytes.
template <size_t HashLength>
class HullInterpLookupStrategy : public BasicLookupStrategy<HashLength> {
public:
  HullInterpLookupStrategy(const void* beg, const void* end,
                            std::array<BlockLine, 256> blocks)
    : BasicLookupStrategy<HashLength>(beg, end), Blocks(blocks) {}

  virtual ~HullInterpLookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const override {
    size_t lo, hi;
    window(hash, lo, hi);
    if (lo >= hi) return false;

    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);

    // One interpolation probe to split the window.
    const uint64_t kl = primary_key<HashLength>(b + lo * HashLength);
    HASHER_PROBE_TOUCH(b + lo * HashLength);
    if (hk < kl) return false;
    const uint64_t kr = primary_key<HashLength>(b + (hi - 1) * HashLength);
    HASHER_PROBE_TOUCH(b + (hi - 1) * HashLength);
    if (hk > kr) return false;

    size_t p;
    if (kr == kl) {
      p = lo + ((hi - lo) >> 1);
    } else {
      long double frac = (long double)(hk - kl) / (long double)(kr - kl);
      p = lo + (size_t)(frac * (long double)(hi - 1 - lo));
      if (p < lo) p = lo;
      if (p >= hi) p = hi - 1;
    }

    HASHER_PROBE_TOUCH(b + p * HashLength);
    HASHER_PROBE_CMP();
    const uint64_t kp = primary_key<HashLength>(b + p * HashLength);

    size_t sub_lo, sub_hi;
    if (kp < hk) {
      sub_lo = p + 1;
      sub_hi = hi;
    } else if (kp > hk) {
      sub_lo = lo;
      sub_hi = p;
    } else {
      // kp == hk: handle equal primary key (with L>8 tail-confirm)
      if constexpr (HashLength <= 8) {
        return true;
      } else {
        // Scan run of equal primary keys in both directions from p.
        for (size_t j = p; j < hi && primary_key<HashLength>(b + j * HashLength) == hk; ++j)
          if (std::memcmp(b + j * HashLength + 8, hash + 8, HashLength - 8) == 0) return true;
        for (size_t j = p; j-- > lo && primary_key<HashLength>(b + j * HashLength) == hk; )
          if (std::memcmp(b + j * HashLength + 8, hash + 8, HashLength - 8) == 0) return true;
        return false;
      }
    }

    // Branchless binary search (VERBATIM from block_ls.h search_window) on the
    // narrowed sub-window [sub_lo, sub_hi).
    return search_window(hash, sub_lo, sub_hi);
  }

  virtual void contains_batch(
    const uint8_t* hashes,
    size_t n,
    size_t stride,
    bool* results
  ) const override {
    staged_batch(hashes, n, stride, results);
  }

protected:
  const uint8_t* base() const {
    return reinterpret_cast<const uint8_t*>(this->HashesBeg.get());
  }

  size_t count() const {
    return static_cast<size_t>(this->HashesEnd - this->HashesBeg.get());
  }

  // Per-block BlockLine hull window (identical to InterpLookupStrategy::window
  // and block_linear_ls.h).
  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const size_t exp = expected_index(hash, static_cast<uint32_t>(n));
    const BlockLine& bl = Blocks[hash[0]];
    if (bl.empty) { lo = hi = 0; return; }
    int64_t l = (int64_t)exp + (int64_t)std::floor(bl.s * (double)exp + bl.c_lo);
    int64_t r = (int64_t)exp + (int64_t)std::ceil (bl.s * (double)exp + bl.c_hi) + 1;
    if (l < 0) l = 0;
    if (r > (int64_t)n) r = (int64_t)n;
    lo = (size_t)l;
    hi = (size_t)(r > l ? r : l);
  }

  // Verbatim branchless search_window from block_ls.h (plan-mandated copy).
  inline bool search_window(const uint8_t* hash, size_t lo, size_t hi) const {
    const uint8_t* const b = base();
    const uint64_t hk = primary_key<HashLength>(hash);

    size_t pos = lo;
    size_t len = hi - lo;
    while (len > 0) {
      const size_t half = len >> 1;
      const size_t probe = pos + half;
      HASHER_PROBE_TOUCH(b + probe * HashLength);
      HASHER_PROBE_CMP();
      const uint64_t pk = primary_key<HashLength>(b + probe * HashLength);
      const bool lt = pk < hk;
      pos = lt ? probe + 1 : pos;
      len = lt ? len - half - 1 : half;
    }

    if constexpr (HashLength <= 8) {
      return pos < hi && primary_key<HashLength>(b + pos * HashLength) == hk;
    } else {
      for (size_t j = pos; j < hi; ++j) {
        const uint8_t* cand = b + j * HashLength;
        if (primary_key<HashLength>(cand) != hk) break;
        if (std::memcmp(cand + 8, hash + 8, HashLength - 8) == 0) return true;
      }
      return false;
    }
  }

  // Staged D=32 pipeline (mirrors block_ls.h staged_batch + block_linear_ls.h
  // staged_batch) with ONE interpolation step per lane during dispatch.
  //
  // Dispatch: window() → one interp probe → if probe is a miss/hit, record
  // result immediately and move on; otherwise narrow [lo,hi) to the sub-window
  // that must contain hk, prefetch the first branchless probe, and enqueue.
  // Then run the branchless binary loop (identical to staged_batch in block_ls.h)
  // over the narrowed sub-window across rounds.
  //
  // Correctness for the kp==hk early-hit case (L>8): we do the full bidirectional
  // scan inline during dispatch, exactly as contains() does. This path is rare
  // (primary-key collision), so running it serially does not hurt throughput.
  void staged_batch(
    const uint8_t* hashes,
    size_t n,
    size_t stride,
    bool* results
  ) const {
    const uint8_t* const b = base();
    constexpr size_t D = 32;

    struct Lane {
      const uint8_t* h;
      size_t out;
      size_t lo, hi, mid;
      bool active;
    };

    Lane lanes[D];
    size_t next = 0;
    size_t nactive = 0;

    // Try to enqueue the next query into lane ln.
    // Performs window() + one-shot interp narrowing.
    // Returns true if the lane was loaded and needs the binary loop.
    // Returns false if no more queries or the query was resolved immediately.
    auto dispatch = [&](Lane& ln) -> bool {
      while (next < n) {
        const size_t i = next++;
        const uint8_t* h = hashes + i * stride;
        size_t lo, hi;
        window(h, lo, hi);

        if (lo >= hi) {
          results[i] = false;
          continue;
        }

        const uint64_t hk = primary_key<HashLength>(h);
        const uint64_t kl = primary_key<HashLength>(b + lo * HashLength);
        if (hk < kl) { results[i] = false; continue; }
        const uint64_t kr = primary_key<HashLength>(b + (hi - 1) * HashLength);
        if (hk > kr) { results[i] = false; continue; }

        // Compute interpolation estimate p.
        size_t p;
        if (kr == kl) {
          p = lo + ((hi - lo) >> 1);
        } else {
          long double frac = (long double)(hk - kl) / (long double)(kr - kl);
          p = lo + (size_t)(frac * (long double)(hi - 1 - lo));
          if (p < lo) p = lo;
          if (p >= hi) p = hi - 1;
        }

        const uint64_t kp = primary_key<HashLength>(b + p * HashLength);

        if (kp < hk) {
          // hk must be in [p+1, hi); continue branchless search there.
          lo = p + 1;
        } else if (kp > hk) {
          // hk must be in [lo, p); continue branchless search there.
          hi = p;
        } else {
          // kp == hk: resolve immediately.
          if constexpr (HashLength <= 8) {
            results[i] = true;
          } else {
            // Bidirectional scan of equal-primary-key run (identical to contains()).
            bool found = false;
            for (size_t j = p; j < hi && primary_key<HashLength>(b + j * HashLength) == hk; ++j)
              if (std::memcmp(b + j * HashLength + 8, h + 8, HashLength - 8) == 0) { found = true; break; }
            if (!found) {
              for (size_t j = p; j-- > lo && primary_key<HashLength>(b + j * HashLength) == hk; )
                if (std::memcmp(b + j * HashLength + 8, h + 8, HashLength - 8) == 0) { found = true; break; }
            }
            results[i] = found;
          }
          continue; // resolved; do not enqueue
        }

        if (lo >= hi) {
          results[i] = false;
          continue;
        }

        // Enqueue for branchless binary search on narrowed sub-window [lo, hi).
        ln.h   = h;
        ln.out = i;
        ln.lo  = lo;
        ln.hi  = hi;
        ln.mid = lo + ((hi - lo) >> 1);
        HASHER_PREFETCH(b + ln.mid * HashLength);
        ln.active = true;
        return true;
      }
      ln.active = false;
      return false;
    };

    for (size_t d = 0; d < D; ++d) {
      lanes[d].active = false;
      if (dispatch(lanes[d])) { ++nactive; }
    }

    // Branchless binary search loop — VERBATIM from block_ls.h staged_batch.
    while (nactive > 0) {
      for (size_t d = 0; d < D; ++d) {
        Lane& ln = lanes[d];
        if (!ln.active) continue;

        HASHER_PROBE_TOUCH(b + ln.mid * HashLength);
        HASHER_PROBE_CMP();
        const int c = fast_hash_cmp<HashLength>(b + ln.mid * HashLength, ln.h);
        bool done = false;
        if (c < 0) {
          ln.lo = ln.mid + 1;
        } else if (c > 0) {
          ln.hi = ln.mid;
        } else {
          results[ln.out] = true;
          done = true;
        }

        if (!done) {
          if (ln.lo < ln.hi) {
            ln.mid = ln.lo + ((ln.hi - ln.lo) >> 1);
            HASHER_PREFETCH(b + ln.mid * HashLength);
            continue;
          }
          results[ln.out] = false;
          done = true;
        }

        --nactive;
        ln.active = false;
        if (dispatch(ln)) { ++nactive; }
      }
    }
  }

  std::array<BlockLine, 256> Blocks;
};
