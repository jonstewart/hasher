#pragma once

#include "hashset/basic_ls.h"
#include "hashset/hash_compare.h"
#include "hashset/probe.h"
#include "hashset/util.h"

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

template <
  size_t HashLength,
  size_t BlockBits
>
class FineBlockLookupStrategy: public BasicLookupStrategy<HashLength> {
  static_assert(HashLength >= 2, "FineBlockLookupStrategy requires HashLength >= 2 (uses hash[0] and hash[1])");
  static_assert(BlockBits <= 16, "FineBlockLookupStrategy requires BlockBits <= 16");
public:
  using Blocks = std::vector<std::pair<int64_t, int64_t>>;

  FineBlockLookupStrategy(
    const void* beg,
    const void* end,
    Blocks blocks
  ):
    BasicLookupStrategy<HashLength>(beg, end),
    Blocks_(std::move(blocks))
  {}

  virtual ~FineBlockLookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const override {
    size_t lo, hi;
    window(hash, lo, hi);
    return search_window(hash, lo, hi);
  }

  // Batched lookup that overlaps the (otherwise serial, latency-bound) cache
  // misses of independent lookups. See staged_batch().
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

  // Narrow the search to a [lo, hi) index window using the expected position
  // plus this block's observed min/max deviation. Identical bounds to the
  // original std::binary_search formulation, but expressed as clamped indices
  // (which also avoids forming out-of-range pointers).
  //
  // Differs from BlockLookupStrategy::window() in two ways:
  //   (a) block index uses TWO leading bytes: bi = ((hash[0]<<8)|hash[1]) >> (16-BlockBits)
  //   (b) Blocks_ is a std::vector (not std::array<...,256>)
  inline void window(const uint8_t* hash, size_t& lo, size_t& hi) const {
    const size_t n = count();
    const size_t exp = expected_index(hash, static_cast<uint32_t>(n));
    const size_t bi = ((hash[0] << 8) | hash[1]) >> (16 - BlockBits);
    // An empty block (no stored hash has this leading block index) keeps its
    // sentinel bounds {INT64_MAX, INT64_MIN}; adding exp would overflow (UB),
    // and the query is a guaranteed miss anyway, so return an empty window.
    if (Blocks_[bi].first > Blocks_[bi].second) {
      lo = hi = 0;
      return;
    }
    int64_t l = static_cast<int64_t>(exp) + Blocks_[bi].first;
    int64_t r = static_cast<int64_t>(exp) + Blocks_[bi].second + 1;
    if (l < 0) { l = 0; }
    if (r > static_cast<int64_t>(n)) { r = static_cast<int64_t>(n); }
    lo = static_cast<size_t>(l);
    hi = static_cast<size_t>(r > l ? r : l);
  }

  // Branchless lower_bound on the leading-8-byte primary key over [lo, hi),
  // then confirm the full hash. Removing the data-dependent branch of an
  // ordinary binary search avoids the ~50% mispredict penalty that dominates
  // random-key lookups; the integer primary-key compare replaces the
  // byte-by-byte std::array comparison.
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
    }
    else {
      // Primary keys can collide; scan the (near-always length-1) run of equal
      // primary keys, confirming the full hash.
      for (size_t j = pos; j < hi; ++j) {
        const uint8_t* cand = b + j * HashLength;
        if (primary_key<HashLength>(cand) != hk) {
          break;
        }
        if (std::memcmp(cand + 8, hash + 8, HashLength - 8) == 0) {
          return true;
        }
      }
      return false;
    }
  }

  // Software-pipelined batched binary search. D independent lookups are kept in
  // flight; each round advances every lane by one probe and prefetches that
  // lane's next probe, so up to D dependent-load chains overlap and hide memory
  // latency (memory-level parallelism). Results are identical to contains().
  void staged_batch(
    const uint8_t* hashes,
    size_t n,
    size_t stride,
    bool* results
  ) const {
    const uint8_t* const b = base();
    constexpr size_t D = 32; // in-flight lookups; ~saturates typical LFB counts

    struct Lane {
      const uint8_t* h;
      size_t out;
      size_t lo, hi, mid;
      bool active;
    };

    Lane lanes[D];
    size_t next = 0;
    size_t nactive = 0;

    auto dispatch = [&](Lane& ln) -> bool {
      while (next < n) {
        const size_t i = next++;
        const uint8_t* h = hashes + i * stride;
        size_t lo, hi;
        window(h, lo, hi);
        if (lo < hi) {
          ln.h = h;
          ln.out = i;
          ln.lo = lo;
          ln.hi = hi;
          ln.mid = lo + ((hi - lo) >> 1);
          HASHER_PREFETCH(b + ln.mid * HashLength);
          ln.active = true;
          return true;
        }
        results[i] = false; // empty window => certain miss
      }
      ln.active = false;
      return false;
    };

    for (size_t d = 0; d < D; ++d) {
      lanes[d].active = false;
      if (dispatch(lanes[d])) { ++nactive; }
    }

    while (nactive > 0) {
      for (size_t d = 0; d < D; ++d) {
        Lane& ln = lanes[d];
        if (!ln.active) { continue; }

        HASHER_PROBE_TOUCH(b + ln.mid * HashLength);
        HASHER_PROBE_CMP();
        const int c = fast_hash_cmp<HashLength>(b + ln.mid * HashLength, ln.h);
        bool done = false;
        if (c < 0) {
          ln.lo = ln.mid + 1;
        }
        else if (c > 0) {
          ln.hi = ln.mid;
        }
        else {
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

  Blocks Blocks_;
};
