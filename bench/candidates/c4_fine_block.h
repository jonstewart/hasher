// bench/candidates/c4_fine_block.h
#pragma once
#include "eval/candidate.h"
#include "hashset/fine_block_ls.h"
#include "hashset/util.h"
#include <algorithm>
#include <chrono>
#include <climits>
#include <memory>
#include <vector>

template <size_t L>
struct C4FineBlock : eval::Candidate {
  static constexpr size_t BB = 14;
  using LS = FineBlockLookupStrategy<L, BB>;

  std::unique_ptr<LS> ls;
  double build_ns = 0;

  std::string name() const override { return "c4-fine-block"; }

  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();

    std::vector<std::pair<int64_t, int64_t>> b;
    b.assign((size_t)1 << BB, {INT64_MAX, INT64_MIN});

    for (size_t i = 0; i < hs.count; ++i) {
      const uint8_t* h = hs.at(i);
      const size_t e = expected_index(h, (uint32_t)hs.count);
      const int64_t d = (int64_t)i - (int64_t)e;
      const size_t bi = ((h[0] << 8) | h[1]) >> (16 - BB);
      b[bi].first  = std::min(b[bi].first,  d);
      b[bi].second = std::max(b[bi].second, d);
    }

    ls = std::make_unique<LS>(hs.beg(), hs.end(), std::move(b));
    nhash_ = hs.count;
    build_ns = std::chrono::duration<double, std::nano>(
      std::chrono::steady_clock::now() - t0).count();
  }

  bool contains(const uint8_t* h) const override {
    return ls->contains(h);
  }

  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    ls->contains_batch(q, n, s, o);
  }

  eval::Budget budget() const override {
    // aux_bytes_per_hash is filled in at report time using nhash; use 0 here
    // and let the harness compute it, or stash a sentinel. The brief says to
    // set aux_bytes_per_hash = (1<<14)*16.0/nhash; but Budget is returned
    // without knowing nhash at budget() call time. We store nhash from build()
    // so we can fill it in correctly.
    return { build_ns, (double)((size_t)1 << BB) * 16.0 / (double)nhash_, true };
  }

private:
  size_t nhash_ = 0;
};
