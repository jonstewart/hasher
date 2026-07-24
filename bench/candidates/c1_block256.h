// bench/candidates/c1_block256.h
#pragma once
#include "eval/candidate.h"
#include "hashset/block_ls.h"
#include "hashset/util.h"
#include <array>
#include <chrono>
#include <memory>

template <size_t L>
struct C1Block256 : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<L,8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  double build_ns = 0;
  std::string name() const override { return "c1-block256"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      const size_t e = expected_index(hs.at(i), static_cast<uint32_t>(hs.count));
      const int64_t d = (int64_t)i - (int64_t)e;
      const size_t bi = hs.at(i)[0];
      b[bi].first  = std::min(b[bi].first, d);
      b[bi].second = std::max(b[bi].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<L,8>>(hs.beg(), hs.end(), b);
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return { build_ns, 0.0, true }; }
};
