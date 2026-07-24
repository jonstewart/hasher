// bench/candidates/c2_block_linear.h
#pragma once
#include "eval/candidate.h"
#include "hashset/block_linear_ls.h"
#include "hashset/hull_lines.h"
#include <chrono>
#include <memory>

template <size_t L>
struct C2BlockLinear : eval::Candidate {
  std::unique_ptr<BlockLinearLookupStrategy<L,8>> ls;
  std::array<BlockLine,256> lines;
  size_t nhash = 0;
  double build_ns = 0;
  std::string name() const override { return "c2-block-linear"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    nhash = hs.count;
    lines = make_block_hull_lines(hs);
    ls = std::make_unique<BlockLinearLookupStrategy<L,8>>(hs.beg(), hs.end(), lines);
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override {
    // aux bytes = 256 blocks * 16 B (4 floats) spread over the set
    const double aux = nhash > 0 ? 256.0 * 16.0 / (double)nhash : 0.0;
    return { build_ns, aux, true };
  }
};
