// bench/candidates/c5_interp.h
#pragma once
#include "eval/candidate.h"
#include "hashset/interp_ls.h"
#include "hashset/hull_lines.h"
#include <chrono>
#include <memory>

template <size_t L>
struct C5Interp : eval::Candidate {
  std::unique_ptr<InterpLookupStrategy<L>> ls;
  std::array<BlockLine,256> lines;
  size_t nhash = 0;
  double build_ns = 0;
  std::string name() const override { return "c5-interp"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    nhash = hs.count;
    lines = make_block_hull_lines(hs);
    ls = std::make_unique<InterpLookupStrategy<L>>(hs.beg(), hs.end(), lines);
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
