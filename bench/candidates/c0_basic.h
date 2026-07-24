// bench/candidates/c0_basic.h
#pragma once
#include "eval/candidate.h"
#include "hashset/basic_ls.h"
#include <chrono>
#include <memory>

template <size_t L>
struct C0Basic : eval::Candidate {
  std::unique_ptr<BasicLookupStrategy<L>> ls;
  double build_ns = 0;
  std::string name() const override { return "c0-basic"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    ls = std::make_unique<BasicLookupStrategy<L>>(hs.beg(), hs.end());
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);
  }
  eval::Budget budget() const override { return { build_ns, 0.0, true }; }
};
