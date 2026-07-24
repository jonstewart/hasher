// bench/candidates/ext_unordered.h
#pragma once
#include "eval/candidate.h"
#include <array>
#include <chrono>
#include <cstring>
#include <unordered_set>

template <size_t L>
struct ArrHash { size_t operator()(const std::array<uint8_t,L>& a) const {
  size_t h = 1469598103934665603ull;
  for (uint8_t c : a) { h ^= c; h *= 1099511628211ull; } return h; } };

template <size_t L>
struct ExtUnordered : eval::Candidate {
  std::unordered_set<std::array<uint8_t,L>, ArrHash<L>> set;
  double build_ns = 0;
  std::string name() const override { return "unordered"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    set.reserve(hs.count);
    std::array<uint8_t,L> k;
    for (size_t i = 0; i < hs.count; ++i) { std::memcpy(k.data(), hs.at(i), L); set.insert(k); }
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override {
    std::array<uint8_t,L> k; std::memcpy(k.data(), h, L); return set.find(k) != set.end();
  }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);
  }
  eval::Budget budget() const override { return { build_ns, (double)(L + 24), false }; }
};
