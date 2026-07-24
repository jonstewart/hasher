// bench/candidates/ext_phmap.h
#pragma once
#include "eval/candidate.h"
#include <array>
#include <chrono>
#include <cstring>
#include <parallel_hashmap/phmap.h>

// FNV-1a over the fixed-length key — used as the hash for phmap since
// std::hash<std::array<...>> is not defined in libstdc++.
template <size_t L>
struct PhmapArrHash {
  size_t operator()(const std::array<uint8_t,L>& a) const noexcept {
    size_t h = 14695981039346656037ull;
    for (uint8_t c : a) { h ^= c; h *= 1099511628211ull; }
    return h;
  }
};

// Swiss-table reference (the "Abseil territory" north star). NOT sorted:
// it stores a full hashed copy, so preserves_sorted=false and aux bytes are
// reported (the extra table + key copies beyond the canonical array).
template <size_t L>
struct ExtPhmap : eval::Candidate {
  phmap::flat_hash_set<std::array<uint8_t,L>, PhmapArrHash<L>> set;
  double build_ns = 0; size_t nhash = 0;
  std::string name() const override { return "phmap"; }
  void build(const eval::SetRef& hs) override {
    auto t0 = std::chrono::steady_clock::now();
    nhash = hs.count; set.reserve(hs.count);
    std::array<uint8_t,L> k;
    for (size_t i = 0; i < hs.count; ++i) { std::memcpy(k.data(), hs.at(i), L); set.insert(k); }
    build_ns = std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-t0).count();
  }
  bool contains(const uint8_t* h) const override {
    std::array<uint8_t,L> k; std::memcpy(k.data(), h, L); return set.contains(k);
  }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = contains(q + i * s);
  }
  eval::Budget budget() const override {
    // ~sizeof(key)+1 control byte per slot at ~1.4 load factor, all auxiliary.
    return { build_ns, (double)(L + 1) * 1.4, false };
  }
};
