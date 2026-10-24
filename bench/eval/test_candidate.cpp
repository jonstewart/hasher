// bench/eval/test_candidate.cpp
#include "eval/candidate.h"
#include "harness.h"

#include <cassert>
#include <cstdio>

// A trivial candidate that answers via linear scan, to prove the interface
// compiles and dispatches polymorphically.
struct ScanCandidate : eval::Candidate {
  size_t hlen = 0, count = 0; const uint8_t* data = nullptr;
  std::string name() const override { return "scan"; }
  void build(const eval::SetRef& h) override { hlen = h.hlen; count = h.count; data = h.data; }
  bool contains(const uint8_t* hash) const override {
    for (size_t i = 0; i < count; ++i)
      if (std::memcmp(data + i * hlen, hash, hlen) == 0) return true;
    return false;
  }
  void contains_batch(const uint8_t* q, size_t n, size_t stride, bool* out) const override {
    for (size_t i = 0; i < n; ++i) out[i] = contains(q + i * stride);
  }
  eval::Budget budget() const override { return {}; }
};

int main() {
  HashSet hs = make_sorted_set(1000, 20, 42);
  ScanCandidate c;
  c.build(hs);
  assert(c.contains(hs.at(0)));
  eval::Candidate& base = c;         // polymorphic use
  assert(base.name() == "scan");
  std::printf("ok\n");
  return 0;
}
