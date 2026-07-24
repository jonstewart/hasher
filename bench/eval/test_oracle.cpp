// bench/eval/test_oracle.cpp
#include "eval/oracle.h"
#include "harness.h"
#include "hashset/block_ls.h"

#include <cassert>
#include <cstdio>
#include <memory>

// Wrap the shipping block strategy so we can validate the oracle against a known-good candidate.
struct BlockCand : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<20, 8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  std::string name() const override { return "block256"; }
  void build(const HashSet& hs) override {
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      size_t e = expected_index(hs.at(i), hs.count);
      int64_t d = (int64_t)i - (int64_t)e;
      size_t bi = hs.at(i)[0];
      b[bi].first = std::min(b[bi].first, d);
      b[bi].second = std::max(b[bi].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<20,8>>(hs.beg(), hs.end(), b);
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override {
    ls->contains_batch(q, n, s, o);
  }
  eval::Budget budget() const override { return {}; }
};

// A deliberately broken candidate that always says "not present" — the oracle
// MUST catch it (proves the gate actually rejects).
struct BrokenCand : BlockCand {
  std::string name() const override { return "broken"; }
  bool contains(const uint8_t*) const override { return false; }
  void contains_batch(const uint8_t*, size_t n, size_t, bool* o) const override {
    for (size_t i = 0; i < n; ++i) o[i] = false;
  }
};

int main() {
  HashSet hs = make_sorted_set(200000, 20, 7);

  BlockCand good;
  eval::OracleResult r = eval::validate(hs, good);
  assert(r.ok);
  assert(r.mismatches == 0);
  assert(r.checked > 0);

  BrokenCand bad;
  eval::OracleResult rb = eval::validate(hs, bad);
  assert(!rb.ok);
  assert(rb.mismatches > 0);

  std::printf("ok checked=%zu\n", r.checked);
  return 0;
}
