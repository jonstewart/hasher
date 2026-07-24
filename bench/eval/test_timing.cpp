#include "eval/timing.h"
#include "eval/oracle.h"      // reuses BlockCand-style wrapper via a local def
#include "harness.h"
#include "hashset/block_ls.h"

#include <cassert>
#include <cstdio>
#include <memory>

struct BlockCand : eval::Candidate {
  std::unique_ptr<BlockLookupStrategy<20,8>> ls;
  std::array<std::pair<int64_t,int64_t>,256> b;
  std::string name() const override { return "block256"; }
  void build(const HashSet& hs) override {
    b.fill({INT64_MAX, INT64_MIN});
    for (size_t i = 0; i < hs.count; ++i) {
      size_t e = expected_index(hs.at(i), hs.count);
      int64_t d = (int64_t)i - (int64_t)e;
      b[hs.at(i)[0]].first = std::min(b[hs.at(i)[0]].first, d);
      b[hs.at(i)[0]].second = std::max(b[hs.at(i)[0]].second, d);
    }
    ls = std::make_unique<BlockLookupStrategy<20,8>>(hs.beg(), hs.end(), b);
  }
  bool contains(const uint8_t* h) const override { return ls->contains(h); }
  void contains_batch(const uint8_t* q, size_t n, size_t s, bool* o) const override { ls->contains_batch(q,n,s,o); }
  eval::Budget budget() const override { return {}; }
};

int main() {
  HashSet hs = make_sorted_set(1000000, 20, 3);
  BlockCand c; c.build(hs);
  Queries q = make_random_queries(4096, 20, 11);

  eval::Timing ts = eval::time_single(c, q, 5);
  assert(ts.ns_min > 0.0);
  assert(ts.ns_median >= ts.ns_min);

  std::vector<uint8_t> scratch(q.count);
  eval::Timing tb = eval::time_batch(c, q, scratch, 5);
  assert(tb.ns_min > 0.0);
  assert(tb.ns_median >= tb.ns_min);
  // Single and batch must agree on the checksum (same answers).
  assert(ts.checksum == tb.checksum);
  std::printf("ok single=%.1f batch=%.1f\n", ts.ns_min, tb.ns_min);
  return 0;
}
