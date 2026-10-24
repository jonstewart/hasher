// Standalone hash-set lookup benchmark for libhasher.
//
// Compares, on synthetic uniform-random sorted sets (a faithful model of NSRL /
// VirusShare, since cryptographic hashes are uniform and the predictor assumes
// uniformity):
//   * basic          - plain std::binary_search over the whole set
//   * block256        - the block strategy's single-hash contains()
//   * block256.batch  - the block strategy's staged, prefetched contains_batch()
//
// It generates the data itself (no external .hset files needed) and validates
// every strategy against a std::binary_search ground truth before timing.
//
// Build from the repository root (needs only expected_index from the library):
//   g++ -O3 -march=native -std=c++17 -Iinclude -Ibench \
//       bench/bench_lookup.cpp src/lib/hashset/util.cpp -o bench/bench_lookup
//
// Run (optional argument = set size, default 10,000,000):
//   bench/bench_lookup 10000000
#include "harness.h"
#include "reference.h"
#include "hashset/lookupstrategy.h"

#include <memory>

// Runner that drives the real virtual contains_batch() on the block strategy.
template <size_t L>
Candidate make_block256_batch(const HashSet& hs) {
  auto b8 = compute_block_bounds<L, 8>(hs);
  std::shared_ptr<LookupStrategy> ls =
      std::make_shared<BlockLookupStrategy<L, 8>>(hs.beg(), hs.end(), b8);
  return {"block256.batch", [ls](const Queries& q, uint8_t* out) -> uint64_t {
    static thread_local std::vector<uint8_t> res;
    res.assign(q.count, 0);
    ls->contains_batch(q.data.data(), q.count, q.hlen,
                       reinterpret_cast<bool*>(res.data()));
    uint64_t cs = 0;
    for (size_t i = 0; i < q.count; ++i) { out[i] = res[i]; cs += res[i] ? 1 : 0; }
    return cs;
  }};
}

template <size_t L>
void run_for_L(const char* title, uint64_t seed, size_t n) {
  HashSet hs = make_sorted_set(n, L, seed);
  std::vector<Candidate> cands;
  cands.push_back(make_basic_reference<L>(hs));
  cands.push_back(make_block256_reference<L>(hs));
  cands.push_back(make_block256_batch<L>(hs));
  run_suite(title, hs, cands, default_workloads(), 6);
}

int main(int argc, char** argv) {
  size_t n = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 10000000;
  std::printf("libhasher lookup benchmark, n=%zu hashes/set\n\n", n);
  run_for_L<20>("SHA-1 (L=20)", 0xABCDEF01, n);
  run_for_L<16>("MD5 (L=16)", 0x12345678, n);
  return 0;
}
