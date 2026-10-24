// bench/eval.cpp
// Frozen eval driver. Runs the bar + all registered candidates across the
// dataset matrix. Held-out numbers are authoritative. Pin with taskset:
//   taskset -c 2 bench/eval [n]
#include "eval/suite.h"
#include "eval/datasets.h"
#include "candidates/registry.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

// Probe globals live here for the standalone (non-library) build under -DHASHER_PROBE.
#ifdef HASHER_PROBE
uint64_t g_hasher_probe_touches = 0;
uint64_t g_hasher_probe_cmps = 0;
#endif

int main(int argc, char** argv) {
  const size_t n = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 10000000;
  std::printf("libhasher eval harness — held-out numbers are authoritative\n\n");

  // Synthetic held-out (disjoint seed from any tuning done in candidates).
  // Seeds are fixed for reproducibility; see bench/RESULTS.md.
  eval::Split s20 = eval::split_disjoint(n, 20, 0x7ACE7357C0FFEE01ull, 0xDEADBEEF5A5A0002ull);
  {
    auto cands = candidates::all<20>();
    eval::run_leaderboard("SHA-1 L=20 synthetic held-out", s20.held_out, cands);
  }

  // Adversarial (correctness + tightness stress).
  {
    HashSet adv = eval::make_adversarial_set(n / 10, 20, 0xADFEEDFACE0003ull);
    auto cands = candidates::all<20>();
    eval::run_leaderboard("SHA-1 L=20 adversarial", adv, cands);
  }

  // Real NSRL SHA-1 (mmap, zero copy). Optional: only if present.
  {
    std::shared_ptr<boost::interprocess::mapped_region> keep;
    const char* p = "/data/nsrl/2.47/nsrl-sha1";
    if (FILE* f = std::fopen(p, "rb")) { std::fclose(f);
      eval::HashSetView v = eval::mmap_nsrl_sha1(p, keep);
      auto cands = candidates::all<20>();
      eval::run_leaderboard("NSRL SHA-1 (real, mmap)", v, cands);
    }
  }

  // Real NSRL MD5 (derived+cached once under $HOME/build).
  {
    const char* home = std::getenv("HOME");
    if (!home) { std::fprintf(stderr, "HOME not set; skipping NSRL MD5\n"); return 0; }
    std::string cache = std::string(home) + "/build/nsrl-md5";
    std::printf("Deriving NSRL MD5 cache (one-time; may take several minutes)...\n");
    std::fflush(stdout);
    eval::derive_nsrl_md5_cache("/data/nsrl/2.47/NSRLFile.txt", cache);
    std::shared_ptr<boost::interprocess::mapped_region> keep;
    eval::HashSetView v = eval::mmap_raw(cache, 16, keep);
    auto cands = candidates::all<16>();
    eval::run_leaderboard("NSRL MD5 (real, derived)", v, cands);
  }
  return 0;
}
