// bench/candidates/registry.h
#pragma once
#include "eval/candidate.h"
#include "candidates/c0_basic.h"
#include "candidates/c1_block256.h"
#include "candidates/c2_block_linear.h"
#include "candidates/c3_global_hull.h"
#include "candidates/c4_fine_block.h"
#include "candidates/c5_interp.h"
#include "candidates/ext_phmap.h"
#include "candidates/ext_unordered.h"
#include <memory>
#include <vector>
#include <cstdlib>
namespace candidates {
template <size_t L>
std::vector<std::unique_ptr<eval::Candidate>> all() {
  std::vector<std::unique_ptr<eval::Candidate>> v;
  v.push_back(std::make_unique<C0Basic<L>>());
  v.push_back(std::make_unique<C1Block256<L>>());
  v.push_back(std::make_unique<C2BlockLinear<L>>());
  v.push_back(std::make_unique<C3GlobalHull<L>>());
  v.push_back(std::make_unique<C4FineBlock<L>>());
  v.push_back(std::make_unique<C5Interp<L>>());
  v.push_back(std::make_unique<ExtPhmap<L>>());
  v.push_back(std::make_unique<ExtUnordered<L>>());

  // EVAL_ONLY filter: if set, keep only the candidate with matching name.
  if (const char* only = std::getenv("EVAL_ONLY")) {
    std::vector<std::unique_ptr<eval::Candidate>> f;
    for (auto& c : v) if (c->name() == only) f.push_back(std::move(c));
    return f;
  }

  return v;
}
} // namespace candidates
