// bench/candidates/registry.h
#pragma once
#include "eval/candidate.h"
#include "candidates/c0_basic.h"
#include "candidates/c1_block256.h"
#include "candidates/ext_phmap.h"
#include "candidates/ext_unordered.h"
#include <memory>
#include <vector>
namespace candidates {
template <size_t L>
std::vector<std::unique_ptr<eval::Candidate>> all() {
  std::vector<std::unique_ptr<eval::Candidate>> v;
  v.push_back(std::make_unique<C0Basic<L>>());
  v.push_back(std::make_unique<C1Block256<L>>());
  v.push_back(std::make_unique<ExtPhmap<L>>());
  v.push_back(std::make_unique<ExtUnordered<L>>());
  return v;
}
} // namespace candidates
