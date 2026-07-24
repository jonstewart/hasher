// bench/eval/test_datasets.cpp
#include "eval/datasets.h"
#include "harness.h"

#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
  // Adversarial set is still sorted and correct as a set.
  HashSet a = eval::make_adversarial_set(50000, 20, 5);
  assert(a.count == 50000);
  for (size_t i = 1; i < a.count; ++i)
    assert(std::memcmp(a.at(i-1), a.at(i), a.hlen) <= 0);   // sorted

  // Tuning and held-out are disjoint seeds and distinct.
  eval::Split s = eval::split_disjoint(10000, 20, 1, 2);
  assert(s.tune.count == 10000 && s.held_out.count == 10000);
  assert(std::memcmp(s.tune.at(0), s.held_out.at(0), 20) != 0);

  std::printf("ok\n");
  return 0;
}
