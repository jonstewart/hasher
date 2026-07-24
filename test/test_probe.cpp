#include <catch2/catch_test_macros.hpp>

#include "hashset/probe.h"

TEST_CASE("probe_counters_noop_by_default") {
  // Without -DHASHER_PROBE the macros must compile to nothing and the
  // accessor must report zero, so instrumented and shipped code share source.
  hasher_probe_reset();
  HASHER_PROBE_TOUCH(nullptr);
  HASHER_PROBE_CMP();
  CHECK(hasher_probe_touches() == 0);
  CHECK(hasher_probe_cmps() == 0);
}
