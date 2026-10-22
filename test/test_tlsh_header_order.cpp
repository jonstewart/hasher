#include <catch2/catch_test_macros.hpp>

#include <set>

#include "tlsh_digest.h"
#include "hashset/tlsh_header_order.h"

TEST_CASE("tlsh_header_order_is_a_cost_sorted_permutation") {
  uint8_t codes[128] = {};
  for (const auto [L, q1, q2]: {std::tuple{0, 0, 0}, std::tuple{255, 15, 15}, std::tuple{77, 3, 9}, std::tuple{128, 8, 8}}) {
    const auto q = make_tlsh_digest(L, q1, q2, 1, codes);
    for (bool incl: {true, false}) {
      const TlshHeaderOrder o(q, incl);

      std::set<uint8_t> ls(o.l.begin(), o.l.end()), qs(o.q.begin(), o.q.end());
      CHECK(ls.size() == 256);
      CHECK(qs.size() == 256);

      for (size_t i = 0; i < 256; ++i) {
        const uint32_t lc = incl ? tlsh_l_cost(tlsh_mod_diff(o.l[i], L, 256)) : 0;
        CHECK(o.l_cost[i] == lc);
        const uint32_t qc = tlsh_q_cost(tlsh_mod_diff(o.q[i] >> 4, q1, 16)) +
                            tlsh_q_cost(tlsh_mod_diff(o.q[i] & 0x0F, q2, 16));
        CHECK(o.q_cost[i] == qc);
        if (i) {
          CHECK(o.l_cost[i - 1] <= o.l_cost[i]);
          CHECK(o.q_cost[i - 1] <= o.q_cost[i]);
        }
      }
      if (incl) {
        CHECK(o.l[0] == L);
      }
      CHECK(o.q[0] == ((q1 << 4) | q2));
    }
  }
}
