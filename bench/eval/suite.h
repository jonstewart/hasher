// bench/eval/suite.h
#pragma once

#include "eval/candidate.h"
#include "eval/oracle.h"
#include "eval/timing.h"
#include "harness.h"          // Workload, default_workloads, make_random_queries, make_mixed_queries_v
#include "hashset/probe.h"

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace eval {

struct Row {
  std::string cand;
  bool ok = false;
  double single_min = 0, single_med = 0, single_sd = 0;
  double batch_min = 0, batch_med = 0, batch_sd = 0;
  uint64_t probe_touches = 0;
  Budget budget;
};

template <class SetT>
inline Queries queries_for(const SetT& hs, const Workload& wl) {
  return (wl.hit == 0.0) ? make_random_queries(wl.m, hs.hlen, 90001 + wl.m)
                         : make_mixed_queries_v(hs, wl.m, wl.hit, 90001 + wl.m);
}

template <class SetT>
inline std::vector<Row> run_leaderboard(const std::string& title, const SetT& hs,
                                        std::vector<std::unique_ptr<Candidate>>& cands,
                                        const std::vector<Workload>& wls = default_workloads()) {
  std::printf("=== %s (hlen=%zu, count=%zu) ===\n", title.c_str(), hs.hlen, hs.count);
  std::vector<Row> rows;
  for (auto& up : cands) {
    Candidate& c = *up;
    Row row; row.cand = c.name();
    OracleResult val = validate(hs, c);   // builds c; DISQUALIFY on any mismatch
    row.ok = val.ok;
    row.budget = c.budget();
    if (!row.ok) {
      std::printf("  %-16s DISQUALIFIED (%zu/%zu mismatches)\n", row.cand.c_str(), val.mismatches, val.checked);
      rows.push_back(row); continue;
    }
    // Held-out timing: use the largest workload for the headline number.
    for (auto& wl : wls) {
      Queries q = queries_for(hs, wl);
      std::vector<uint8_t> scratch(q.count);
      Timing ts = time_single(c, q);
      Timing tb = time_batch(c, q, scratch);
      std::printf("  %-16s %-8s single %8.1f (med %8.1f sd %6.1f)  batch %8.1f (med %8.1f sd %6.1f)\n",
                  row.cand.c_str(), wl.tag, ts.ns_min, ts.ns_median, ts.ns_stddev,
                  tb.ns_min, tb.ns_median, tb.ns_stddev);
      // Keep the last workload's numbers as the row headline.
      row.single_min = ts.ns_min; row.single_med = ts.ns_median; row.single_sd = ts.ns_stddev;
      row.batch_min = tb.ns_min;  row.batch_med = tb.ns_median;  row.batch_sd = tb.ns_stddev;
    }
    // Probe cross-check (only meaningful under -DHASHER_PROBE).
    hasher_probe_reset();
    for (size_t i = 0; i < std::min<size_t>(hs.count, 4096); ++i) (void)c.contains(hs.at(i));
    row.probe_touches = hasher_probe_touches();
    std::printf("    budget: build=%.1fms aux=%.2fB/hash sorted=%d probe_touch/lookup~%.2f\n",
                row.budget.build_ns / 1e6, row.budget.aux_bytes_per_hash,
                row.budget.preserves_sorted ? 1 : 0,
                row.probe_touches / 4096.0);
    rows.push_back(row);
  }
  std::printf("\n");
  return rows;
}

} // namespace eval
