#!/bin/sh
# perf stat isolated to one candidate's query region (via EVAL_ONLY).
# Usage: bench/run_perf.sh <candidate-name> [n]
set -e
CAND="$1"
N="${2:-10000000}"
PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 3)
if [ "$PARANOID" -gt 1 ]; then
  echo "perf_event_paranoid=$PARANOID — counters likely denied."
  echo "Request in vm/guest.nix: boot.kernel.sysctl.\"kernel.perf_event_paranoid\" = 1;"
fi
# Note: LLC-load-misses may read <not supported> in a VM; this is expected.
# The probe build (-DHASHER_PROBE) provides machine-independent counters as a cross-check.
EVAL_ONLY="$CAND" taskset -c 2 perf stat \
  -e cycles,instructions,L1-dcache-load-misses,LLC-load-misses,branch-misses \
  bench/bench_eval "$N"
