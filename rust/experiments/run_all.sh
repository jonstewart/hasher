#!/usr/bin/env bash
# Reproducible lookup experiments for the hset crate.
#
# Generates synthetic hash sets, runs the `hset bench` matrix, and writes a
# Markdown report with the machine description, so results from different
# hardware can be compared side by side. Everything is driven by the committed
# binaries; nothing depends on this conversation or on local scratch state.
#
# Usage:  experiments/run_all.sh [report.md]
# Env:    N=10000000   hashes in the main synthetic set (use 1000000 for a quick run)
#         NBIG=40000000  hashes in the large set (0 to skip)
#         HLEN=20      bytes per hash
#         QUERIES=1000000
#         SCRATCH=...  where to put the generated .hset files (default $TMPDIR/hset-exp)
#         PIN=...      command prefix to pin a core (default: taskset -c 1 if available)
#         PERF=0       set to 1 to include perf-stat marginal counters (Linux)
set -euo pipefail

cd "$(dirname "$0")/.."
N=${N:-10000000}
NBIG=${NBIG:-40000000}
HLEN=${HLEN:-20}
QUERIES=${QUERIES:-1000000}
SCRATCH=${SCRATCH:-${TMPDIR:-/tmp}/hset-exp}
if [ -z "${PIN+x}" ]; then
  if command -v taskset >/dev/null 2>&1; then PIN="taskset -c 1"; else PIN=""; fi
fi
PERF=${PERF:-0}
REPORT=${1:-experiments/results/$(hostname -s 2>/dev/null || hostname)-$(date -u +%Y-%m-%d).md}

cargo build --release --workspace --bins --examples >/dev/null
HSET=target/release/hset
SYNTH=target/release/examples/synth_hset
mkdir -p "$SCRATCH" "$(dirname "$REPORT")"

# bench FILE [extra args...] -> "single | batch" ns/lookup of the "with hint" row
bench() {
  local f=$1; shift
  $PIN $HSET bench "$f" --queries "$QUERIES" "$@" | awk '/^with hint/ {
    for (i = 1; i <= NF; i++) { if ($i == "single") s = $(i+1); if ($i ~ /^batch/) b = $(i+1) }
    printf "%s | %s", s, b }'
}
# bench3 FILE -> hint | legacy | basic rows from --compare
bench3() {
  local f=$1; shift
  $PIN $HSET bench "$f" --queries "$QUERIES" --compare "$@" | awk '
    /ns\/lookup/ { for (i = 1; i <= NF; i++) { if ($i == "single") s = $(i+1); if ($i ~ /^batch/) b = $(i+1) }
      label = $1; for (i = 2; i <= NF && $i != "single"; i++) label = label " " $i
      printf "| %s | %s | %s |\n", label, s, b }'
}
winstats() { $PIN $HSET verify "$1" | grep -o 'window mean=[0-9.]* max=[0-9]*, table [^,]*'; }
gen() { # gen count bits kind out [adversarial]
  local count=$1 bits=$2 kind=$3 out=$4 adv=${5:-}
  if [ ! -f "$out" ]; then
    $SYNTH "$count" "$HLEN" "$out" "$kind" "$bits" $adv 2>&1 | grep -E "built|wrote" | sed 's/^/    /'
  fi
}

{
echo "# hset lookup experiments"
echo
echo "- date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "- host: $(uname -srm)"
if command -v lscpu >/dev/null 2>&1; then
  echo "- cpu: $(lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2}')"
  echo "- caches: $(lscpu | awk -F: '/L1d|L2|L3/ {gsub(/^ +/, "", $2); printf "%s=%s ", $1, $2}')"
elif command -v sysctl >/dev/null 2>&1; then
  echo "- cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
  echo "- caches: L2=$(sysctl -n hw.l2cachesize 2>/dev/null || true) perflevel0.L2=$(sysctl -n hw.perflevel0.l2cachesize 2>/dev/null || true)"
fi
echo "- rustc: $(rustc -V); pin: '${PIN}'"
echo "- commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo ' (dirty)')"
echo "- parameters: N=$N NBIG=$NBIG HLEN=$HLEN QUERIES=$QUERIES (50 % hits, seed 1)"
echo
echo "All numbers are ns per lookup; 'single' is \`contains\` one at a time, 'batch' is"
echo "\`contains_batch\` in 4096-query batches. Expect about ±10 % run-to-run noise."
echo
echo "## Datasets"
echo
echo '```'
for b in 0 8 12 14 16 18 20; do gen "$N" "$b" hull "$SCRATCH/u-h$b.hset"; done
gen "$N" 0 none "$SCRATCH/u-none.hset"
gen "$N" 8 legacy "$SCRATCH/u-legacy.hset"
gen "$N" "" hull "$SCRATCH/u-auto.hset"
gen "$((N / 5))" "" hull "$SCRATCH/adv.hset" adversarial
if [ "$NBIG" -gt 0 ]; then for b in 14 16 18 20; do gen "$NBIG" "$b" hull "$SCRATCH/big-h$b.hset"; done; fi
echo '```'
echo
echo "## 1. Default configuration vs legacy hint vs binary search (N=$N)"
echo
echo "| strategy | single | batch |"
echo "|---|---:|---:|"
bench3 "$SCRATCH/u-auto.hset"
echo
echo "auto-chosen table: $(winstats "$SCRATCH/u-auto.hset")"
echo
echo "## 2. Table size x search mode (N=$N)"
echo
echo "Single-lookup search inside the window: kary = 8-ary, recursive = Lemire-style recursive"
echo "dictionary search from the model's prediction. Batch uses the automatic pipeline choice."
echo
echo "| table bits | table | window mean / max | kary single | kary batch | recursive single | recursive batch |"
echo "|---|---:|---:|---:|---:|---:|---:|"
for b in none 0 8 12 14 16 18 20; do
  f="$SCRATCH/u-h$b.hset"; [ "$b" = none ] && f="$SCRATCH/u-none.hset"
  ws=$(winstats "$f"); tbl=$(echo "$ws" | sed 's/.*table //'); win=$(echo "$ws" | sed 's/window mean=\([0-9.]*\) max=\([0-9]*\).*/\1 \/ \2/')
  printf "| %s | %s | %s | %s | %s |\n" "$b" "$tbl" "$win" "$(bench "$f" --single kary)" "$(bench "$f" --single recursive)"
done
echo
if [ "$NBIG" -gt 0 ]; then
echo "## 3. Table size x search mode, large set (N=$NBIG)"
echo
echo "| table bits | table | window mean / max | kary single | kary batch | recursive single | recursive batch |"
echo "|---|---:|---:|---:|---:|---:|---:|"
for b in 14 16 18 20; do
  f="$SCRATCH/big-h$b.hset"
  ws=$(winstats "$f"); tbl=$(echo "$ws" | sed 's/.*table //'); win=$(echo "$ws" | sed 's/window mean=\([0-9.]*\) max=\([0-9]*\).*/\1 \/ \2/')
  printf "| %s | %s | %s | %s | %s |\n" "$b" "$tbl" "$win" "$(bench "$f" --single kary)" "$(bench "$f" --single recursive)"
done
echo
fi
echo "## 4. Batch pipelines (N=$N, auto table)"
echo
echo "| batch mode | batch |"
echo "|---|---:|"
for bm in staged lanes; do printf "| %s | %s |\n" "$bm" "$(bench "$SCRATCH/u-auto.hset" --only batch --batch-mode $bm | sed 's/.*| //')"; done
for sb in 8 16 32 64 128; do printf "| passes, sub-batch %s | %s |\n" "$sb" "$(bench "$SCRATCH/u-auto.hset" --only batch --batch-mode passes --sub-batch $sb | sed 's/.*| //')"; done
echo
echo "## 5. Prefetch thresholds (N=$N)"
echo
echo "Whole-window prefetch threshold, kary single, on the 14-bit table (wide windows):"
echo
echo "| window-bytes | single | batch |"
echo "|---|---:|---:|"
for w in 512 1024 2048 4096; do printf "| %s | %s |\n" "$w" "$(bench "$SCRATCH/u-h14.hset" --single kary --window-bytes $w)"; done
echo
echo "Recursive region cap, recursive single, on the 14-bit table:"
echo
echo "| region-bytes | single | batch |"
echo "|---|---:|---:|"
for r in 256 512 1024 2048; do printf "| %s | %s |\n" "$r" "$(bench "$SCRATCH/u-h14.hset" --single recursive --region-bytes $r)"; done
echo
echo "## 6. Adversarial data (N=$((N / 5)), skewed leading bytes, auto table)"
echo
echo "| strategy | single | batch |"
echo "|---|---:|---:|"
bench3 "$SCRATCH/adv.hset"
echo
echo "window stats: $(winstats "$SCRATCH/adv.hset")"
echo
echo "## 7. Hint-less search modes (N=$N, no table)"
echo
echo "| single mode | single | batch |"
echo "|---|---:|---:|"
for m in kary recursive; do printf "| %s | %s |\n" "$m" "$(bench "$SCRATCH/u-none.hset" --single $m)"; done
echo
if [ "$PERF" = 1 ] && command -v perf >/dev/null 2>&1; then
echo "## 8. perf counters, marginal per batched lookup (4M minus 1M queries, auto table)"
echo
echo "| mode | cycles | instructions | L1d loads | L1d misses |"
echo "|---|---:|---:|---:|---:|"
for bm in staged "passes --sub-batch 16"; do
  read -r c1 i1 l1 m1 < <(perf stat -x, -e cycles,instructions,L1-dcache-loads,L1-dcache-load-misses $PIN $HSET bench "$SCRATCH/u-auto.hset" --queries 1000000 --only batch --batch-mode $bm 2>&1 >/dev/null | awk -F, '{v[$3]=$1} END {print v["cycles"], v["instructions"], v["L1-dcache-loads"], v["L1-dcache-load-misses"]}')
  read -r c4 i4 l4 m4 < <(perf stat -x, -e cycles,instructions,L1-dcache-loads,L1-dcache-load-misses $PIN $HSET bench "$SCRATCH/u-auto.hset" --queries 4000000 --only batch --batch-mode $bm 2>&1 >/dev/null | awk -F, '{v[$3]=$1} END {print v["cycles"], v["instructions"], v["L1-dcache-loads"], v["L1-dcache-load-misses"]}')
  printf "| %s | %s | %s | %s | %s |\n" "$bm" "$(( (c4 - c1) / 3000000 ))" "$(( (i4 - i1) / 3000000 ))" "$(( (l4 - l1) / 3000000 ))" "$(( (m4 - m1) / 3000000 ))"
done
echo
fi
echo "## Criterion"
echo
echo "For statistically characterised single-lookup latency per strategy, run"
echo '`HSET_BENCH_ALL=1 HSET_BENCH_N='"$N"' cargo bench -p hset --bench lookup` and keep'
echo 'the `target/criterion` report next to this file.'
} | tee "$REPORT"
echo "report written to $REPORT" >&2
