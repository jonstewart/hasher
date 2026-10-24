# hset lookup experiments

- date: 2026-10-02T14:26:02Z
- host: Linux 6.18.52 x86_64
- cpu: Intel(R) Xeon(R) CPU           E5645  @ 2.40GHz
- caches: L1d cache=128 KiB (4 instances) L2 cache=16 MiB (4 instances) L3 cache=16 MiB (1 instance) 
- rustc: rustc 1.98.1 (48a229cea 2026-09-01); pin: 'taskset -c 1'
- commit: the rust port commit of 2026-10-02 on branch hashset-lookup-perf (this file is part of that commit, so it cannot name its own hash)
- parameters: N=10000000 NBIG=40000000 HLEN=20 QUERIES=1000000 (50 % hits, seed 1)

All numbers are ns per lookup; 'single' is `contains` one at a time, 'batch' is
`contains_batch` in 4096-query batches. Expect about ±10 % run-to-run noise.

## Datasets

```
    built hint Hull { bits: 0 } in 687.05ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h0.hset (200004120 bytes)
    built hint Hull { bits: 8 } in 596.65ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h8.hset (200004120 bytes)
    built hint Hull { bits: 12 } in 596.21ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h12.hset (200053272 bytes)
    built hint Hull { bits: 14 } in 604.74ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h14.hset (200200728 bytes)
    built hint Hull { bits: 16 } in 642.77ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h16.hset (200790552 bytes)
    built hint Hull { bits: 18 } in 766.74ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h18.hset (203149848 bytes)
    built hint Hull { bits: 20 } in 1.01s
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-h20.hset (212587032 bytes)
    built hint None in 508.00ns
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-none.hset (200004120 bytes)
    built hint Block { bits: 8 } in 65.26ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-legacy.hset (200008216 bytes)
    built hint Hull { bits: 18 } in 786.14ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/u-auto.hset (203149848 bytes)
    built hint Hull { bits: 16 } in 121.00ms
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/adv.hset (40790552 bytes)
    built hint Hull { bits: 14 } in 2.37s
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/big-h14.hset (800200728 bytes)
    built hint Hull { bits: 16 } in 2.39s
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/big-h16.hset (800790552 bytes)
    built hint Hull { bits: 18 } in 3.04s
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/big-h18.hset (803149848 bytes)
    built hint Hull { bits: 20 } in 3.07s
    wrote /tmp/claude-1000/-work/b46edc91-ef6e-4395-b35f-8966dbf30a19/scratchpad/exp/big-h20.hset (812587032 bytes)
```

## 1. Default configuration vs legacy hint vs binary search (N=10000000)

| strategy | single | batch |
|---|---:|---:|
| with hint | 192.6 | 96.5 |
| binary search (no hint) | 417.8 | 188.9 |
| legacy block8 hint | 401.9 | 225.1 |

auto-chosen table: window mean=6.8 max=17, table 3.00 MiB

## 2. Table size x search mode (N=10000000)

Single-lookup search inside the window: kary = 8-ary, recursive = Lemire-style recursive
dictionary search from the model's prediction. Batch uses the automatic pipeline choice.

| table bits | table | window mean / max | kary single | kary batch | recursive single | recursive batch |
|---|---:|---:|---:|---:|---:|---:|
| none | 0 B | 10000000.0 / 10000000 | 1194.5 | 664.9 | 528.8 | 208.1 |
| 0 | 12 B | 2665.8 / 2666 | 819.5 | 362.3 | 605.5 | 253.4 |
| 8 | 3.0 KiB | 230.5 / 374 | 488.4 | 232.9 | 421.2 | 235.5 |
| 12 | 48.0 KiB | 55.5 / 114 | 315.8 | 172.8 | 292.0 | 206.7 |
| 14 | 192.0 KiB | 27.8 / 66 | 241.0 | 155.2 | 243.7 | 166.7 |
| 16 | 768.0 KiB | 13.8 / 32 | 197.5 | 107.4 | 200.6 | 107.1 |
| 18 | 3.00 MiB | 6.8 / 17 | 199.2 | 107.0 | 197.0 | 100.0 |
| 20 | 12.00 MiB | 3.3 / 10 | 203.2 | 105.0 | 204.4 | 105.6 |

## 3. Table size x search mode, large set (N=40000000)

| table bits | table | window mean / max | kary single | kary batch | recursive single | recursive batch |
|---|---:|---:|---:|---:|---:|---:|
| 14 | 192.0 KiB | 55.8 / 132 | 378.7 | 226.0 | 359.8 | 241.5 |
| 16 | 768.0 KiB | 27.8 / 62 | 295.0 | 205.0 | 309.0 | 204.3 |
| 18 | 3.00 MiB | 13.8 / 33 | 275.9 | 143.3 | 280.6 | 144.4 |
| 20 | 12.00 MiB | 6.8 / 19 | 294.8 | 151.2 | 297.0 | 150.1 |

## 4. Batch pipelines (N=10000000, auto table)

| batch mode | batch |
|---|---:|
| staged | 108.1 |
| lanes | 158.9 |
| passes, sub-batch 8 | 154.1 |
| passes, sub-batch 16 | 151.8 |
| passes, sub-batch 32 | 143.7 |
| passes, sub-batch 64 | 140.9 |
| passes, sub-batch 128 | 141.7 |

## 5. Prefetch thresholds (N=10000000)

Whole-window prefetch threshold, kary single, on the 14-bit table (wide windows):

| window-bytes | single | batch |
|---|---:|---:|
| 512 | 267.1 | 169.4 |
| 1024 | 237.4 | 155.1 |
| 2048 | 238.3 | 154.6 |
| 4096 | 237.6 | 155.0 |

Recursive region cap, recursive single, on the 14-bit table:

| region-bytes | single | batch |
|---|---:|---:|
| 256 | 242.0 | 154.9 |
| 512 | 243.0 | 156.0 |
| 1024 | 241.7 | 157.6 |
| 2048 | 243.3 | 156.3 |

## 6. Adversarial data (N=2000000, skewed leading bytes, auto table)

| strategy | single | batch |
|---|---:|---:|
| with hint | 144.8 | 120.3 |
| binary search (no hint) | 2098.5 | 744.2 |
| legacy block8 hint | 607.1 | 281.4 |

window stats: window mean=40.6 max=91, table 768.0 KiB

## 7. Hint-less search modes (N=10000000, no table)

| single mode | single | batch |
|---|---:|---:|
| kary | 1188.0 | 618.8 |
| recursive | 510.3 | 196.5 |

## 8. perf counters, marginal per batched lookup (4M minus 1M queries, auto table)

| mode | cycles | instructions | L1d loads | L1d misses |
|---|---:|---:|---:|---:|
| staged | 433 | 370 | 61 | 9 |
| passes --sub-batch 16 | 540 | 409 | 71 | 13 |

## Criterion

For statistically characterised single-lookup latency per strategy, run
`HSET_BENCH_ALL=1 HSET_BENCH_N=10000000 cargo bench -p hset --bench lookup` and keep
the `target/criterion` report next to this file.
