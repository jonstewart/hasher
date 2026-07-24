# libhasher eval — reproducibility record

## Fixed reproducibility seeds

| role       | seed literal              | notes                        |
|------------|---------------------------|------------------------------|
| tune       | `0x7ACE7357C0FFEE01ull`   | tuning set (NOT held-out)    |
| held-out   | `0xDEADBEEF5A5A0002ull`   | held-out set (authoritative) |
| adversarial| `0xADFEEDFACE0003ull`     | adversarial stress set       |

These seeds are frozen. Never use the held-out seed for tuning.

## Benchmark environment

- **CPU:** Intel Xeon E5645, SSE4.2, no AVX2
- **Pinned core:** `taskset -c 2 bench/eval [n]`
- **Compiler:** `g++ -O3 -march=native -std=c++17`
- **n (default):** 10,000,000

## Workload matrix

| tag      | m (queries) | hit fraction | notes                      |
|----------|-------------|--------------|----------------------------|
| 4K miss  | 4,096       | 0.0          | cold-cache misses          |
| 4K hit   | 4,096       | 1.0          | cold-cache guaranteed hits |
| 1M miss  | 1,000,000   | 0.0          | warm-cache, all misses     |
| 1M mix   | 1,000,000   | 0.5          | warm-cache, 50% hit rate   |
| 1M hit   | 1,000,000   | 1.0          | warm-cache, all hits       |

## Notes on instrumentation

`BasicLookupStrategy` (c0-basic) is intentionally left uninstrumented for
probe touches — `std::binary_search` does not expose its probe positions.
The probe_touch/lookup column for c0-basic will read 0 even under
`-DHASHER_PROBE`. It is the floor baseline, not a tuned candidate.

## Leaderboard (populate after running bench/eval)

Run:
```sh
taskset -c 2 bench/eval 10000000
```

| candidate   | single ns (min/med/sd) | batch ns (min/med/sd) | preserves_sorted | aux B/hash | build ms | probe touches/lookup | notes |
|-------------|------------------------|-----------------------|------------------|------------|----------|----------------------|-------|
| c0-basic    |                        |                       | yes              | 0.00       |          | 0 (uninstrumented)   | floor baseline, std::binary_search |
| c1-block256 |                        |                       | yes              | 0.00       |          |                      | block-bounded binary search + batch MLP |
| phmap       |                        |                       | no               | ~29.40     |          | N/A                  | parallel-hashmap flat_hash_set |
| unordered   |                        |                       | no               | ~44.00     |          | N/A                  | std::unordered_set |
