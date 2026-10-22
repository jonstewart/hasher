# TLSH lower-bound embedding and similarity sections

This document completes the "TLSH Similarity Sections" spec for libhasher's
hset format: it defines the derived Euclidean embedding (the spec's pending
section 8), the `TVEC` vectors section and the `TIVF` index section, and the
indexed kNN procedure. Sections 1–7 of the spec (canonical digest, exact
distance, cell index, record map) are implemented as described in
`HASHSET_FORMAT` and `include/hasher/tlsh.h`, with two adaptations:

* the 36-byte row is laid out so that bytewise order equals canonical order
  (L, Q1, Q2, body, checksum), so the existing sort/search machinery applies;
* duplicate digests are duplicate rows, each mapped to its record through the
  existing `RIDX` chunk, which plays the role of `TLSH_RECORD_MAP`.

## 1. The embedding

Write `diff(a, b)` for the reference TLSH distance with length included. The
embedding `phi(d)` maps a digest to 264 float32 coordinates such that

    || phi(a) - phi(b) ||^2  <=  diff(a, b)      whenever diff(a, b) <= 144.

Each TLSH cost term is bounded separately by one block of coordinates, and
the blocks are orthogonal, so the squared Euclidean distance is the sum of
the per-term bounds.

### Body (dims 0–255)

Bucket `i` occupies dims `2i, 2i+1`. The four codes map to the corners of a
staircase:

| code | point    |
|------|----------|
| 0    | ( 1, 0)  |
| 1    | ( 0, 0)  |
| 2    | ( 0, 1)  |
| 3    | (-1, 1)  |

Squared distances: adjacent codes 1, two apart 2, and (0, 3) 5, against TLSH
costs 1, 1, 1, 2, 2, 6. This is the tightest possible planar placement:
d(0,3) cannot exceed (1 + sqrt 2)^2 ≈ 5.83 by the triangle inequality through
code 2 while d(1,3) ≤ 2 is required, and 5 is the largest value realizable
with the adjacent distances exactly 1. All coordinates are in {-1, 0, 1}, so
the body contributes integer distances and can be evaluated with popcounts:

    X = lo_a ^ lo_b,  Y = hi_a ^ hi_b,  S = ~(lo_a ^ hi_a)
    body_emb2 = popcount(X ^ Y) + popcount(Y) + 4 popcount(X & Y & S)

(the exact TLSH body is the same expression with 5 in place of 4).

### Length (dim 256)

`phi_L = L` as a float. For a difference `k = |L_a - L_b|` the squared distance
is `k^2`, and TLSH charges 0, 1, 12k for k = 0, 1, ≥2. `k^2 <= 12k` exactly for
`k <= 12`, and `k = 12` is also where the L term alone reaches 144. This is the
best possible: a chain of unit steps forces any Euclidean realization to have
`d(k)^2 <= k^2`, so the linear map is optimal for every pair that matters.

Two caveats. First, pairs with `diff > 144` have no guarantee (and do not need
one: TLSH scores above ~100 carry no similarity information). Second, the L
term in TLSH is a difference mod 256 while the embedding is linear; they
disagree only when one input is in the terabyte range (L ≥ 244) and the other
is tiny. Such pairs are not guaranteed.

### Quartile ratios (dims 257–260)

Q1 and Q2 are circular (mod 16), so each is placed on a regular 16-gon of
radius `R = 1 / (2 sin(pi/16)) ≈ 2.5629`, chosen so that adjacent values are
exactly distance 1 apart (TLSH cost 1). For a circular difference k the
squared chord is `sin^2(pi k/16) / sin^2(pi/16)`:

| k        | 1 | 2    | 3    | 4     | 5     | 6     | 7     | 8     |
|----------|---|------|------|-------|-------|-------|-------|-------|
| chord^2  | 1 | 3.85 | 8.11 | 13.14 | 18.16 | 22.43 | 25.27 | 26.27 |
| TLSH     | 1 | 12   | 24   | 36    | 48    | 60    | 72    | 84    |

### Checksum (dims 261–263)

Bits 0–2 of the checksum, each scaled by `1/sqrt 3`. A differing checksum
costs 1 in TLSH; the embedding contributes `(number of differing low bits)/3
<= 1`, and 0 when the checksums are equal.

### Distance without length

For `include_length = false` the distance is computed over all dims except
256. With the L term gone there is no 144 cap: the bound holds for every pair.

### Tightness

On near pairs from the synthetic family corpus the squared embedding distance
averages about 0.78 of the TLSH distance (see `test/test_tlsh_embedding.cpp`).

## 2. Section TVEC (vectors)

Optional, one per TLSH hash set, following that set's `HDAT`/`RIDX`. Payload:

| offset | type | field    | meaning                                  |
|--------|------|----------|------------------------------------------|
| 0      | u16  | version  | 1                                        |
| 2      | u8   | variant  | 0 (128 buckets, 1-byte checksum)         |
| 3      | u8   | flags    | 0                                        |
| 4      | u32  | dims     | 264                                      |
| 8      | u64  | n        | row count, equals the HDAT hash count    |
| 16     | u32  | dtype    | 1 = float32, little-endian               |
| 20     | u32  | reserved | 0                                        |
| 24     | u64  | reserved | 0                                        |
| 32     | f32  | data     | n × dims, row-major, row r is phi(HDAT row r) |

The chunk is positioned so that `data` begins on a 4096-byte boundary in the
file; `offset(TVEC chunk) + 12 + 32` is page aligned. A consumer can therefore
memory-map the file and hand `numpy.memmap(path, np.float32, offset=..., shape=(n, 264))`
or a `float*` straight to faiss, hnswlib, scikit-learn, HDBSCAN, UMAP, etc.
`utils/hsvectors.py` shows this.

## 3. Section TIVF (inverted-file index)

Optional, following `TVEC` (or `HDAT`/`RIDX` when no vectors are stored; the
index does not need the vectors, it embeds digests on the fly). Lists never
span L values: rows are grouped by L, and each group is split by k-means over
the embedding into about `ceil(group_size / target_list_size)` lists.

| offset | type       | field       | meaning                                      |
|--------|------------|-------------|----------------------------------------------|
| 0      | u16        | version     | 1                                            |
| 2      | u16        | flags       | 0                                            |
| 4      | u32        | dims        | 264                                          |
| 8      | u32        | lists       | C                                            |
| 12     | u32        | reserved    | 0                                            |
| 16     | u64        | n           | row count                                    |
| 24     | u64        | reserved    | 0                                            |
| 32     | f32[C×dims]| centroids   | one embedding-space point per list           |
|        | f32[C]     | radius      | max Euclidean distance from centroid to a member |
|        | f32[C]     | radius_xlen | same, over dims except 256                   |
|        | u64[C+1]   | list_start  | CSR offsets into ids                         |
|        | u32[n]     | ids         | HDAT row indexes, ascending within each list |

## 4. Indexed kNN (exact for diff <= 144)

Given query digest q, k, max_distance T ≤ 144:

1. `v = phi(q)`. For each list c compute `b_c = max(0, ||v - centroid_c|| - radius_c)^2`.
2. Visit lists in increasing `b_c`. Keep a bounded max-heap of the k best
   exact TLSH distances (computed on the 36-byte HDAT rows with the popcount
   kernel; `tau` = k-th best so far, initially T + 1).
3. Stop when `b_c >= tau`. Correctness: for any row r in list c,
   `||v - phi(r)|| >= ||v - c|| - radius_c` (triangle inequality), and
   `||v - phi(r)||^2 <= diff(q, r)` when `diff(q, r) <= 144`; so every row with
   `diff < tau <= 145` lives in a list with `b_c < tau`.

The same procedure with `include_length = false` uses `radius_xlen` and the
distance over dims except 256, and is exact for every T.
