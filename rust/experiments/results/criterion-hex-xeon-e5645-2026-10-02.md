# Criterion hex benchmark, Xeon E5645 (Westmere), 2026-10-02

`HSET_BENCH_HEX_LEVELS=1 cargo bench -p hset --bench hex`, rustc 1.98.1,
`lto = "thin"`, default target (SSE2 baseline; runtime detection picks SSE4.2
on this CPU, which has no AVX). Mean ns per call, one buffer per width.

`scalar` is the portable reference (`hex::scalar`); `simd` is the runtime
dispatched kernel (`hex::simd`); `simd@Sse2` / `simd@Sse4_2` pin the level;
`simd-upper` decodes uppercase input; `encode-string` / `decode-into` are the
public entry points including allocation (encode) or validation and `Result`
(decode).

## encode (bytes -> lowercase hex)

| width | scalar | simd | simd@Sse2 | simd@Sse4_2 | encode-string | speedup |
|---|---:|---:|---:|---:|---:|---:|
| md5 (16 B) | 28.0 | 17.2 | 11.8 | 16.0 | 53.8 | 1.6x |
| sha1 (20 B) | 33.0 | 23.0 | 16.7 | 21.5 | 65.1 | 1.4x |
| sha256 (32 B) | 49.7 | 21.2 | 15.9 | 19.3 | 59.3 | 2.3x |
| sha512 (64 B) | 96.4 | 30.0 | 24.6 | 26.8 | 86.8 | 3.2x |
| 4 KiB | 6131 | 1004 | 1275 | 1032 | 2140 | 6.1x |

## decode (hex -> bytes, with validation)

| width | scalar | simd | simd@Sse2 | simd@Sse4_2 | simd-upper | decode-into | speedup |
|---|---:|---:|---:|---:|---:|---:|---:|
| md5 (16 B) | 65.4 | 23.5 | 16.8 | 22.9 | 24.6 | 28.4 | 2.8x |
| sha1 (20 B) | 80.0 | 33.3 | 29.6 | 32.9 | 34.9 | 38.2 | 2.4x |
| sha256 (32 B) | 127.8 | 34.3 | 25.4 | 31.7 | 32.5 | 38.1 | 3.7x |
| sha512 (64 B) | 349.3 | 46.9 | 43.1 | 49.3 | 48.5 | 55.8 | 7.4x |
| 4 KiB | 50698 | 2118 | 2154 | 2134 | 2145 | 2102 | 23.9x |

## Notes

* Digest widths that are not a multiple of 16 bytes (SHA-1) re-run the kernel
  on the last full block with overlapping output. Before that change the
  padded tail cost as much as a full block: SHA-1 encode 31.4 ns, decode 45.1 ns.
* On this Westmere core the SSE2-pinned kernel is faster than SSE4.2 for short
  inputs (the SSE4.1 `pblendvb` select is two uops here) but slower on the
  4 KiB buffer. Runtime dispatch picks SSE4.2; the difference is a few ns per
  call and was left alone rather than tuned to a 2010 CPU.
* `encode-string` is dominated by the allocation and UTF-8 check of the
  returned `String`, not by the kernel. Callers on a hot path should use
  `hex::simd::encode_into` with a reused buffer.

## Row batches (`hex/rows` group, ns per hash, 4096 rows)

The batch functions take the contiguous fixed-width layout of a section
(`encode_rows*`) or a list of strings (`decode_rows`) and run the kernel
densely across row boundaries, so SHA-1 rows no longer pay for the
half-block overlap. `encode-string-loop` is the old `hset dump` inner loop
(`hex::encode` + `writeln!` per hash); `decode-into-loop` is the old
`hset query -f` inner loop.

| width | encode-string-loop | encode-writer-loop | encode-rows | encode-rows-writer | decode-into-loop | decode-rows |
|---|---:|---:|---:|---:|---:|---:|
| md5 | 109.4 | 31.6 | 15.0 | 11.8 | 37.0 | 15.9 |
| sha1 | 117.5 | 38.8 | 17.9 | 15.1 | 47.5 | 20.4 |
| sha256 | 112.3 | 39.1 | 23.0 | 20.0 | 49.4 | 27.0 |
| sha512 | 131.1 | 50.9 | 35.0 | 37.6 | 68.0 | 49.6 |

## End to end, 1 M SHA-1 synthetic set (`synth_hset 1000000 20 ... hull`)

Wall-clock seconds, best of three, output to `/dev/null` (writing the 41 MB
text file to the shared `/work` mount costs about 1.2 s on its own and
hides everything else).

| command | before (69fb167) | after |
|---|---:|---:|
| `hset dump` | 0.129 | 0.031 |
| `hset query -f all.txt -q` | 0.454 | 0.407 |

Dump output is byte-identical. In the new `query -f` profile hex decoding is
no longer visible; the remaining time is reading lines into one `String`
each (`read_until`, malloc) and the lookups themselves.

## Pitfalls met along the way

* `encode_to_string` / `encode_to_writer` first zeroed an 8 KiB stack
  scratch buffer per call, which cost about 250 ns and made the per-hash
  writer loop slower than the allocating one. Inputs up to 64 bytes now use
  a 128-byte buffer.
* `cargo build --examples` builds only the examples, so the first
  end-to-end comparison ran a stale `hset` binary from before the SIMD work.
  Check binary timestamps before timing.
