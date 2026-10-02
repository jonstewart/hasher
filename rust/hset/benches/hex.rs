//! Hex encode/decode throughput: SIMD kernels versus the scalar reference.
//!
//! Each digest width that appears in `.hset` files is measured (MD5 16,
//! SHA-1 20, SHA-256 32, SHA-512 64 bytes), plus a long buffer that shows the
//! steady-state rate without per-call overhead. Throughput is in input bytes
//! for encode and in output bytes for decode, so the two are comparable.
//!
//! The `hex/rows` group measures the batch paths that `hset dump` and
//! `hset query -f` use, in ns per hash, against the per-call loops they
//! replaced.
//!
//! Environment knobs:
//! * `HSET_BENCH_HEX_LEVELS=1` also run the SIMD kernels pinned to the
//!   compile-time baseline level (SSE2 on x86_64) for comparison with the
//!   runtime-detected level.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fearless_simd::Level;
use hset::hex;

const WIDTHS: &[(&str, usize)] = &[
    ("md5", 16),
    ("sha1", 20),
    ("sha256", 32),
    ("sha512", 64),
    ("4k", 4096),
];

fn sample_bytes(len: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64 | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let mut g = c.benchmark_group("hex/encode");
    let detected = Level::new();
    let pin_levels = std::env::var_os("HSET_BENCH_HEX_LEVELS").is_some();
    for &(name, len) in WIDTHS {
        let bytes = sample_bytes(len);
        let mut out = vec![0u8; len * 2];
        g.throughput(Throughput::Bytes(len as u64));

        g.bench_with_input(BenchmarkId::new("scalar", name), &bytes, |b, bytes| {
            b.iter(|| {
                hex::scalar::encode_into(black_box(bytes), &mut out);
                black_box(&out);
            })
        });
        g.bench_with_input(BenchmarkId::new("simd", name), &bytes, |b, bytes| {
            b.iter(|| {
                hex::simd::encode_into(black_box(bytes), &mut out);
                black_box(&out);
            })
        });
        if pin_levels {
            for level in [Level::baseline(), detected] {
                let id = BenchmarkId::new(format!("simd@{level:?}"), name);
                g.bench_with_input(id, &bytes, |b, bytes| {
                    b.iter(|| {
                        hex::simd::encode_into_at(level, black_box(bytes), &mut out);
                        black_box(&out);
                    })
                });
            }
        }
        // The allocating public entry point, as callers actually use it.
        g.bench_with_input(
            BenchmarkId::new("encode-string", name),
            &bytes,
            |b, bytes| b.iter(|| hex::encode(black_box(bytes))),
        );
    }
    g.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut g = c.benchmark_group("hex/decode");
    let detected = Level::new();
    let pin_levels = std::env::var_os("HSET_BENCH_HEX_LEVELS").is_some();
    for &(name, len) in WIDTHS {
        let bytes = sample_bytes(len);
        let lower = hex::encode(&bytes);
        let upper = lower.to_ascii_uppercase();
        let mut out = vec![0u8; len];
        g.throughput(Throughput::Bytes(len as u64));

        g.bench_with_input(BenchmarkId::new("scalar", name), &lower, |b, s| {
            b.iter(|| {
                let ok = hex::scalar::decode_into(black_box(s.as_bytes()), &mut out);
                black_box((ok, &out));
            })
        });
        g.bench_with_input(BenchmarkId::new("simd", name), &lower, |b, s| {
            b.iter(|| {
                let ok = hex::simd::decode_into(black_box(s.as_bytes()), &mut out);
                black_box((ok, &out));
            })
        });
        g.bench_with_input(BenchmarkId::new("simd-upper", name), &upper, |b, s| {
            b.iter(|| {
                let ok = hex::simd::decode_into(black_box(s.as_bytes()), &mut out);
                black_box((ok, &out));
            })
        });
        if pin_levels {
            for level in [Level::baseline(), detected] {
                let id = BenchmarkId::new(format!("simd@{level:?}"), name);
                g.bench_with_input(id, &lower, |b, s| {
                    b.iter(|| {
                        let ok =
                            hex::simd::decode_into_at(level, black_box(s.as_bytes()), &mut out);
                        black_box((ok, &out));
                    })
                });
            }
        }
        // The validating public entry point, as callers actually use it.
        g.bench_with_input(BenchmarkId::new("decode-into", name), &lower, |b, s| {
            b.iter(|| {
                hex::decode_into(black_box(s), &mut out).unwrap();
                black_box(&out);
            })
        });
    }
    g.finish();
}

fn bench_rows(c: &mut Criterion) {
    use std::io::Write;

    let mut g = c.benchmark_group("hex/rows");
    let rows = 4096usize;
    for &(name, width) in &WIDTHS[..4] {
        let data = sample_bytes(rows * width);
        let lines: Vec<String> = data.chunks(width).map(hex::encode).collect();
        g.throughput(Throughput::Elements(rows as u64));

        // Encode: per-row `encode` + writeln (the old dump), per-row writer,
        // batch into a Vec, batch streamed to a writer.
        g.bench_with_input(
            BenchmarkId::new("encode-string-loop", name),
            &data,
            |b, d| {
                let mut sink = Vec::with_capacity(rows * (2 * width + 1));
                b.iter(|| {
                    sink.clear();
                    for row in d.chunks(width) {
                        writeln!(sink, "{}", hex::encode(black_box(row))).unwrap();
                    }
                    black_box(&sink);
                })
            },
        );
        g.bench_with_input(
            BenchmarkId::new("encode-writer-loop", name),
            &data,
            |b, d| {
                let mut sink = Vec::with_capacity(rows * (2 * width + 1));
                b.iter(|| {
                    sink.clear();
                    for row in d.chunks(width) {
                        hex::encode_to_writer(black_box(row), &mut sink).unwrap();
                        sink.push(b'\n');
                    }
                    black_box(&sink);
                })
            },
        );
        g.bench_with_input(BenchmarkId::new("encode-rows", name), &data, |b, d| {
            let mut sink = Vec::with_capacity(rows * (2 * width + 1));
            b.iter(|| {
                sink.clear();
                hex::encode_rows(black_box(d), width, b"\n", &mut sink);
                black_box(&sink);
            })
        });
        g.bench_with_input(
            BenchmarkId::new("encode-rows-writer", name),
            &data,
            |b, d| {
                let mut sink = Vec::with_capacity(rows * (2 * width + 1));
                b.iter(|| {
                    sink.clear();
                    hex::encode_rows_to_writer(black_box(d), width, b"\n", &mut sink).unwrap();
                    black_box(&sink);
                })
            },
        );

        // Decode: per-row `decode_into` (the old query) versus `decode_rows`.
        g.bench_with_input(
            BenchmarkId::new("decode-into-loop", name),
            &lines,
            |b, l| {
                let mut out = Vec::with_capacity(rows * width);
                b.iter(|| {
                    out.clear();
                    for s in l {
                        let start = out.len();
                        out.resize(start + width, 0);
                        hex::decode_into(black_box(s), &mut out[start..]).unwrap();
                    }
                    black_box(&out);
                })
            },
        );
        g.bench_with_input(BenchmarkId::new("decode-rows", name), &lines, |b, l| {
            let mut out = Vec::with_capacity(rows * width);
            b.iter(|| {
                out.clear();
                hex::decode_rows(black_box(l).iter().map(String::as_str), width, &mut out).unwrap();
                black_box(&out);
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_rows);
criterion_main!(benches);
