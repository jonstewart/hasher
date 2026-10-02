//! Membership lookup latency and throughput across strategies.
//!
//! Environment knobs:
//! * `HSET_BENCH_N`     set size (default 1_000_000)
//! * `HSET_BENCH_HLEN`  hash length in bytes (default 20)
//! * `HSET_BENCH_ALL=1` include extra variants (fixed bit counts, binary single search)

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hset::lookup::{self, BatchMode, BitsPolicy, HintSpec, Lookup, SearchConfig, SingleMode};
use hset::synth;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Variant {
    name: String,
    spec: HintSpec,
    cfg: SearchConfig,
}

fn variants(n: usize, hlen: usize) -> Vec<Variant> {
    let policy = BitsPolicy::default();
    let hull_bits = match lookup::resolve_bits(HintSpec::Hull { bits: u8::MAX }, n, hlen, &policy) {
        HintSpec::Hull { bits } => bits,
        _ => unreachable!(),
    };
    let block_bits = match lookup::resolve_bits(HintSpec::Block { bits: 0 }, n, hlen, &policy) {
        HintSpec::Block { bits } => bits,
        _ => unreachable!(),
    };
    let cfg = SearchConfig::default();
    let binary = SearchConfig {
        single: SingleMode::Binary,
        batch: BatchMode::Lanes,
        ..SearchConfig::default()
    };
    let mut v = vec![
        Variant {
            name: "none-auto".into(),
            spec: HintSpec::None,
            cfg,
        },
        Variant {
            name: "block8-legacy".into(),
            spec: HintSpec::LEGACY,
            cfg,
        },
        Variant {
            name: format!("block{block_bits}-auto"),
            spec: HintSpec::Block { bits: block_bits },
            cfg,
        },
        Variant {
            name: format!("hull{hull_bits}-auto"),
            spec: HintSpec::Hull { bits: hull_bits },
            cfg,
        },
    ];
    let recursive = SearchConfig {
        single: SingleMode::Recursive,
        ..SearchConfig::default()
    };
    v.push(Variant {
        name: format!("hull{hull_bits}-recursive"),
        spec: HintSpec::Hull { bits: hull_bits },
        cfg: recursive,
    });
    if std::env::var("HSET_BENCH_ALL").is_ok() {
        v.push(Variant {
            name: "hull0-recursive".into(),
            spec: HintSpec::Hull { bits: 0 },
            cfg: recursive,
        });
        v.push(Variant {
            name: "none-recursive".into(),
            spec: HintSpec::None,
            cfg: recursive,
        });
        for bits in [8u8, 12, 14] {
            v.push(Variant {
                name: format!("hull{bits}-recursive"),
                spec: HintSpec::Hull { bits },
                cfg: recursive,
            });
        }
        v.push(Variant {
            name: "none-binary".into(),
            spec: HintSpec::None,
            cfg: binary,
        });
        v.push(Variant {
            name: format!("hull{hull_bits}-binary"),
            spec: HintSpec::Hull { bits: hull_bits },
            cfg: binary,
        });
        v.push(Variant {
            name: format!("block{block_bits}-binary"),
            spec: HintSpec::Block { bits: block_bits },
            cfg: binary,
        });
        for bits in [8u8, 12, 14, 16, 18, 20] {
            if bits != hull_bits {
                v.push(Variant {
                    name: format!("hull{bits}"),
                    spec: HintSpec::Hull { bits },
                    cfg,
                });
            }
            if bits != block_bits && bits != 8 {
                v.push(Variant {
                    name: format!("block{bits}"),
                    spec: HintSpec::Block { bits },
                    cfg,
                });
            }
        }
    }
    v
}

type BuiltVariant = (Variant, Option<(u16, Vec<u8>)>);

fn bench_lookup(c: &mut Criterion) {
    let n = env_usize("HSET_BENCH_N", 1_000_000);
    let hlen = env_usize("HSET_BENCH_HLEN", 20);
    let data = synth::sorted_unique_hashes(n, hlen, 0x7ACE_7357_C0FF_EE01);
    let m = 1usize << 16;
    let miss = synth::queries(&data, hlen, m, 0.0, 0xDEAD_BEEF_5A5A_0002);
    let hit = synth::queries(&data, hlen, m, 1.0, 0xDEAD_BEEF_5A5A_0003);
    let workloads = [("miss", &miss), ("hit", &hit)];
    let batch = 4096usize;

    let built: Vec<BuiltVariant> = variants(n, hlen)
        .into_iter()
        .map(|v| {
            let hint = lookup::build_hint(hlen, &data, v.spec).unwrap();
            (v, hint)
        })
        .collect();

    for (kind, pipelined) in [("single", false), ("batch", true)] {
        for (wl, queries) in workloads {
            let mut g = c.benchmark_group(format!("lookup/{kind}/{wl}"));
            g.warm_up_time(Duration::from_secs(1));
            g.measurement_time(Duration::from_secs(4));
            g.sample_size(20);
            for (v, hint) in &built {
                let h = hint.as_ref().map(|(t, b)| lookup::hint_from_parts(*t, b));
                let lk: Box<dyn Lookup> =
                    lookup::make_lookup_with(hlen, &data, h.as_ref(), v.cfg).unwrap();
                if pipelined {
                    g.throughput(Throughput::Elements(batch as u64));
                    let mut out = vec![false; batch];
                    let mut off = 0usize;
                    g.bench_with_input(BenchmarkId::new(&v.name, n), &lk, |b, lk| {
                        b.iter(|| {
                            let q = &queries[off * hlen..(off + batch) * hlen];
                            off = (off + batch) % (m - batch);
                            lk.contains_batch(q, &mut out);
                            black_box(&out);
                        })
                    });
                } else {
                    g.throughput(Throughput::Elements(1));
                    let mut i = 0usize;
                    g.bench_with_input(BenchmarkId::new(&v.name, n), &lk, |b, lk| {
                        b.iter(|| {
                            let q = &queries[i * hlen..(i + 1) * hlen];
                            i = (i + 1) & (m - 1);
                            black_box(lk.contains(black_box(q)))
                        })
                    });
                }
            }
            g.finish();
        }
    }
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);
