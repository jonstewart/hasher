//! Cost of building hint tables and sorting input.

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hset::lookup::{self, HintSpec};
use hset::synth;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn bench_build(c: &mut Criterion) {
    let n = env_usize("HSET_BENCH_N", 1_000_000);
    let hlen = 20usize;
    let data = synth::sorted_unique_hashes(n, hlen, 0x7ACE_7357_C0FF_EE01);

    let mut g = c.benchmark_group("build/hint");
    g.throughput(Throughput::Elements(n as u64));
    g.measurement_time(Duration::from_secs(5));
    g.sample_size(10);
    for (name, spec) in [
        ("block8", HintSpec::Block { bits: 8 }),
        ("block14", HintSpec::Block { bits: 14 }),
        ("hull8", HintSpec::Hull { bits: 8 }),
        ("hull14", HintSpec::Hull { bits: 14 }),
        ("hull18", HintSpec::Hull { bits: 18 }),
    ] {
        g.bench_with_input(BenchmarkId::new(name, n), &spec, |b, spec| {
            b.iter(|| lookup::build_hint(hlen, &data, *spec).unwrap())
        });
    }
    g.finish();

    let mut g = c.benchmark_group("build/sort");
    g.throughput(Throughput::Elements(n as u64));
    g.sample_size(10);
    let mut unsorted = vec![0u8; n * hlen];
    synth::SplitMix64::new(5).fill(&mut unsorted);
    g.bench_function(BenchmarkId::new("sorted_rows", n), |b| {
        b.iter(|| hset::builder::sorted_rows(&unsorted, hlen, true))
    });
    g.finish();
}

criterion_group!(benches, bench_build);
criterion_main!(benches);
