//! Criterion benchmarks for libhasher's TLSH kernel over FFI.
//!
//!   cd rust/tlsh-bench && cargo bench
//!
//! Groups:
//!   tlsh_diff_pair   one sfhash_tlsh_diff call
//!   knn_brute_ffi    brute-force k=10 nearest neighbours over N digests,
//!                    20 queries per iteration; throughput is in rows
//!   tlsh_hash_4mib   hashing a 4 MiB random buffer through sfhash_*_hasher

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tlsh_bench::{make_corpus, perturb, random_digest, tlsh_hash, knn_brute, SplitMix64, TlshDigest};

const K: usize = 10;
const NUM_QUERIES: usize = 20;
const CORPUS_SIZES: &[usize] = &[10_000, 100_000];
const CORPUS_SEED: u64 = 0x7a5b;
const QUERY_SEED: u64 = 0x51e;

fn queries_for(corpus: &[TlshDigest]) -> Vec<TlshDigest> {
    let mut rng = SplitMix64::new(QUERY_SEED);
    (0..NUM_QUERIES)
        .map(|_| {
            let pick = &corpus[rng.below(corpus.len() as u64) as usize];
            perturb(&mut rng, pick, 0.05)
        })
        .collect()
}

fn tlsh_diff_pair(c: &mut Criterion) {
    let mut rng = SplitMix64::new(1);
    let a = random_digest(&mut rng);
    let b = perturb(&mut rng, &a, 0.1);

    c.bench_function("tlsh_diff_pair", |bench| {
        bench.iter(|| black_box(&a).diff(black_box(&b), true))
    });
}

fn knn_brute_ffi(c: &mut Criterion) {
    let mut group = c.benchmark_group("knn_brute_ffi");
    for &n in CORPUS_SIZES {
        let corpus = make_corpus(CORPUS_SEED, n);
        let queries = queries_for(&corpus);

        // one iteration scans every row once per query
        group.throughput(Throughput::Elements((n * NUM_QUERIES) as u64));
        group.sample_size(if n >= 100_000 { 20 } else { 50 });
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bench, _| {
            bench.iter(|| {
                let mut found = 0usize;
                for q in &queries {
                    found += knn_brute(black_box(&corpus), q, K).len();
                }
                found
            })
        });
    }
    group.finish();
}

fn tlsh_hash_4mib(c: &mut Criterion) {
    const SIZE: usize = 4 << 20;
    let mut buf = vec![0u8; SIZE];
    SplitMix64::new(CORPUS_SEED).fill_bytes(&mut buf);

    let mut group = c.benchmark_group("tlsh_hash_4mib");
    group.throughput(Throughput::Bytes(SIZE as u64));
    group.sample_size(20);
    group.bench_function("sfhash_hasher", |bench| bench.iter(|| tlsh_hash(black_box(&buf))));
    group.finish();
}

criterion_group!(benches, tlsh_diff_pair, knn_brute_ffi, tlsh_hash_4mib);
criterion_main!(benches);
