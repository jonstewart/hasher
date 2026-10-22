//! Criterion benchmarks for libhasher's TLSH kernel and hash set kNN over FFI.
//!
//!   cd rust/tlsh-bench && cargo bench
//!   cargo bench -- hset_knn --warm-up-time 1 --measurement-time 3
//!   TLSH_BENCH_N=10000,100000 cargo bench -- hset_knn
//!
//! Groups:
//!   tlsh_diff_pair   one sfhash_tlsh_diff call
//!   knn_brute_ffi    brute-force k=10 nearest neighbours over N digests,
//!                    20 queries per iteration; throughput is in rows
//!   tlsh_hash_4mib   hashing a 4 MiB random buffer through sfhash_*_hasher
//!   hset_knn         naive brute force (one sfhash_tlsh_diff call per row)
//!                    against sfhash_hashset_tlsh_knn_with BRUTE / INDEX and
//!                    sfhash_hashset_tlsh_knn (default) over an hset file of
//!                    N rows; k=10, max_distance=144, include_length=true,
//!                    20 queries per iteration; throughput is rows x queries
//!
//! The hset files for hset_knn are written once per N into a fresh directory
//! under the system temp dir (build time is printed, not benchmarked) and
//! removed when the group finishes.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput};
use tlsh_bench::{
    build_tlsh_hset, knn_brute, knn_brute_with, make_corpus, make_hashed_corpus, perturb, random_digest, tlsh_hash,
    Hashset, SplitMix64, TlshDigest, TlshMatch, HSET_TLSH_INDEX, TLSH_KNN_BRUTE, TLSH_KNN_INDEX,
};

const K: usize = 10;
const MAX_DISTANCE: u32 = 144;
const INCLUDE_LENGTH: bool = true;
const NUM_QUERIES: usize = 20;
const CORPUS_SIZES: &[usize] = &[10_000, 100_000];
const HSET_SIZES: &[usize] = &[10_000, 100_000, 1_000_000];
const CORPUS_SEED: u64 = 0x7a5b;
const QUERY_SEED: u64 = 0x51e;

/// `TLSH_BENCH_N` as a comma-separated list, or the defaults.
fn sizes_from_env(default: &[usize]) -> Vec<usize> {
    match std::env::var("TLSH_BENCH_N") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| t.replace('_', "").parse().unwrap_or_else(|_| panic!("TLSH_BENCH_N: bad size {t:?}")))
            .collect(),
        _ => default.to_vec(),
    }
}

/// NUM_QUERIES digests drawn from the corpus, each perturbed once.
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

    c.bench_function("tlsh_diff_pair", |bench| bench.iter(|| black_box(&a).diff(black_box(&b), true)));
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

/// A fresh directory for the hset files, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> ScratchDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("tlsh-bench-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&p).expect("create scratch dir");
        ScratchDir(p)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Everything one N needs: the hset on disk and loaded, its rows in memory
/// (sorted and deduplicated, so indexes agree with the file), and the queries.
struct HsetCase {
    n: usize,
    hset: Hashset,
    tidx: usize,
    rows: Vec<TlshDigest>,
    queries: Vec<TlshDigest>,
}

fn prepare_case(dir: &ScratchDir, n: usize) -> HsetCase {
    let t0 = Instant::now();
    let corpus = make_hashed_corpus(CORPUS_SEED, n);
    let queries = queries_for(&corpus);
    let t_corpus = t0.elapsed();

    let path = dir.0.join(format!("tlsh-{n}.hset"));
    let t1 = Instant::now();
    // the index only; the TVEC matrix (n x 264 x f32) is not needed for kNN
    let bytes = build_tlsh_hset(&path, &corpus, HSET_TLSH_INDEX).expect("build hset");
    let t_build = t1.elapsed();

    let t2 = Instant::now();
    let hset = Hashset::open(&path).expect("load hset");
    let tidx = hset.tlsh_index().expect("TLSH hash set");
    let rows = hset.tlsh_rows(tidx);
    let t_load = t2.elapsed();

    assert_eq!(
        hset.tlsh_knn_strategies(tidx),
        TLSH_KNN_BRUTE | TLSH_KNN_INDEX,
        "hset has no TIVF index"
    );

    eprintln!(
        "hset_knn N={n}: corpus {:.2}s, build {:.2}s ({:.1} MiB, {} rows), load {:.2}s",
        t_corpus.as_secs_f64(),
        t_build.as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0),
        rows.len(),
        t_load.as_secs_f64()
    );

    HsetCase { n, hset, tidx, rows, queries }
}

/// Every strategy must give the same answer for every query (outside timing).
fn check_agreement(case: &HsetCase) {
    let HsetCase { hset, tidx, rows, queries, .. } = case;
    for (qi, q) in queries.iter().enumerate() {
        let naive = knn_brute_with(rows, q, K, MAX_DISTANCE, INCLUDE_LENGTH);
        let brute = hset.tlsh_knn(*tidx, q, K, MAX_DISTANCE, INCLUDE_LENGTH, Some(TLSH_KNN_BRUTE));
        let index = hset.tlsh_knn(*tidx, q, K, MAX_DISTANCE, INCLUDE_LENGTH, Some(TLSH_KNN_INDEX));
        let dflt = hset.tlsh_knn(*tidx, q, K, MAX_DISTANCE, INCLUDE_LENGTH, None);
        assert_eq!(brute, naive, "N={} query {qi}: hset brute != naive", case.n);
        assert_eq!(index, naive, "N={} query {qi}: hset index != naive", case.n);
        assert_eq!(dflt, naive, "N={} query {qi}: hset default != naive", case.n);
    }
}

fn hset_knn(c: &mut Criterion) {
    let sizes = sizes_from_env(HSET_SIZES);
    let dir = ScratchDir::new();

    let mut group = c.benchmark_group("hset_knn");
    // the naive scan takes hundreds of ms per iteration at 1M rows
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for n in sizes {
        let case = prepare_case(&dir, n);
        check_agreement(&case);

        let HsetCase { hset, tidx, rows, queries, .. } = &case;
        let rows_n = rows.len();

        // one iteration answers every query over every row
        group.throughput(Throughput::Elements((rows_n * NUM_QUERIES) as u64));

        group.bench_with_input(BenchmarkId::new("naive_brute_ffi", n), &n, |bench, _| {
            bench.iter(|| {
                let mut found = 0usize;
                for q in queries {
                    found += knn_brute_with(black_box(rows), q, K, MAX_DISTANCE, INCLUDE_LENGTH).len();
                }
                found
            })
        });

        let mut out: Vec<TlshMatch> = Vec::with_capacity(K);
        let strategies: [(&str, Option<u32>); 3] = [
            ("hset_knn_brute", Some(TLSH_KNN_BRUTE)),
            ("hset_knn_index", Some(TLSH_KNN_INDEX)),
            ("hset_knn_default", None),
        ];
        for (name, strategy) in strategies {
            group.bench_with_input(BenchmarkId::new(name, n), &n, |bench, _| {
                bench.iter(|| {
                    let mut found = 0usize;
                    for q in queries {
                        found += black_box(hset).tlsh_knn_into(
                            *tidx,
                            black_box(q),
                            K,
                            MAX_DISTANCE,
                            INCLUDE_LENGTH,
                            strategy,
                            &mut out,
                        );
                    }
                    found
                })
            });
        }

        // free the file before the next N
        drop(case);
        let _ = fs::remove_file(dir.0.join(format!("tlsh-{n}.hset")));
    }
    group.finish();
}

criterion_group!(kernel, tlsh_diff_pair, knn_brute_ffi, tlsh_hash_4mib);
criterion_group! {
    name = hset;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = hset_knn
}
criterion_main!(kernel, hset);
