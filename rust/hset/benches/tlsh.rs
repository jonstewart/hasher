//! TLSH kernel and search throughput: the body kernel over a row slice,
//! brute-force and TIVF kNN per query, and the BISECT index build.
//!
//! Environment knobs:
//! * `HSET_BENCH_TLSH_N`     comma-separated synthetic corpus sizes
//!   (default `100000,1000000`)
//! * `HSET_BENCH_TLSH_TEXT`  comma-separated text files to take corpora
//!   from instead (one digest per line, the last whitespace-separated
//!   field, `T1` hex; `TNULL` and unparsable lines are skipped), e.g. the
//!   C++ synthetic hsets' inputs `/work/vs-eval/synthetic/s1m.txt`
//! * `HSET_BENCH_TLSH_BUILD_MAX` largest corpus the build is benchmarked
//!   on (default 100000)
//!
//! The synthetic corpus is `hset_testkit::tlsh::corpus`: families of ten
//! digest-space perturbations of uniformly random bases. The C++
//! `bench_tlsh` corpus hashes real content instead (`make_tlsh_corpus`),
//! which concentrates L and Q in fewer cells; the text knob runs the same
//! digests as the C++ synthetic hsets.
//!
//! Query workloads, 20 queries each, a Criterion iteration answering all
//! 20 (so `elem/s` is queries per second):
//! * `near`   a sampled row with 6 random plane bits flipped; k = 10,
//!   max_distance = 144 (the shape of `bench_tlsh`'s queries)
//! * `member` a sampled row; k = 100, unbounded (`vs_knn_eval`'s member set)
//! * `random` a uniformly random digest; k = 100, unbounded
//!   (`vs_knn_eval`'s random set)
//!
//! The queries are defined by plain SplitMix64 draws on the sorted rows
//! (see [`queries`]) so another harness can reproduce them exactly.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hset::synth::SplitMix64;
use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf};
use hset::tlsh::ivf::search::knn_ivf;
use hset::tlsh::{BodyQuery, IvfIndex, KnnStats, TlshDigest, knn_brute};
use hset_testkit::tlsh::{corpus, sorted_rows};

type Row = [u8; 36];

const QUERIES: usize = 20;
const QUERY_SEED: u64 = 0x51E5_EED5;
const CORPUS_SEED: u64 = 0x7A5B;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_list(name: &str) -> Option<Vec<String>> {
    let v = std::env::var(name).ok()?;
    Some(
        v.split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
    )
}

/// Sorted rows of the digests in a text file.
fn read_text(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let digests: Vec<TlshDigest> = text
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|f| TlshDigest::from_hex(f).ok())
        .filter(|d| !d.is_null())
        .collect();
    sorted_rows(&digests)
}

/// `(label, sorted rows)` per corpus.
fn corpora() -> Vec<(String, Vec<Row>)> {
    if let Some(files) = env_list("HSET_BENCH_TLSH_TEXT") {
        return files
            .iter()
            .map(|f| {
                let rows = read_text(f);
                let name = std::path::Path::new(f)
                    .file_stem()
                    .map_or(f.clone(), |s| s.to_string_lossy().into_owned());
                (format!("{name}-{}", rows.len()), rows)
            })
            .collect();
    }
    env_list("HSET_BENCH_TLSH_N")
        .unwrap_or_else(|| vec!["100000".into(), "1000000".into()])
        .iter()
        .map(|s| {
            let n: usize = s.parse().expect("HSET_BENCH_TLSH_N entries are sizes");
            (format!("synth-{n}"), sorted_rows(&corpus(CORPUS_SEED, n)))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum QuerySet {
    Near,
    Member,
    Random,
}

/// [`QUERIES`] query digests over sorted `rows`, from SplitMix64 seeded
/// with `QUERY_SEED + set` (set 0 near, 1 member, 2 random), every draw a
/// `next_u64()`:
/// * member: `rows[draw % n]`;
/// * near: a member, then 6 times `p = draw % 256` flips bit `p % 8` of
///   byte `2 + p / 8` (the bit planes);
/// * random: bytes 0..35 are the little-endian bytes of five draws in
///   order (the last draw's top 4 bytes unused), byte 35 is 0, and a null
///   result gets checksum (byte 34) 1.
fn queries(rows: &[Row], set: QuerySet) -> Vec<TlshDigest> {
    let mut rng = SplitMix64::new(QUERY_SEED + set as u64);
    let n = rows.len() as u64;
    (0..QUERIES)
        .map(|_| match set {
            QuerySet::Member => TlshDigest(rows[(rng.next_u64() % n) as usize]),
            QuerySet::Near => {
                let mut b = rows[(rng.next_u64() % n) as usize];
                for _ in 0..6 {
                    let p = (rng.next_u64() % 256) as usize;
                    b[2 + p / 8] ^= 1 << (p % 8);
                }
                TlshDigest(b)
            }
            QuerySet::Random => {
                let mut b = [0u8; 36];
                for w in 0..5 {
                    let bytes = rng.next_u64().to_le_bytes();
                    let take = (36 - 8 * w).min(8);
                    b[8 * w..8 * w + take].copy_from_slice(&bytes[..take]);
                }
                b[35] = 0;
                let mut d = TlshDigest(b);
                if d.is_null() {
                    d.0[34] = 1;
                }
                d
            }
        })
        .collect()
}

/// The sum of the body distances from `q` to every row.
#[inline(always)]
fn body_sum(q: &BodyQuery, rows: &[Row]) -> u32 {
    let mut s = 0u32;
    for r in rows {
        s = s.wrapping_add(q.body(r));
    }
    s
}

/// [`body_sum`] compiled for POPCNT.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
fn body_sum_popcnt(q: &BodyQuery, rows: &[Row]) -> u32 {
    body_sum(q, rows)
}

/// `(name, set, k, max_distance)`.
const WORKLOADS: [(&str, QuerySet, usize, u32); 3] = [
    ("near", QuerySet::Near, 10, 144),
    ("member", QuerySet::Member, 100, u32::MAX),
    ("random", QuerySet::Random, 100, u32::MAX),
];

fn bench_tlsh(c: &mut Criterion) {
    let build_max = env_usize("HSET_BENCH_TLSH_BUILD_MAX", 100_000);
    for (label, rows) in corpora() {
        let n = rows.len();
        let t0 = std::time::Instant::now();
        let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).unwrap();
        eprintln!(
            "{label}: {n} rows, BISECT build {:.1} ms, {} lists",
            t0.elapsed().as_secs_f64() * 1e3,
            ivf.lists()
        );
        let valid = (&ivf).validate(&rows).unwrap();

        // body kernel over every row: as a caller's loop compiles it, and
        // compiled for POPCNT as the crate's scans are
        let mut g = c.benchmark_group("tlsh/body");
        g.throughput(Throughput::Elements(n as u64));
        g.sample_size(20);
        let q = black_box(BodyQuery::new(&queries(&rows, QuerySet::Near)[0]));
        g.bench_function(BenchmarkId::new("body_query", &label), |b| {
            b.iter(|| body_sum(&q, &rows))
        });
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("popcnt") {
            g.bench_function(BenchmarkId::new("body_query_popcnt", &label), |b| {
                // SAFETY: the CPU has POPCNT, checked above.
                b.iter(|| unsafe { body_sum_popcnt(&q, &rows) })
            });
        }
        g.finish();

        for (wl, set, k, max_distance) in WORKLOADS {
            let qs = queries(&rows, set);
            let mut stats = KnnStats::default();
            for (qi, q) in qs.iter().enumerate() {
                let brute = knn_brute(&rows, q, k, max_distance, true);
                let ivf_hits = knn_ivf(&valid, q, k, max_distance, true, Some(&mut stats));
                assert_eq!(brute, ivf_hits, "{label} {wl} query {qi}");
            }
            let per = |x: u64| x / QUERIES as u64;
            eprintln!(
                "{label} {wl}: ivf per query visits {} cells, bounds {} lists, scans {} rows",
                per(stats.cells),
                per(stats.lists),
                per(stats.rows)
            );
            let mut g = c.benchmark_group(format!("tlsh/knn/{wl}"));
            g.throughput(Throughput::Elements(QUERIES as u64));
            g.warm_up_time(Duration::from_secs(1));
            g.measurement_time(Duration::from_secs(5));
            g.sample_size(10);
            g.bench_function(BenchmarkId::new("brute", &label), |b| {
                b.iter(|| {
                    for q in &qs {
                        black_box(knn_brute(&rows, q, k, max_distance, true));
                    }
                })
            });
            g.bench_function(BenchmarkId::new("ivf", &label), |b| {
                b.iter(|| {
                    for q in &qs {
                        black_box(knn_ivf(&valid, q, k, max_distance, true, None));
                    }
                })
            });
            g.finish();
        }

        if n <= build_max {
            let mut g = c.benchmark_group("tlsh/build_ivf");
            g.throughput(Throughput::Elements(n as u64));
            g.sample_size(10);
            for threads in [1, 0] {
                let opts = IvfBuildOptions {
                    threads,
                    ..IvfBuildOptions::default()
                };
                let name = if threads == 0 {
                    "bisect_all"
                } else {
                    "bisect_1"
                };
                g.bench_function(BenchmarkId::new(name, &label), |b| {
                    b.iter(|| build_tlsh_ivf(&rows, &opts).unwrap())
                });
            }
            g.finish();
        }
    }
}

criterion_group!(benches, bench_tlsh);
criterion_main!(benches);
