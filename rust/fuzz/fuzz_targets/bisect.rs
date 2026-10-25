#![no_main]

//! The BISECT build over small sorted row sets, and one cell just past
//! `FLAT_MAX` rows so the coarse bisection runs. The build never fails or
//! panics on sorted rows, its index validates (every list nonempty, the
//! lists partition the rows by cell), every medoid is a member, `radius2`
//! is exact, a flat cell of `s` rows has at most `ceil(s / T)` lists, the
//! thread count does not change the result, the payload round-trips
//! through `TivfView`, and `knn_ivf` agrees with `knn_brute`. Unsorted rows
//! are refused. The coalescing invariant is not required of a build.

#[path = "common/tlsh.rs"]
mod common;

use arbitrary::Arbitrary;
use common::{QuerySpec, Row, RowSpec, check_knn, sorted_rows};
use hset::Error;
use hset::tlsh::ivf::FLAT_MAX;
use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf};
use hset::tlsh::{BodyQuery, IvfIndex, TivfView, TlshDigest, TlshIvf};
use libfuzzer_sys::fuzz_target;

/// `big` selects a large case: the first row's cell gets this many rows
/// plus up to 1023 more, near copies of the specs' bodies.
const BIG: u8 = 0xB1;
const BIG_ROWS: usize = FLAT_MAX + 1;

#[derive(Arbitrary, Debug)]
struct BisectCase {
    rows: Vec<RowSpec>,
    big: u8,
    extra: u16,
    /// Bits flipped per copied row in a large case (0: exact copies).
    flips: u8,
    target: u8,
    seed: u64,
    threads: u8,
    queries: Vec<QuerySpec>,
}

/// SplitMix64, for the bit flips of a large case's copies.
fn splitmix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn case_rows(case: &BisectCase) -> Vec<Row> {
    let mut rows = sorted_rows(&case.rows);
    if case.big == BIG && !rows.is_empty() {
        let base = rows.clone();
        let n = BIG_ROWS + usize::from(case.extra % 1024);
        for i in 0..n {
            let mut r = base[i % base.len()];
            r[..2].copy_from_slice(&base[0][..2]);
            for f in 0..u64::from(case.flips % 4) {
                let bit = splitmix(case.seed ^ ((i as u64) << 2) ^ f) % 256;
                r[2 + (bit / 8) as usize] ^= 1 << (bit % 8);
            }
            rows.push(r);
        }
        rows.sort_unstable();
    }
    rows
}

/// The cells of sorted rows, ascending, each once.
fn row_cells(rows: &[Row]) -> Vec<usize> {
    let mut cells: Vec<usize> = rows
        .iter()
        .map(|r| usize::from(TlshDigest(*r).cell()))
        .collect();
    cells.dedup();
    cells
}

/// Checked over the cells that have rows only: validation has shown that
/// no other cell has a list, and a walk over all 65,536 cells costs more
/// under the fuzzer's comparison tracing than the build does.
fn check_shape(ivf: &TlshIvf, rows: &[Row], target: usize) {
    for c in row_cells(rows) {
        let lists = ivf.cell_range(c);
        let cell_rows: u64 = lists.clone().map(|l| ivf.list_len(l)).sum();
        if cell_rows as usize <= FLAT_MAX {
            assert!(
                lists.len() <= (cell_rows as usize).div_ceil(target),
                "cell 0x{c:04x}: {} lists over {cell_rows} rows, T = {target}",
                lists.len()
            );
        }
        for l in lists {
            let medoid = ivf.medoid(l);
            let body = BodyQuery::new(&medoid);
            let mut is_member = false;
            let mut radius2 = 0;
            for id in ivf.list_ids(l) {
                let row = &rows[id as usize];
                is_member |= *row == medoid.0;
                radius2 = radius2.max(body.emb_body(row));
            }
            assert!(is_member, "list {l}: medoid {medoid:?} is not a member");
            assert_eq!(ivf.radius2(l), radius2, "list {l}: radius2 is not exact");
        }
    }
}

fuzz_target!(|case: BisectCase| {
    let rows = case_rows(&case);
    let opts = IvfBuildOptions {
        target_list_size: 1 + usize::from(case.target % 64),
        seed: case.seed,
        threads: 1 + usize::from(case.threads % 3),
    };
    let ivf = build_tlsh_ivf(&rows, &opts).expect("build over sorted rows");
    if opts.threads != 1 {
        let one = build_tlsh_ivf(&rows, &IvfBuildOptions { threads: 1, ..opts }).unwrap();
        assert_eq!(ivf, one, "the thread count changed the index");
    }

    // Validated once, through the payload: the view holds the same arrays
    // (from_index), so this is the build's validation too, and each full
    // validation walks all 65,536 cells.
    let bytes = ivf.to_bytes();
    let view = TivfView::parse(&bytes, rows.len() as u64).expect("own payload parses");
    assert_eq!(TlshIvf::from_index(&view), ivf);
    let valid = view.validate(&rows).expect("a fresh build validates");
    check_shape(&ivf, &rows, opts.target_list_size);
    check_knn(&valid, &case.queries);

    // Swap the first two rows that differ: no longer sorted.
    if let Some(i) = rows.windows(2).position(|w| w[0] != w[1]) {
        let mut unsorted = rows.clone();
        unsorted.swap(i, i + 1);
        assert!(matches!(
            build_tlsh_ivf(&unsorted, &opts),
            Err(Error::Input(_))
        ));
    }
});
