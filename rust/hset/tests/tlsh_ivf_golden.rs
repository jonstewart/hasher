//! Golden test for the reproducibility of BISECT index bytes, ported from
//! `test/test_tlsh_ivf_golden.cpp`.
//!
//! BISECT uses integer arithmetic only and draws straight from
//! `mt19937_64`, so for the same rows and seed its TIVF payload is the
//! same on every platform and in both languages. The corpora are generated
//! as in C++: integer arithmetic on `mt19937_64` output only. Each case
//! checks the row count, the list count, `ids.len()` and the SHA-256 of
//! the payload of the default build; the constants are the C++ ones
//! (recorded on arm64 macOS / clang), so a mismatch is a parity bug, not
//! something to update.
//!
//! The C++ KMEANS exactness check of the same corpora is not ported
//! (KMEANS is not built in Rust).

use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf};
use hset::tlsh::ivf::{FLAT_MAX, IvfIndex, TARGET_LIST_SIZE, TlshIvf};
use hset::tlsh::mt64::Mt19937_64;
use sha2::{Digest, Sha256};

/// One header cell of a corpus: its L and row count.
struct CellSpec {
    l: u8,
    rows: usize,
}

/// Offsets in a row (C++ `TlshDigest`: L, Q, hi[16], lo[16], checksum,
/// reserved).
const HI: usize = 2;
const LO: usize = 18;
const CHECKSUM: usize = 34;

/// Rows of the given cells (L per cell, Q drawn), each cell's rows in
/// families of `family_size`: a random base body, then each member a copy
/// with up to 7 random body bits flipped and a random checksum. Sorted and
/// deduplicated (C++ `golden_corpus`, draw for draw).
fn golden_corpus(seed: u64, cells: &[CellSpec], family_size: usize) -> Vec<[u8; 36]> {
    let mut g = Mt19937_64::new(seed);
    let mut rows = Vec::new();
    for c in cells {
        let q = (g.next_u64() & 0xFF) as u8;
        let mut base = [0u8; 36];
        for i in 0..c.rows {
            if i % family_size == 0 {
                for b in 0..16 {
                    base[HI + b] = (g.next_u64() & 0xFF) as u8;
                    base[LO + b] = (g.next_u64() & 0xFF) as u8;
                }
            }
            let mut d = base;
            d[0] = c.l;
            d[1] = q;
            d[CHECKSUM] = (g.next_u64() & 0xFF) as u8;
            d[35] = 0;
            let flips = g.next_u64() % 8;
            for _ in 0..flips {
                let bit = (g.next_u64() % 256) as usize;
                let plane = if bit < 128 { HI } else { LO };
                d[plane + ((bit % 128) >> 3)] ^= 1u8 << (bit & 7);
            }
            rows.push(d);
        }
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// One cell above FLAT_MAX (coarse split), 39 smaller cells of 20-219
/// rows (flat k-means, several above T = 32).
fn large_cells() -> Vec<CellSpec> {
    let mut g = Mt19937_64::new(0x676f_6c64_656e);
    let mut cells = vec![CellSpec { l: 0, rows: 5000 }];
    for c in 1..40u8 {
        cells.push(CellSpec {
            l: 5 * c,
            rows: 20 + (g.next_u64() % 200) as usize,
        });
    }
    cells
}

/// 12 cells of 150-399 rows: flat only.
fn small_cells() -> Vec<CellSpec> {
    let mut g = Mt19937_64::new(0x736d_616c_6c);
    (0..12u8)
        .map(|c| CellSpec {
            l: 7 + 11 * c,
            rows: 150 + (g.next_u64() % 250) as usize,
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Rows of the largest cell.
fn max_cell_rows(ivf: &TlshIvf) -> u64 {
    ivf.cell_lists
        .windows(2)
        .map(|w| ivf.list_start[w[1] as usize] - ivf.list_start[w[0] as usize])
        .max()
        .unwrap_or(0)
}

fn check_golden(rows: &[[u8; 36]], ivf: &TlshIvf, want_rows: usize, want_lists: usize, want_sha: &str) {
    let got = sha256_hex(&ivf.to_bytes());
    let info = format!(
        "rows {}, lists {}, ids {}, sha256 {got}",
        rows.len(),
        ivf.lists(),
        ivf.ids.len()
    );
    assert_eq!(rows.len(), want_rows, "{info}");
    assert_eq!(ivf.ids.len(), want_rows, "{info}");
    assert_eq!(ivf.lists(), want_lists, "{info}");
    assert_eq!(got, want_sha, "{info}");
}

#[test]
fn sha256_helper_matches_fips_180_2() {
    // so a golden mismatch is not the helper's
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn golden_bisect_small() {
    let rows = golden_corpus(0x5eed01, &small_cells(), 20);
    let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).expect("build");
    assert!(max_cell_rows(&ivf) > TARGET_LIST_SIZE as u64);
    assert!(max_cell_rows(&ivf) <= FLAT_MAX as u64);
    check_golden(
        &rows,
        &ivf,
        2844,
        94,
        "bdc17ba69181cce3886aba9a75cfabf6eccdf442e5b58c29b36f1379218598be",
    );
    ivf.validate(&rows).expect("valid");
}

#[test]
fn golden_bisect_large() {
    let rows = golden_corpus(0x5eed02, &large_cells(), 20);
    let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).expect("build");
    // the coarse split is exercised
    assert!(max_cell_rows(&ivf) > FLAT_MAX as u64);
    check_golden(
        &rows,
        &ivf,
        10400,
        343,
        "b1bb7a6d494bef04007ac04832f89aa00552c11f2d1eb01d6c085d5f0bfe55bb",
    );
    ivf.validate(&rows).expect("valid");
}
