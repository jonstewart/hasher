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
    let mut g = Mt19937_64::new(0x73_6d61_6c6c);
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

fn check_golden(
    rows: &[[u8; 36]],
    ivf: &TlshIvf,
    want_rows: usize,
    want_lists: usize,
    want_sha: &str,
) {
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
    (&ivf).validate(&rows).expect("valid");
}

#[test]
fn golden_bisect_large() {
    let rows = golden_corpus(0x5eed02, &large_cells(), 20);
    let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).expect("build");
    // the coarse split is exercised
    assert!(max_cell_rows(&ivf) > FLAT_MAX as u64);
    let cells = ivf.cell_lists.windows(2).filter(|w| w[0] != w[1]).count();
    assert_eq!(cells, 40);
    check_golden(
        &rows,
        &ivf,
        10400,
        343,
        "b1bb7a6d494bef04007ac04832f89aa00552c11f2d1eb01d6c085d5f0bfe55bb",
    );
    (&ivf).validate(&rows).expect("valid");
}

//
// C++-written fixtures (`make check` in the repository root; untracked, so
// absent files are skipped)
//

/// Tags of the chunks read here (big-endian ASCII, HASHSET_FORMAT).
const FTOC: [u8; 4] = *b"FTOC";
const HDAT: [u8; 4] = *b"HDAT";
const TIVF: [u8; 4] = *b"TIVF";
const TVEC: [u8; 4] = *b"TVEC";
/// The section header of the TLSH hash type, `HH` and log2 of
/// `SFHASH_TLSH` = 1 << 15.
const HH_TLSH: [u8; 4] = [b'H', b'H', 0, 15];

/// The chunks of a hash-set file in FTOC order, as (tag, payload): the
/// FTOC chunk at offset 40 lists (u64 LE offset, u32 BE tag) per chunk,
/// and each chunk is a u32 BE tag, a u64 LE length and the payload. A
/// minimal walker for this test, independent of `hset::format`.
fn chunks(file: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let chunk_at = |off: usize| -> ([u8; 4], &[u8]) {
        let tag: [u8; 4] = file[off..off + 4].try_into().unwrap();
        let len = u64::from_le_bytes(file[off + 4..off + 12].try_into().unwrap()) as usize;
        (tag, &file[off + 12..off + 12 + len])
    };
    let (tag, toc) = chunk_at(40);
    assert_eq!(tag, FTOC, "no FTOC at offset 40");
    toc.as_chunks::<12>()
        .0
        .iter()
        .map(|e| {
            let off = u64::from_le_bytes(e[..8].try_into().unwrap()) as usize;
            let (tag, payload) = chunk_at(off);
            assert_eq!(tag, e[8..12], "FTOC tag differs from the chunk's");
            (tag, payload)
        })
        .collect()
}

/// The TLSH section's HDAT rows and TIVF payload, or `None` when the file
/// has no TLSH section or no TIVF.
fn tlsh_section(file: &[u8]) -> Option<(Vec<[u8; 36]>, Vec<u8>)> {
    let all = chunks(file);
    assert!(
        all.iter().all(|(t, _)| *t != TVEC),
        "a TVEC chunk: a fixture from before the TVEC removal"
    );
    let start = all.iter().position(|(t, _)| *t == HH_TLSH)?;
    let section = &all[start + 1..];
    let end = section
        .iter()
        .position(|(t, _)| t.starts_with(b"HH") || *t == *b"FEND")
        .unwrap_or(section.len());
    let section = &section[..end];
    let (_, hdat) = section.iter().find(|(t, _)| *t == HDAT)?;
    let (_, tivf) = section.iter().find(|(t, _)| *t == TIVF)?;
    assert_eq!(hdat.len() % 36, 0, "HDAT is not whole TLSH rows");
    let rows = hdat.as_chunks::<36>().0.to_vec();
    Some((rows, tivf.to_vec()))
}

#[test]
fn rebuilding_cpp_fixtures_reproduces_their_tivf() {
    let dir = hset_testkit::fixtures::fixtures_dir();
    // plan 3.1: builder outputs of the vendored example digests, records
    // (81 rows, duplicates kept; the TLSH-first file has the same rows) and
    // hashsets-only (80 rows)
    let cases = [
        (
            "md5_tlsh.hset",
            81,
            76,
            "4526562d16fc0251141dd786fc6a810f8bdda64dbd1db43dac06928bc7d901ef",
        ),
        (
            "md5_tlsh_knn.hset",
            81,
            76,
            "4526562d16fc0251141dd786fc6a810f8bdda64dbd1db43dac06928bc7d901ef",
        ),
        (
            "tlsh_md5.hset",
            81,
            76,
            "4526562d16fc0251141dd786fc6a810f8bdda64dbd1db43dac06928bc7d901ef",
        ),
        (
            "md5_tlsh_ho.hset",
            80,
            76,
            "06f4d2ff581774066559d1094f0eda30e3421836615e255069c32026ec1d0d88",
        ),
    ];
    let mut checked = 0;
    for (name, want_rows, want_lists, want_sha) in cases {
        let path = dir.join(name);
        let Ok(file) = std::fs::read(&path) else {
            eprintln!("skipping {}: not found", path.display());
            continue;
        };
        let (rows, payload) = tlsh_section(&file).unwrap_or_else(|| panic!("{name}: no TLSH TIVF"));
        assert_eq!(sha256_hex(&payload), want_sha, "{name}: fixture TIVF");
        let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).expect("build");
        assert_eq!(rows.len(), want_rows, "{name}");
        assert_eq!(ivf.lists(), want_lists, "{name}");
        assert!(
            ivf.to_bytes() == payload,
            "{name}: rebuilt TIVF differs from C++'s"
        );
        checked += 1;
    }
    eprintln!("checked {checked} fixtures in {}", dir.display());
}

#[test]
fn rebuilding_other_fresh_cpp_builds_reproduces_their_tivf() {
    // C++ fixtures whose TIVF is a fresh default BISECT build (not a merge,
    // not KMEANS) over thousands of rows in many cells
    let dir = hset_testkit::fixtures::fixtures_dir();
    let names = [
        "merge_a_ho.hset",
        "merge_a_rec.hset",
        "merge_t1_a.hset",
        "merge_df_a.hset",
        "inc_batch.hset",
        "tlsh_opt2.hset",
    ];
    for name in names {
        let path = dir.join(name);
        let Ok(file) = std::fs::read(&path) else {
            eprintln!("skipping {}: not found", path.display());
            continue;
        };
        let (rows, payload) = tlsh_section(&file).unwrap_or_else(|| panic!("{name}: no TLSH TIVF"));
        let ivf = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).expect("build");
        assert!(
            ivf.to_bytes() == payload,
            "{name}: rebuilt TIVF differs from C++'s"
        );
    }
}
