//! Row sets and kNN queries for the TLSH index targets (`tivf`, `bisect`),
//! included by each with `#[path]`.
//!
//! A row's L and Q bytes are drawn from eight values each, so a small row
//! set shares cells (and the IVF has multi-row cells and multi-list
//! cells) instead of spreading one row per cell over 65,536 cells. The
//! values include the ends of each range, where the circular L and Q
//! distances wrap.

use arbitrary::Arbitrary;
use hset::tlsh::ivf::search::knn_ivf;
use hset::tlsh::{DIGEST_LENGTH, IvfIndex, KnnStats, TlshDigest, knn_brute};

pub type Row = [u8; DIGEST_LENGTH];

const L_CHOICES: [u8; 8] = [0, 1, 2, 40, 128, 200, 254, 255];
const Q_CHOICES: [u8; 8] = [0x00, 0x01, 0x10, 0x11, 0x0F, 0xF0, 0x88, 0xFF];

/// Most rows a case builds from its specs.
pub const MAX_ROWS: usize = 256;

/// Most queries a case runs.
pub const MAX_QUERIES: usize = 4;

#[derive(Arbitrary, Debug, Clone)]
pub struct RowSpec {
    l: u8,
    q: u8,
    checksum: u8,
    body: [u8; 32],
}

impl RowSpec {
    /// The row: L and Q from the choice tables, the body and checksum as
    /// given, the reserved byte 0.
    pub fn row(&self) -> Row {
        let mut r = [0u8; DIGEST_LENGTH];
        r[0] = L_CHOICES[usize::from(self.l % 8)];
        r[1] = Q_CHOICES[usize::from(self.q % 8)];
        r[2..34].copy_from_slice(&self.body);
        r[34] = self.checksum;
        r
    }
}

/// The rows of up to [`MAX_ROWS`] specs, sorted bytewise as an `HDAT` is.
pub fn sorted_rows(specs: &[RowSpec]) -> Vec<Row> {
    let mut rows: Vec<Row> = specs.iter().take(MAX_ROWS).map(RowSpec::row).collect();
    rows.sort_unstable();
    rows
}

#[derive(Arbitrary, Debug)]
pub struct QuerySpec {
    /// Query with this row of the set (modulo its length), if any rows.
    row: Option<u16>,
    /// Otherwise this digest.
    digest: RowSpec,
    /// Flip the bits of the body at these positions (so the query is near
    /// a row without being one).
    flips: Vec<u8>,
    k: u8,
    max_distance: u16,
    include_length: bool,
}

impl QuerySpec {
    fn query(&self, rows: &[Row]) -> TlshDigest {
        let mut q = match self.row {
            Some(i) if !rows.is_empty() => rows[usize::from(i) % rows.len()],
            _ => self.digest.row(),
        };
        for &f in self.flips.iter().take(8) {
            q[2 + usize::from(f / 8) % 32] ^= 1 << (f % 8);
        }
        TlshDigest(q)
    }
}

/// `knn_ivf` over the index returns exactly what `knn_brute` returns over
/// its rows, for each of the first [`MAX_QUERIES`] queries.
pub fn check_knn<I: IvfIndex + ?Sized>(ivf: &I, rows: &[Row], queries: &[QuerySpec]) {
    for spec in queries.iter().take(MAX_QUERIES) {
        let q = spec.query(rows);
        let k = usize::from(spec.k % 12);
        let max_distance = u32::from(spec.max_distance);
        let mut stats = KnnStats::default();
        let got = knn_ivf(
            ivf,
            rows,
            &q,
            k,
            max_distance,
            spec.include_length,
            Some(&mut stats),
        )
        .expect("knn_ivf on a valid index");
        let want = knn_brute(rows, &q, k, max_distance, spec.include_length);
        assert_eq!(got, want, "knn_ivf != knn_brute for {q:?}, {spec:?}");
        assert!(stats.rows <= rows.len() as u64, "{stats:?}");
    }
}
