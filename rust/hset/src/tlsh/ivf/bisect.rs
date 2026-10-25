//! The BISECT builder of TIVF indexes (`build_tlsh_ivf`).

use super::{DEFAULT_SEED, TARGET_LIST_SIZE, TlshIvf};
use crate::error::{Error, Result};
use crate::tlsh::CELL_COUNT;
use crate::tlsh::digest::{DIGEST_LENGTH, TlshDigest};
use crate::tlsh::distance::BodyQuery;
use crate::tlsh::mt64::Mt19937_64;

/// A raw 36-byte row of a TLSH section.
type Row = [u8; DIGEST_LENGTH];

/// Options of [`build_tlsh_ivf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IvfBuildOptions {
    /// The clustering target `T`: lists hold about this many rows.
    pub target_list_size: usize,
    /// Seed of the random draws.
    pub seed: u64,
    /// Threads to cluster cells on; 0 = available parallelism.
    pub threads: usize,
}

impl Default for IvfBuildOptions {
    fn default() -> Self {
        Self {
            target_list_size: TARGET_LIST_SIZE,
            seed: DEFAULT_SEED,
            threads: 0,
        }
    }
}

/// Whether the squared distance `big_a / n_a^2` is strictly smaller than
/// `big_b / n_b^2`, compared exactly as `big_a * n_b^2 < big_b * n_a^2`
/// (C++ `tlsh_ivf_nearer`).
///
/// In the flat k-means the squared distance from a row `x` to a centroid
/// of `n` members with coordinate sum `S` is `||x - S / n||^2 = N / n^2`,
/// `N = ||n x - S||^2`. With `x` and every member in `{-1, 0, 1}^256`,
/// `|n x_j - S_j| <= 2n`, so `N <= 2^10 n^2`; for `n <= FLAT_MAX = 2^12`
/// both products are at most `2^58`. Beyond that range the products wrap,
/// as the C++ `uint64_t` products do.
pub const fn nearer(big_a: u64, n_a: u64, big_b: u64, n_b: u64) -> bool {
    big_a.wrapping_mul(n_b).wrapping_mul(n_b) < big_b.wrapping_mul(n_a).wrapping_mul(n_a)
}

// The products of `nearer` stay in 64 bits for nodes of up to 2^13 rows
// (2^10 * 2^26 * 2^26 = 2^62), as C++'s static_assert requires.
const _: () = assert!(super::FLAT_MAX <= 8192);

/// The lists of one cell: per list its medoid, radius2 and size, and the
/// members concatenated (row indexes of the whole section, ascending
/// within a list).
#[derive(Default)]
struct CellLists {
    medoids: Vec<TlshDigest>,
    radius2: Vec<u32>,
    sizes: Vec<u32>,
    ids: Vec<u32>,
}

/// Build the BISECT index over sorted rows.
pub fn build_tlsh_ivf(rows: &[Row], opts: &IvfBuildOptions) -> Result<TlshIvf> {
    if opts.target_list_size == 0 {
        return Err(Error::input("target_list_size must be positive"));
    }
    let n = rows.len() as u64;
    if n > u64::from(u32::MAX) {
        return Err(Error::input("too many rows for a TIVF index"));
    }
    let cells = cell_bounds(rows)?;
    let nonempty: Vec<usize> = (0..CELL_COUNT)
        .filter(|&c| cells[c] != cells[c + 1])
        .collect();

    let results: Vec<CellLists> = nonempty
        .iter()
        .map(|&c| {
            let mut rng = Mt19937_64::new(opts.seed ^ (c as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let _ = &mut rng;
            bisect_cell(&rows[cells[c]..cells[c + 1]], cells[c] as u32)
        })
        .collect();

    // concatenate in cell order
    let mut ivf = TlshIvf {
        n,
        cell_lists: vec![0; CELL_COUNT + 1],
        medoids: Vec::new(),
        radius2: Vec::new(),
        list_start: vec![0],
        ids: Vec::with_capacity(rows.len()),
    };
    let mut ri = 0;
    for c in 0..CELL_COUNT {
        ivf.cell_lists[c] = ivf.lists() as u32;
        if nonempty.get(ri) == Some(&c) {
            let r = &results[ri];
            ri += 1;
            ivf.medoids.extend_from_slice(&r.medoids);
            ivf.radius2.extend_from_slice(&r.radius2);
            for &sz in &r.sizes {
                let last = *ivf.list_start.last().expect("list_start starts at 0");
                ivf.list_start.push(last + u64::from(sz));
            }
            ivf.ids.extend_from_slice(&r.ids);
        }
    }
    ivf.cell_lists[CELL_COUNT] = ivf.lists() as u32;
    Ok(ivf)
}

/// The start of each cell's rows in sorted `rows`, `CELL_COUNT + 1`
/// entries (C++ `make_tlsh_cell_index`, whose sortedness check it keeps).
fn cell_bounds(rows: &[Row]) -> Result<Vec<usize>> {
    let mut cells = vec![0usize; CELL_COUNT + 1];
    for (i, r) in rows.iter().enumerate() {
        if i > 0 && r < &rows[i - 1] {
            return Err(Error::input("TLSH rows are not sorted"));
        }
        cells[usize::from(TlshDigest(*r).cell()) + 1] += 1;
    }
    for c in 1..=CELL_COUNT {
        cells[c] += cells[c - 1];
    }
    Ok(cells)
}

/// The lists of one cell's rows; ids written are local indexes plus
/// `base`.
fn bisect_cell(rows: &[Row], base: u32) -> CellLists {
    let ids: Vec<u32> = (0..rows.len() as u32).collect();
    let (med, r2) = one_center(rows, &ids);
    CellLists {
        medoids: vec![TlshDigest(rows[med as usize])],
        radius2: vec![r2],
        sizes: vec![ids.len() as u32],
        ids: ids.iter().map(|&id| base + id).collect(),
    }
}

/// The exact 1-center of the rows `ids` (local indexes into `rows`,
/// ascending): the member whose largest squared body-embedding distance
/// to the others is smallest, ties by the smaller index. Returns
/// `(medoid, radius2)` (C++ `one_center`).
fn one_center(rows: &[Row], ids: &[u32]) -> (u32, u32) {
    let (mut best, mut best_r) = (ids[0], u32::MAX);
    for &i in ids {
        let q = BodyQuery::new(&TlshDigest(rows[i as usize]));
        let mut r = 0;
        for &j in ids {
            if r > best_r {
                break;
            }
            r = r.max(q.emb_body(&rows[j as usize]));
        }
        if r < best_r || (r == best_r && i < best) {
            best = i;
            best_r = r;
        }
    }
    (best, best_r)
}
