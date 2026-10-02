//! Window models: given a query hash, bound the index range that could hold it.

use super::block;
use super::hull::{HullEntry, frac_of};
use crate::key::{expected_index, prefetch};

/// Index of the block holding `key` when the key space is split on its top `bits` bits.
#[inline(always)]
pub fn block_index(key: u64, bits: u8) -> usize {
    if bits == 0 {
        0
    } else {
        (key >> (64 - bits)) as usize
    }
}

/// A position model. `window` returns a half-open index range, clamped to
/// `[0, n)`, that is guaranteed to contain `hash` if the set contains it.
pub trait Model: Send + Sync {
    fn window(&self, key: u64, hash: &[u8], n: u32) -> (u32, u32);
    /// The model's point prediction of where `hash` would sit (unclamped).
    fn center(&self, key: u64, hash: &[u8], n: u32) -> i64;
    /// Positions spanned by a key difference of `dkey` near `key`, i.e. the
    /// model's local density. Used to re-aim after a missed region.
    fn delta(&self, key: u64, dkey: u64, n: u32) -> u64;
    /// Windows for many keys at once into `lo`/`hi`. The default loops over
    /// [`Model::window`]; table models gather their entries first and then
    /// run the arithmetic as a plain loop over arrays so it can vectorise.
    fn window_batch(
        &self,
        keys: &[u64],
        hashes: &[u8],
        hlen: usize,
        n: u32,
        lo: &mut [u32],
        hi: &mut [u32],
    ) {
        for (j, &k) in keys.iter().enumerate() {
            let (a, b) = self.window(k, &hashes[j * hlen..(j + 1) * hlen], n);
            lo[j] = a;
            hi[j] = b;
        }
    }

    /// Prefetch whatever `window` will read for `key` (no-op if nothing).
    #[inline(always)]
    fn prefetch_entry(&self, key: u64) {
        let _ = key;
    }
    /// Mean window width over the model's blocks, if the model has blocks.
    fn mean_window(&self) -> Option<f64> {
        None
    }
    fn describe(&self) -> String;
    /// Auxiliary memory used by the model.
    fn table_bytes(&self) -> usize;
}

/// No model: the whole array.
#[derive(Debug, Clone, Copy, Default)]
pub struct Full;

impl Model for Full {
    #[inline(always)]
    fn window(&self, _key: u64, _hash: &[u8], n: u32) -> (u32, u32) {
        (0, n)
    }

    #[inline(always)]
    fn center(&self, key: u64, _hash: &[u8], n: u32) -> i64 {
        ((u128::from(key) * u128::from(n)) >> 64) as i64
    }

    #[inline(always)]
    fn delta(&self, _key: u64, dkey: u64, n: u32) -> u64 {
        ((u128::from(dkey) * u128::from(n)) >> 64) as u64
    }

    fn describe(&self) -> String {
        "binary search over the full array".into()
    }

    fn table_bytes(&self) -> usize {
        0
    }
}

/// Flat per-block `[min, max]` deviation from the expected index.
#[derive(Debug, Clone)]
pub struct FlatBlocks {
    pub bits: u8,
    pub table: Vec<(i64, i64)>,
}

impl FlatBlocks {
    pub fn from_bytes(bits: u8, bytes: &[u8]) -> Self {
        FlatBlocks {
            bits,
            table: block::table_from_bytes(bytes),
        }
    }
}

impl Model for FlatBlocks {
    #[inline(always)]
    fn window(&self, key: u64, hash: &[u8], n: u32) -> (u32, u32) {
        let (dmin, dmax) = self.table[block_index(key, self.bits)];
        if dmin > dmax {
            return (0, 0);
        }
        let e = i64::from(expected_index(hash, n));
        let lo = (e + dmin).clamp(0, i64::from(n));
        let hi = (e + dmax + 1).clamp(lo, i64::from(n));
        (lo as u32, hi as u32)
    }

    #[inline(always)]
    fn center(&self, key: u64, hash: &[u8], n: u32) -> i64 {
        let (dmin, dmax) = self.table[block_index(key, self.bits)];
        i64::from(expected_index(hash, n)) + (dmin + dmax) / 2
    }

    #[inline(always)]
    fn delta(&self, _key: u64, dkey: u64, n: u32) -> u64 {
        ((u128::from(dkey) * u128::from(n)) >> 64) as u64
    }

    #[inline(always)]
    fn prefetch_entry(&self, key: u64) {
        prefetch(
            self.table
                .as_ptr()
                .wrapping_add(block_index(key, self.bits)) as *const u8,
        );
    }

    fn mean_window(&self) -> Option<f64> {
        let widths: Vec<f64> = self
            .table
            .iter()
            .filter(|(lo, hi)| lo <= hi)
            .map(|(lo, hi)| (hi - lo + 1) as f64)
            .collect();
        (!widths.is_empty()).then(|| widths.iter().sum::<f64>() / widths.len() as f64)
    }

    fn describe(&self) -> String {
        format!("flat {}-bit blocks", self.bits)
    }

    fn table_bytes(&self) -> usize {
        self.table.len() * 16
    }
}

/// Per-block convex-hull fitted lines; see [`super::hull`].
#[derive(Debug, Clone)]
pub struct HullBlocks {
    pub bits: u8,
    pub table: Vec<HullEntry>,
}

impl HullBlocks {
    pub fn from_bytes(bits: u8, bytes: &[u8]) -> Self {
        HullBlocks {
            bits,
            table: super::hull::table_from_bytes(bytes),
        }
    }
}

impl Model for HullBlocks {
    #[inline(always)]
    fn window(&self, key: u64, _hash: &[u8], n: u32) -> (u32, u32) {
        let e = &self.table[block_index(key, self.bits)];
        e.window(frac_of(key, self.bits), n)
    }

    fn window_batch(
        &self,
        keys: &[u64],
        _hashes: &[u8],
        _hlen: usize,
        n: u32,
        lo: &mut [u32],
        hi: &mut [u32],
    ) {
        const MAX: usize = 256;
        debug_assert!(keys.len() <= MAX);
        let m = keys.len().min(MAX);
        let mut frac = [0u32; MAX];
        let mut slope = [0u32; MAX];
        let mut rmin = [0i32; MAX];
        let mut rmax = [0i32; MAX];
        // Gather: independent table loads.
        for j in 0..m {
            let k = keys[j];
            let e = &self.table[block_index(k, self.bits)];
            frac[j] = frac_of(k, self.bits);
            slope[j] = e.slope;
            rmin[j] = e.rmin;
            rmax[j] = e.rmax;
        }
        // Arithmetic over arrays: 32x32->64 multiply, shift, add, clamp.
        let nn = i64::from(n);
        for j in 0..m {
            let p = ((u64::from(frac[j]) * u64::from(slope[j])) >> 32) as i64;
            let a = (p + i64::from(rmin[j])).clamp(0, nn);
            let b = (p + i64::from(rmax[j]) + 1).clamp(a, nn);
            lo[j] = a as u32;
            hi[j] = b as u32;
        }
    }

    #[inline(always)]
    fn center(&self, key: u64, _hash: &[u8], _n: u32) -> i64 {
        let e = &self.table[block_index(key, self.bits)];
        e.predict(frac_of(key, self.bits)) + (i64::from(e.rmin) + i64::from(e.rmax)) / 2
    }

    #[inline(always)]
    fn delta(&self, key: u64, dkey: u64, _n: u32) -> u64 {
        let e = &self.table[block_index(key, self.bits)];
        // slope is positions per 2^32 frac units; one frac unit is 2^(32-bits) key units.
        ((u128::from(dkey) * u128::from(e.slope)) >> (64 - u32::from(self.bits))) as u64
    }

    #[inline(always)]
    fn prefetch_entry(&self, key: u64) {
        prefetch(
            self.table
                .as_ptr()
                .wrapping_add(block_index(key, self.bits)) as *const u8,
        );
    }

    fn mean_window(&self) -> Option<f64> {
        let widths: Vec<f64> = self
            .table
            .iter()
            .filter(|e| !e.is_empty())
            .map(|e| e.width() as f64)
            .collect();
        (!widths.is_empty()).then(|| widths.iter().sum::<f64>() / widths.len() as f64)
    }

    fn describe(&self) -> String {
        format!("convex-hull lines over {}-bit blocks", self.bits)
    }

    fn table_bytes(&self) -> usize {
        self.table.len() * 12
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_index_uses_top_bits() {
        assert_eq!(block_index(0xffff_0000_0000_0000, 8), 0xff);
        assert_eq!(block_index(0x1234_0000_0000_0000, 16), 0x1234);
        assert_eq!(block_index(0xffff_ffff_ffff_ffff, 0), 0);
        assert_eq!(block_index(0x8000_0000_0000_0000, 1), 1);
    }

    #[test]
    fn full_model_is_whole_array() {
        assert_eq!(Full.window(0, &[0; 20], 123), (0, 123));
    }

    #[test]
    fn empty_flat_block_gives_empty_window() {
        let m = FlatBlocks {
            bits: 1,
            table: vec![block::EMPTY, (-1, 1)],
        };
        assert_eq!(m.window(0, &[0; 20], 100), (0, 0));
        let h = [0x80u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(m.window(0x8000_0000_0000_0000, &h, 100), (49, 52));
    }
}
