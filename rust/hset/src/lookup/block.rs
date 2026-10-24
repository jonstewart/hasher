//! Flat per-block deviation bounds (the legacy `0x6208` hint and its
//! finer-grained generalisation).
//!
//! For block `b` (leading `bits` of the hash) the table stores the minimum and
//! maximum of `actual_index - expected_index` over the block's hashes, where
//! `expected_index` is the leading 32 bits scaled to the set size.

use super::model::block_index;
use crate::key::{expected_index, key64};

/// Sentinel pair for an empty block (`min > max`).
pub const EMPTY: (i64, i64) = (i64::MAX, i64::MIN);

/// Build the flat table for sorted `data` with `L` bytes per hash.
pub fn build_table<const L: usize>(data: &[u8], bits: u8) -> Vec<(i64, i64)> {
    let n = data.len() / L;
    assert!(n < (1usize << 32), "too many hashes for a 32-bit index");
    assert!(L >= 4, "flat blocks need at least 4-byte hashes");
    let mut table = vec![EMPTY; 1usize << bits];
    for i in 0..n {
        let h = &data[i * L..(i + 1) * L];
        let e = i64::from(expected_index(h, n as u32));
        let d = i as i64 - e;
        let b = block_index(key64::<L>(h), bits);
        let (lo, hi) = &mut table[b];
        *lo = (*lo).min(d);
        *hi = (*hi).max(d);
    }
    table
}

pub fn table_to_bytes(table: &[(i64, i64)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(table.len() * 16);
    for (lo, hi) in table {
        v.extend_from_slice(&lo.to_le_bytes());
        v.extend_from_slice(&hi.to_le_bytes());
    }
    v
}

pub fn table_from_bytes(bytes: &[u8]) -> Vec<(i64, i64)> {
    bytes
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| {
            (
                i64::from_le_bytes(c[..8].try_into().unwrap()),
                i64::from_le_bytes(c[8..].try_into().unwrap()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    #[test]
    fn bounds_cover_every_hash() {
        let data = synth::adversarial_hashes(10_000, 20, 3);
        let n = (data.len() / 20) as u32;
        for bits in [8u8, 12] {
            let t = build_table::<20>(&data, bits);
            for i in 0..n as usize {
                let h = &data[i * 20..(i + 1) * 20];
                let (lo, hi) = t[block_index(key64::<20>(h), bits)];
                let e = i64::from(expected_index(h, n));
                assert!(e + lo <= i as i64 && (i as i64) <= e + hi);
            }
        }
    }

    #[test]
    fn bytes_roundtrip() {
        let data = synth::sorted_unique_hashes(500, 16, 9);
        let t = build_table::<16>(&data, 5);
        let b = table_to_bytes(&t);
        assert_eq!(b.len(), 32 * 16);
        assert_eq!(table_from_bytes(&b), t);
    }
}
