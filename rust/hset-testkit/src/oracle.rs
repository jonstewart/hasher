//! Independent reference oracles for property, fuzz and mutation testing:
//! [`NaiveSet`] (linear-scan membership/lookup), [`set_op_model`] (`BTreeSet`
//! algebra for set operations) and [`hex_oracle`] (a from-scratch hex codec).
//! None of these delegate to `hset::lookup` or `hset::hex` — they exist to be
//! compared against those implementations.

use std::collections::BTreeSet;
use std::ops::Range;

use hset::SetOp;

/// A linear-scan reference set of fixed-width rows, kept however it was
/// built (callers that want `equal_range` to be a contiguous span of equal
/// rows must build from sorted data, duplicates included).
#[derive(Debug, Clone)]
pub struct NaiveSet {
    pub rows: Vec<Vec<u8>>,
    pub width: usize,
}

impl NaiveSet {
    /// Splits `data` into `width`-byte rows via `chunks_exact`; any short
    /// trailing remainder is discarded.
    pub fn from_bytes(data: &[u8], width: usize) -> NaiveSet {
        NaiveSet {
            rows: data.chunks_exact(width).map(<[u8]>::to_vec).collect(),
            width,
        }
    }

    /// True iff some row equals the first `width` bytes of `h`.
    pub fn contains(&self, h: &[u8]) -> bool {
        self.find(h).is_some()
    }

    /// The index of the first row equal to the first `width` bytes of `h`,
    /// found by a linear scan.
    pub fn find(&self, h: &[u8]) -> Option<usize> {
        let key = &h[..self.width];
        self.rows.iter().position(|r| r.as_slice() == key)
    }

    /// The span of rows equal to the first `width` bytes of `h`, or `0..0`
    /// when absent.
    pub fn equal_range(&self, h: &[u8]) -> Range<usize> {
        let key = &h[..self.width];
        let Some(first) = self.rows.iter().position(|r| r.as_slice() == key) else {
            return 0..0;
        };
        let last = self
            .rows
            .iter()
            .rposition(|r| r.as_slice() == key)
            .expect("first was found, so rposition must find it too");
        first..last + 1
    }
}

/// A reference implementation of set operations via `BTreeSet` algebra.
pub fn set_op_model(op: SetOp, a: &BTreeSet<Vec<u8>>, b: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
    match op {
        SetOp::Union => a.union(b).cloned().collect(),
        SetOp::Intersect => a.intersection(b).cloned().collect(),
        SetOp::Subtract => a.difference(b).cloned().collect(),
    }
}

/// A from-scratch hex codec, independent of `hset::hex`.
pub mod hex_oracle {
    /// Lowercase, two hex digits per byte.
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Decodes a hex string (either case). `None` on odd length or any
    /// byte that is not a hex digit.
    pub fn decode(s: &[u8]) -> Option<Vec<u8>> {
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let (chunks, _) = s.as_chunks::<2>();
        chunks
            .iter()
            .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hset::synth::SplitMix64;

    #[test]
    fn naive_set_matches_btreeset() {
        let width = 3;
        let mut rng = SplitMix64::new(1);
        let mut data = vec![0u8; 200 * width];
        rng.fill(&mut data);
        let mut rows: Vec<Vec<u8>> = data.chunks_exact(width).map(|r| r.to_vec()).collect();
        rows.sort();
        let mut flat = Vec::with_capacity(rows.len() * width);
        for r in &rows {
            flat.extend_from_slice(r);
        }
        let set = NaiveSet::from_bytes(&flat, width);
        let btree: BTreeSet<Vec<u8>> = rows.iter().cloned().collect();

        let check = |h: &[u8]| {
            assert_eq!(
                set.contains(h),
                btree.contains(h),
                "contains mismatch for {h:?}"
            );
            let expected_find = rows.iter().position(|r| r.as_slice() == h);
            assert_eq!(set.find(h), expected_find, "find mismatch for {h:?}");
            let positions: Vec<usize> = rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.as_slice() == h)
                .map(|(i, _)| i)
                .collect();
            let expected_range = if positions.is_empty() {
                0..0
            } else {
                positions[0]..positions[positions.len() - 1] + 1
            };
            assert_eq!(
                set.equal_range(h),
                expected_range,
                "equal_range mismatch for {h:?}"
            );
        };

        for row in &rows {
            check(row);
        }

        let mut probe_rng = SplitMix64::new(2);
        let mut probes = vec![0u8; 50 * width];
        probe_rng.fill(&mut probes);
        for probe in probes.chunks_exact(width) {
            check(probe);
        }
    }

    #[test]
    fn naive_set_uses_prefix_of_longer_query() {
        let width = 2;
        let rows_data = [0x01u8, 0x02, 0x03, 0x04, 0xAA, 0xBB];
        let set = NaiveSet::from_bytes(&rows_data, width);

        let hit = [0x03u8, 0x04, 0x99, 0x99, 0x99];
        assert_eq!(hit.len(), 5);
        assert!(set.contains(&hit));

        let miss = [0x03u8, 0x05, 0x99, 0x99, 0x99];
        assert_eq!(miss.len(), 5);
        assert!(!set.contains(&miss));
    }

    #[test]
    fn set_op_model_on_small_sets() {
        let a: BTreeSet<Vec<u8>> = [vec![1u8], vec![2], vec![3]].into_iter().collect();
        let b: BTreeSet<Vec<u8>> = [vec![2u8], vec![3], vec![4]].into_iter().collect();

        let union: BTreeSet<Vec<u8>> = [vec![1u8], vec![2], vec![3], vec![4]].into_iter().collect();
        let intersect: BTreeSet<Vec<u8>> = [vec![2u8], vec![3]].into_iter().collect();
        let subtract: BTreeSet<Vec<u8>> = [vec![1u8]].into_iter().collect();

        assert_eq!(set_op_model(SetOp::Union, &a, &b), union);
        assert_eq!(set_op_model(SetOp::Intersect, &a, &b), intersect);
        assert_eq!(set_op_model(SetOp::Subtract, &a, &b), subtract);
    }

    #[test]
    fn hex_oracle_roundtrip_and_rejects() {
        assert_eq!(hex_oracle::encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_oracle::decode(b"00ABff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(hex_oracle::decode(b"abc"), None);
        assert_eq!(hex_oracle::decode(b"zz"), None);
        assert_eq!(hex_oracle::decode(b""), Some(vec![]));
    }
}
