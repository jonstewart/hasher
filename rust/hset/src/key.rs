//! Primitives for fast hash comparison and position prediction.
//!
//! Cryptographic digests are uniformly distributed, so a lexicographic
//! comparison of two digests is decided by the leading bytes almost every
//! time. Loading the leading bytes as one big-endian integer (the *primary
//! key*) turns the hot comparison of a search into a single integer compare.

use std::cmp::Ordering;

/// Load the leading `min(L, 8)` bytes of `h` as a big-endian integer,
/// left-aligned so the most significant bit of the hash is bit 63.
///
/// Two hashes compare lexicographically exactly as their keys compare,
/// except that equal keys require a tie-break on the remaining bytes.
#[inline(always)]
pub fn key64<const L: usize>(h: &[u8]) -> u64 {
    if L >= 8 {
        u64::from_be_bytes(h[..8].try_into().unwrap())
    } else {
        let mut k = 0u64;
        for &b in &h[..L] {
            k = (k << 8) | u64::from(b);
        }
        k << (8 * (8 - L))
    }
}

/// Runtime-length variant of [`key64`].
#[inline]
pub fn key64_dyn(h: &[u8]) -> u64 {
    let take = h.len().min(8);
    let mut k = 0u64;
    for &b in &h[..take] {
        k = (k << 8) | u64::from(b);
    }
    k << (8 * (8 - take))
}

/// Three-way lexicographic comparison of two `L`-byte hashes.
#[inline(always)]
pub fn cmp_hash<const L: usize>(a: &[u8], b: &[u8]) -> Ordering {
    let ka = key64::<L>(a);
    let kb = key64::<L>(b);
    if ka != kb {
        return ka.cmp(&kb);
    }
    if L <= 8 {
        Ordering::Equal
    } else {
        a[8..L].cmp(&b[8..L])
    }
}

/// Compare the bytes after the primary key (no-op for `L <= 8`).
#[inline(always)]
pub fn tail_eq<const L: usize>(a: &[u8], b: &[u8]) -> bool {
    L <= 8 || a[8..L] == b[8..L]
}

/// The reference position predictor used by the legacy block hint: the
/// leading 32 bits of the hash scaled to the set size.
///
/// `(high32 * n) >> 32` cannot overflow for `n < 2^32`.
#[inline(always)]
pub fn expected_index(h: &[u8], n: u32) -> u32 {
    let high32 = u64::from(u32::from_be_bytes(h[..4].try_into().unwrap()));
    ((high32 * u64::from(n)) >> 32) as u32
}

/// Prefetch the cache line containing `p` into all cache levels.
#[inline(always)]
pub fn prefetch(p: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
        // SAFETY: prefetch is a hint; it never faults, even on invalid
        // addresses, and has no other side effects.
        unsafe { _mm_prefetch::<_MM_HINT_T0>(p as *const i8) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::aarch64::{_PREFETCH_LOCALITY3, _PREFETCH_READ, _prefetch};
        // SAFETY: see above.
        unsafe { _prefetch::<_PREFETCH_READ, _PREFETCH_LOCALITY3>(p as *const i8) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key64_matches_lexicographic_order() {
        let a = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
        let b = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x00, 0x00];
        assert_eq!(key64::<10>(&a), 0x0102030405060708);
        assert!(key64::<10>(&a) < key64::<10>(&b));
        assert_eq!(cmp_hash::<10>(&a, &b), Ordering::Less);
        assert_eq!(key64::<4>(&a), 0x0102030400000000);
        assert_eq!(key64_dyn(&a[..4]), key64::<4>(&a));
        assert_eq!(key64_dyn(&a), key64::<10>(&a));
    }

    #[test]
    fn tail_decides_ties() {
        let a = [0xffu8; 20];
        let mut b = [0xffu8; 20];
        b[19] = 0xfe;
        assert_eq!(key64::<20>(&a), key64::<20>(&b));
        assert_eq!(cmp_hash::<20>(&a, &b), Ordering::Greater);
        assert!(!tail_eq::<20>(&a, &b));
        assert!(tail_eq::<8>(&a, &b));
    }

    #[test]
    fn expected_index_matches_reference_formula() {
        let h = [0x80u8, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(expected_index(&h, 1000), 500);
        let h = [0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        assert_eq!(expected_index(&h, u32::MAX), u32::MAX - 1);
        let h = [0u8; 8];
        assert_eq!(expected_index(&h, 12345), 0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    macro_rules! key_props {
        ($($l:literal => $key64:ident, $cmp:ident;)*) => {
            proptest! {
                $(
                    #[test]
                    fn $key64(h in any::<[u8; $l]>()) {
                        prop_assert_eq!(key64::<$l>(&h), key64_dyn(&h));
                    }

                    #[test]
                    fn $cmp(
                        a in any::<[u8; $l]>(),
                        flip in prop::option::of(0usize..$l),
                        fresh in any::<[u8; $l]>(),
                    ) {
                        let b = match flip {
                            Some(j) => {
                                let mut b = a;
                                b[j] ^= 1;
                                b
                            }
                            None => fresh,
                        };
                        prop_assert_eq!(cmp_hash::<$l>(&a, &b), a.cmp(&b));
                        let t = 8.min($l);
                        prop_assert_eq!(tail_eq::<$l>(&a, &b), a[t..] == b[t..]);
                    }
                )*
            }
        };
    }

    key_props! {
        4 => key64_const_matches_dyn_4, cmp_hash_matches_slice_cmp_4;
        8 => key64_const_matches_dyn_8, cmp_hash_matches_slice_cmp_8;
        16 => key64_const_matches_dyn_16, cmp_hash_matches_slice_cmp_16;
        20 => key64_const_matches_dyn_20, cmp_hash_matches_slice_cmp_20;
        28 => key64_const_matches_dyn_28, cmp_hash_matches_slice_cmp_28;
        32 => key64_const_matches_dyn_32, cmp_hash_matches_slice_cmp_32;
        48 => key64_const_matches_dyn_48, cmp_hash_matches_slice_cmp_48;
        64 => key64_const_matches_dyn_64, cmp_hash_matches_slice_cmp_64;
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    macro_rules! key_proofs {
        ($($l:literal, $unwind:literal => $key64:ident, $cmp:ident;)*) => {
            $(
                #[kani::proof]
                #[kani::unwind($unwind)]
                fn $key64() {
                    let h: [u8; $l] = kani::any();
                    assert!(key64::<$l>(&h) == key64_dyn(&h));
                }

                #[kani::proof]
                #[kani::unwind($unwind)]
                fn $cmp() {
                    let a: [u8; $l] = kani::any();
                    let b: [u8; $l] = kani::any();
                    assert!(cmp_hash::<$l>(&a, &b) == a.cmp(&b));
                }
            )*
        };
    }

    // Unwind bound L + 1 for each length L.
    key_proofs! {
        4, 5 => key64_matches_dyn_4, cmp_hash_matches_slice_cmp_4;
        8, 9 => key64_matches_dyn_8, cmp_hash_matches_slice_cmp_8;
        16, 17 => key64_matches_dyn_16, cmp_hash_matches_slice_cmp_16;
        20, 21 => key64_matches_dyn_20, cmp_hash_matches_slice_cmp_20;
        28, 29 => key64_matches_dyn_28, cmp_hash_matches_slice_cmp_28;
        32, 33 => key64_matches_dyn_32, cmp_hash_matches_slice_cmp_32;
        48, 49 => key64_matches_dyn_48, cmp_hash_matches_slice_cmp_48;
        64, 65 => key64_matches_dyn_64, cmp_hash_matches_slice_cmp_64;
    }

    /// Over one minute: about 96 s of verification under Kani 0.68.
    #[kani::proof]
    #[kani::unwind(1)]
    fn expected_index_below_n() {
        let h: [u8; 4] = kani::any();
        let n: u32 = kani::any();
        kani::assume(n > 0);
        assert!(expected_index(&h, n) < n);
    }
}
