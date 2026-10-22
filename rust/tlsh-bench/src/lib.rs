//! Thin wrappers over libhasher's TLSH C API (`include/hasher/tlsh.h`,
//! `include/hasher/hasher.h`), plus a deterministic synthetic digest
//! generator and a brute-force kNN used by the Criterion benchmarks.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::MaybeUninit;

/// `SFHASH_TLSH_DIGEST_LENGTH`
pub const TLSH_DIGEST_LENGTH: usize = 36;
/// `SFHASH_TLSH_HEX_LENGTH`: "T1" + 70 hex characters, without the NUL
pub const TLSH_HEX_LENGTH: usize = 72;
/// `SFHASH_TLSH` from `SFHASH_HashAlgorithm`
pub const SFHASH_TLSH: u32 = 1 << 15;

/// Mirror of `struct SFHASH_HashValues`. Keep in sync with
/// `include/hasher/hasher.h`; `tests::hash_values_layout` checks the size.
#[repr(C)]
pub struct HashValues {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha2_224: [u8; 28],
    pub sha2_256: [u8; 32],
    pub sha2_384: [u8; 48],
    pub sha2_512: [u8; 64],
    pub sha3_224: [u8; 28],
    pub sha3_256: [u8; 32],
    pub sha3_384: [u8; 48],
    pub sha3_512: [u8; 64],
    pub blake3: [u8; 32],
    pub fuzzy: [u8; 148],
    pub quick_md5: [u8; 16],
    pub tlsh: [u8; TLSH_DIGEST_LENGTH],
    pub entropy: f64,
}

/// `sizeof(SFHASH_HashValues)` as printed by a C++ program compiled against
/// the headers (612 bytes of digests, padded to 616 for the double, + 8).
pub const HASH_VALUES_SIZE: usize = 624;
/// `offsetof(SFHASH_HashValues, Tlsh)`
pub const HASH_VALUES_TLSH_OFFSET: usize = 576;

/// Opaque `SFHASH_Hasher`.
#[repr(C)]
pub struct RawHasher {
    _private: [u8; 0],
}

pub mod ffi {
    use super::*;

    extern "C" {
        pub fn sfhash_tlsh_from_hex(hex: *const c_char, digest: *mut c_void) -> bool;
        pub fn sfhash_tlsh_to_hex(digest: *const c_void, hex: *mut c_char);
        pub fn sfhash_tlsh_is_null(digest: *const c_void) -> bool;
        pub fn sfhash_tlsh_diff(a: *const c_void, b: *const c_void, include_length: bool) -> c_int;

        pub fn sfhash_create_hasher(hash_algs: u32) -> *mut RawHasher;
        pub fn sfhash_update_hasher(hasher: *mut RawHasher, beg: *const c_void, end: *const c_void);
        pub fn sfhash_get_hashes(hasher: *mut RawHasher, out_hashes: *mut HashValues);
        pub fn sfhash_destroy_hasher(hasher: *mut RawHasher);
    }
}

/// A TLSH digest in libhasher's 36-byte canonical form:
/// L, Q, plane_hi[16], plane_lo[16], checksum, reserved.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct TlshDigest(pub [u8; TLSH_DIGEST_LENGTH]);

impl Default for TlshDigest {
    fn default() -> Self {
        TlshDigest::NULL
    }
}

impl TlshDigest {
    pub const NULL: TlshDigest = TlshDigest([0; TLSH_DIGEST_LENGTH]);

    /// Decodes "T1" + 70 hex characters (prefix optional, either case) or "TNULL".
    pub fn from_hex(hex: &str) -> Option<TlshDigest> {
        let c = CString::new(hex).ok()?;
        let mut d = TlshDigest::NULL;
        let ok = unsafe { ffi::sfhash_tlsh_from_hex(c.as_ptr(), d.0.as_mut_ptr().cast()) };
        ok.then_some(d)
    }

    /// "T1" + 70 uppercase hex characters, or "TNULL".
    pub fn to_hex(&self) -> String {
        let mut buf = [0 as c_char; TLSH_HEX_LENGTH + 1];
        unsafe {
            ffi::sfhash_tlsh_to_hex(self.0.as_ptr().cast(), buf.as_mut_ptr());
            CStr::from_ptr(buf.as_ptr())
        }
        .to_str()
        .expect("sfhash_tlsh_to_hex writes ASCII")
        .to_owned()
    }

    pub fn is_null(&self) -> bool {
        unsafe { ffi::sfhash_tlsh_is_null(self.0.as_ptr().cast()) }
    }

    /// `Tlsh::totalDiff`-identical distance; -1 if either digest is null.
    #[inline]
    pub fn diff(&self, other: &TlshDigest, include_length: bool) -> i32 {
        unsafe { ffi::sfhash_tlsh_diff(self.0.as_ptr().cast(), other.0.as_ptr().cast(), include_length) }
    }

    pub fn l(&self) -> u8 {
        self.0[0]
    }

    pub fn q1(&self) -> u8 {
        self.0[1] >> 4
    }

    pub fn q2(&self) -> u8 {
        self.0[1] & 0x0F
    }

    pub fn checksum(&self) -> u8 {
        self.0[34]
    }

    /// The 2-bit code of bucket `i` (0..128).
    pub fn bucket(&self, i: usize) -> u8 {
        let hi = (self.0[2 + (i >> 3)] >> (i & 7)) & 1;
        let lo = (self.0[18 + (i >> 3)] >> (i & 7)) & 1;
        (hi << 1) | lo
    }

    /// Builds a digest from its fields, like `make_tlsh_digest`.
    pub fn from_fields(l: u8, q1: u8, q2: u8, checksum: u8, codes: &[u8; 128]) -> TlshDigest {
        let mut d = TlshDigest::NULL;
        d.0[0] = l;
        d.0[1] = (q1 << 4) | (q2 & 0x0F);
        d.0[34] = checksum;
        for (i, &c) in codes.iter().enumerate() {
            d.0[2 + (i >> 3)] |= ((c >> 1) & 1) << (i & 7);
            d.0[18 + (i >> 3)] |= (c & 1) << (i & 7);
        }
        d
    }
}

/// A libhasher `SFHASH_Hasher` configured for TLSH only.
pub struct TlshHasher {
    raw: *mut RawHasher,
}

impl TlshHasher {
    pub fn new() -> TlshHasher {
        let raw = unsafe { ffi::sfhash_create_hasher(SFHASH_TLSH) };
        assert!(!raw.is_null(), "sfhash_create_hasher failed");
        TlshHasher { raw }
    }

    pub fn update(&mut self, data: &[u8]) {
        let beg = data.as_ptr();
        unsafe {
            ffi::sfhash_update_hasher(self.raw, beg.cast(), beg.add(data.len()).cast());
        }
    }

    /// The digest of everything fed so far; null if the input cannot be hashed.
    pub fn digest(&mut self) -> TlshDigest {
        let mut hv = MaybeUninit::<HashValues>::zeroed();
        unsafe {
            ffi::sfhash_get_hashes(self.raw, hv.as_mut_ptr());
            TlshDigest(hv.assume_init().tlsh)
        }
    }
}

impl Default for TlshHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TlshHasher {
    fn drop(&mut self) {
        unsafe { ffi::sfhash_destroy_hasher(self.raw) }
    }
}

// The hasher owns its state and is not shared; it is fine to move it between threads.
unsafe impl Send for TlshHasher {}

/// One-shot TLSH of a buffer.
pub fn tlsh_hash(data: &[u8]) -> TlshDigest {
    let mut h = TlshHasher::new();
    h.update(data);
    h.digest()
}

/// SplitMix64: small, fast, and identical on every platform.
#[derive(Clone, Debug)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// uniform in [0, n)
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    /// uniform in [lo, hi]
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    /// uniform in [0, 1)
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// Fills `buf` with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let x = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&x[..chunk.len()]);
        }
    }
}

/// A random, valid-looking, non-null digest: L in 20..=120, random quartile
/// nibbles, bucket codes spread over 0..=3 as the quartile encoding implies.
pub fn random_digest(rng: &mut SplitMix64) -> TlshDigest {
    let l = rng.between(20, 120) as u8;
    let q1 = rng.below(16) as u8;
    let q2 = rng.below(16) as u8;
    let mut codes = [0u8; 128];
    for c in codes.iter_mut() {
        *c = rng.below(4) as u8;
    }
    let checksum = rng.below(256) as u8;
    let d = TlshDigest::from_fields(l, q1, q2, checksum, &codes);
    debug_assert!(!d.is_null());
    d
}

/// Digest-space perturbation, the same scheme as `perturb_tlsh_corpus` in
/// `test/tlsh_corpus.cpp`: each bucket code moves by +-1 with probability
/// `bucket_flip_prob` (clamped to 0..=3), L occasionally moves by +-{1,2},
/// Q1/Q2 occasionally by +-1 (mod 16), and the checksum is redrawn.
pub fn perturb(rng: &mut SplitMix64, seed: &TlshDigest, bucket_flip_prob: f64) -> TlshDigest {
    let mut codes = [0u8; 128];
    for (b, code) in codes.iter_mut().enumerate() {
        let mut c = seed.bucket(b) as i32;
        if rng.chance(bucket_flip_prob) {
            c += if rng.chance(0.5) { 1 } else { -1 };
            c = c.clamp(0, 3);
        }
        *code = c as u8;
    }

    let mut l = seed.l() as i32;
    if rng.chance(0.1) {
        let step = rng.between(1, 2) as i32;
        l += if rng.chance(0.5) { step } else { -step };
        l = l.clamp(0, 255);
    }

    let mut q1 = seed.q1();
    if rng.chance(0.1) {
        q1 = (q1 + if rng.chance(0.5) { 1 } else { 15 }) & 0x0F;
    }

    let mut q2 = seed.q2();
    if rng.chance(0.1) {
        q2 = (q2 + if rng.chance(0.5) { 1 } else { 15 }) & 0x0F;
    }

    let checksum = rng.below(256) as u8;

    let mut d = TlshDigest::from_fields(l as u8, q1, q2, checksum, &codes);
    if d.is_null() {
        d.0[34] = 1;
    }
    d
}

/// `target_size` perturbations of randomly chosen `seeds`.
pub fn perturb_corpus(seed: u64, seeds: &[TlshDigest], target_size: usize, bucket_flip_prob: f64) -> Vec<TlshDigest> {
    let mut rng = SplitMix64::new(seed);
    let mut out = Vec::with_capacity(target_size);
    if seeds.is_empty() {
        return out;
    }
    for _ in 0..target_size {
        let s = &seeds[rng.below(seeds.len() as u64) as usize];
        out.push(perturb(&mut rng, s, bucket_flip_prob));
    }
    out
}

/// A clustered synthetic corpus of exactly `n` digests: ~n/50 random seed
/// digests (at least 1, at most 2000), each output a perturbation of one of
/// them at a per-digest flip probability in [0.02, 0.25).
pub fn make_corpus(seed: u64, n: usize) -> Vec<TlshDigest> {
    let mut rng = SplitMix64::new(seed);
    let num_seeds = (n / 50).clamp(1, 2000);
    let seeds: Vec<TlshDigest> = (0..num_seeds).map(|_| random_digest(&mut rng)).collect();

    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let s = &seeds[rng.below(seeds.len() as u64) as usize];
        let p = 0.02 + rng.unit() * 0.23;
        out.push(perturb(&mut rng, s, p));
    }
    out
}

/// Brute-force k-nearest-neighbours with a bounded max-heap. Returns
/// `(distance, index)` pairs in ascending order; ties at the boundary keep
/// the earlier index.
pub fn knn_brute(corpus: &[TlshDigest], query: &TlshDigest, k: usize) -> Vec<(i32, u32)> {
    let mut heap: BinaryHeap<(i32, u32)> = BinaryHeap::with_capacity(k + 1);
    for (i, d) in corpus.iter().enumerate() {
        let dist = query.diff(d, true);
        if heap.len() < k {
            heap.push((dist, i as u32));
        } else if dist < heap.peek().map(|t| t.0).unwrap_or(i32::MAX) {
            heap.pop();
            heap.push((dist, i as u32));
        }
    }
    heap.into_sorted_vec()
}

/// Exhaustive reference for `knn_brute`: sort everything, take the first k.
pub fn knn_sorted(corpus: &[TlshDigest], query: &TlshDigest, k: usize) -> Vec<(i32, u32)> {
    let mut all: Vec<Reverse<(i32, u32)>> = corpus
        .iter()
        .enumerate()
        .map(|(i, d)| Reverse((query.diff(d, true), i as u32)))
        .collect();
    all.sort_unstable_by(|a, b| b.cmp(a));
    all.into_iter().take(k).map(|r| r.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // from test/test_tlsh.cpp
    const VEC_HEX: &str = "T11FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";

    // TLSH of 4096 bytes from SplitMix64::new(1), as computed by a C++
    // program against libhasher (see rust/tlsh-bench/README.md)
    const SPLITMIX_4096_HEX: &str = "T1D8817EC26F2910E0B9ABB3A7D00CB21F17E9FE957FE63DFAD14739159236101964424E";

    #[test]
    fn hash_values_layout() {
        assert_eq!(size_of::<HashValues>(), HASH_VALUES_SIZE);
        assert_eq!(offset_of!(HashValues, tlsh), HASH_VALUES_TLSH_OFFSET);
        assert_eq!(size_of::<TlshDigest>(), TLSH_DIGEST_LENGTH);
    }

    #[test]
    fn hex_round_trip() {
        let d = TlshDigest::from_hex(VEC_HEX).unwrap();
        assert!(!d.is_null());
        assert_eq!(d.to_hex(), VEC_HEX);
        assert_eq!(d.0[35], 0);

        let lower = VEC_HEX[2..].to_ascii_lowercase();
        assert_eq!(TlshDigest::from_hex(&lower), Some(d));

        assert_eq!(TlshDigest::from_hex("TNULL"), Some(TlshDigest::NULL));
        assert!(TlshDigest::NULL.is_null());
        assert_eq!(TlshDigest::NULL.to_hex(), "TNULL");

        assert_eq!(TlshDigest::from_hex(""), None);
        assert_eq!(TlshDigest::from_hex(&VEC_HEX[..71]), None);
        assert_eq!(TlshDigest::from_hex("T1\0junk"), None);
    }

    #[test]
    fn diff_basics() {
        let a = TlshDigest::from_hex(VEC_HEX).unwrap();
        assert_eq!(a.diff(&a, true), 0);
        assert_eq!(a.diff(&TlshDigest::NULL, true), -1);

        let mut rng = SplitMix64::new(7);
        let b = random_digest(&mut rng);
        assert_eq!(a.diff(&b, true), b.diff(&a, true));
        assert!(a.diff(&b, false) <= a.diff(&b, true));
        assert!(a.diff(&b, true) > 0);
    }

    #[test]
    fn from_fields_round_trips() {
        let d = TlshDigest::from_hex(VEC_HEX).unwrap();
        let mut codes = [0u8; 128];
        for (i, c) in codes.iter_mut().enumerate() {
            *c = d.bucket(i);
        }
        assert_eq!(TlshDigest::from_fields(d.l(), d.q1(), d.q2(), d.checksum(), &codes), d);
    }

    #[test]
    fn hasher_matches_libhasher() {
        let mut rng = SplitMix64::new(1);
        let mut buf = vec![0u8; 4096];
        rng.fill_bytes(&mut buf);

        let d = tlsh_hash(&buf);
        assert_eq!(d.to_hex(), SPLITMIX_4096_HEX);

        // streaming gives the same answer
        let mut h = TlshHasher::new();
        h.update(&buf[..1000]);
        h.update(&buf[1000..1001]);
        h.update(&buf[1001..]);
        assert_eq!(h.digest(), d);

        // too short to hash
        assert!(tlsh_hash(&buf[..10]).is_null());
        assert!(tlsh_hash(&[]).is_null());
    }

    #[test]
    fn corpus_is_deterministic_and_non_null() {
        let a = make_corpus(3, 2000);
        assert_eq!(a.len(), 2000);
        assert_eq!(a, make_corpus(3, 2000));
        assert_ne!(a, make_corpus(4, 2000));
        assert!(a.iter().all(|d| !d.is_null()));
        for d in a.iter().take(100) {
            assert_eq!(TlshDigest::from_hex(&d.to_hex()), Some(*d));
        }

        let p = perturb_corpus(9, &a[..10], 500, 0.05);
        assert_eq!(p.len(), 500);
        assert_eq!(p, perturb_corpus(9, &a[..10], 500, 0.05));
        assert!(perturb_corpus(9, &[], 5, 0.05).is_empty());
    }

    #[test]
    fn knn_agrees_with_sort() {
        let corpus = make_corpus(5, 3000);
        let mut rng = SplitMix64::new(11);
        for _ in 0..10 {
            let pick = rng.below(3000) as usize;
            let q = perturb(&mut rng, &corpus[pick], 0.05);
            let fast = knn_brute(&corpus, &q, 10);
            assert_eq!(fast.len(), 10);
            assert_eq!(fast, knn_sorted(&corpus, &q, 10));
            assert!(fast.windows(2).all(|w| w[0] <= w[1]));
        }
        assert_eq!(knn_brute(&corpus[..3], &corpus[0], 10).len(), 3);
    }
}
