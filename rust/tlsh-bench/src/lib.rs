//! Thin wrappers over libhasher's TLSH C API (`include/hasher/tlsh.h`,
//! `include/hasher/hasher.h`) and the hash set API (`include/hasher/hashset.h`:
//! loading, the TLSH kNN strategies, the embedding vectors and the builder),
//! plus deterministic synthetic corpora and a brute-force kNN used by the
//! Criterion benchmarks.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::fs;
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;
use std::slice;

/// `SFHASH_TLSH_DIGEST_LENGTH`
pub const TLSH_DIGEST_LENGTH: usize = 36;
/// `SFHASH_TLSH_HEX_LENGTH`: "T1" + 70 hex characters, without the NUL
pub const TLSH_HEX_LENGTH: usize = 72;
/// `SFHASH_TLSH` from `SFHASH_HashAlgorithm`
pub const SFHASH_TLSH: u32 = 1 << 15;
/// `SFHASH_TLSH_EMBEDDING_DIMS`
pub const TLSH_EMBEDDING_DIMS: usize = 264;

/// `SFHASH_TLSH_KNN_BRUTE`: scan every row.
pub const TLSH_KNN_BRUTE: u32 = 1;
/// `SFHASH_TLSH_KNN_INDEX`: prune with the TIVF index stored in the file.
pub const TLSH_KNN_INDEX: u32 = 2;

/// `SFHASH_HSET_TLSH_VECTORS`: write the TVEC embedding matrix.
pub const HSET_TLSH_VECTORS: u32 = 1;
/// `SFHASH_HSET_TLSH_INDEX`: write the TIVF kNN index.
pub const HSET_TLSH_INDEX: u32 = 2;

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

/// Opaque `SFHASH_Hashset`.
#[repr(C)]
pub struct RawHashset {
    _private: [u8; 0],
}

/// Opaque `SFHASH_HashsetBuildCtx`.
#[repr(C)]
pub struct RawBuildCtx {
    _private: [u8; 0],
}

/// `struct SFHASH_Error`.
#[repr(C)]
pub struct RawError {
    pub message: *mut c_char,
}

/// `struct SFHASH_TlshMatch`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TlshMatch {
    pub index: u64,
    pub distance: u32,
}

pub mod ffi {
    use super::*;

    extern "C" {
        pub fn sfhash_tlsh_from_hex(hex: *const c_char, digest: *mut c_void) -> bool;
        pub fn sfhash_tlsh_to_hex(digest: *const c_void, hex: *mut c_char);
        pub fn sfhash_tlsh_is_null(digest: *const c_void) -> bool;
        pub fn sfhash_tlsh_diff(a: *const c_void, b: *const c_void, include_length: bool) -> c_int;

        pub fn sfhash_tlsh_embed(digest: *const c_void, out: *mut f32);

        pub fn sfhash_create_hasher(hash_algs: u32) -> *mut RawHasher;
        pub fn sfhash_update_hasher(hasher: *mut RawHasher, beg: *const c_void, end: *const c_void);
        pub fn sfhash_get_hashes(hasher: *mut RawHasher, out_hashes: *mut HashValues);
        pub fn sfhash_reset_hasher(hasher: *mut RawHasher);
        pub fn sfhash_destroy_hasher(hasher: *mut RawHasher);

        pub fn sfhash_free_error(err: *mut RawError);

        pub fn sfhash_load_hashset(beg: *const c_void, end: *const c_void, err: *mut *mut RawError) -> *mut RawHashset;
        pub fn sfhash_destroy_hashset(hset: *mut RawHashset);
        pub fn sfhash_hashset_index_for_type(hset: *const RawHashset, htype: u32) -> c_int;
        pub fn sfhash_hashset_count(hset: *const RawHashset, tidx: usize) -> u64;
        pub fn sfhash_hashset_hash(hset: *const RawHashset, tidx: usize, idx: usize) -> *const c_void;
        pub fn sfhash_hashset_tlsh_knn(
            hset: *const RawHashset,
            tidx: usize,
            digest: *const c_void,
            k: usize,
            max_distance: u32,
            include_length: bool,
            out: *mut TlshMatch,
        ) -> usize;
        pub fn sfhash_hashset_tlsh_knn_with(
            hset: *const RawHashset,
            tidx: usize,
            digest: *const c_void,
            k: usize,
            max_distance: u32,
            include_length: bool,
            strategy: u32,
            out: *mut TlshMatch,
        ) -> usize;
        pub fn sfhash_hashset_tlsh_knn_strategies(hset: *const RawHashset, tidx: usize) -> u32;
        pub fn sfhash_hashset_tlsh_vectors(hset: *const RawHashset, tidx: usize, dims: *mut usize) -> *const f32;

        pub fn sfhash_hashset_builder_open(
            hashset_name: *const c_char,
            hashset_desc: *const c_char,
            record_order: *const u32,
            record_order_length: usize,
            write_records: bool,
            write_hashsets: bool,
            output_file: *const c_char,
            temp_dir: *const c_char,
            err: *mut *mut RawError,
        ) -> *mut RawBuildCtx;
        pub fn sfhash_hashset_builder_set_tlsh_options(bctx: *mut RawBuildCtx, options: u32);
        pub fn sfhash_hashset_builder_add_hash(bctx: *mut RawBuildCtx, hash: *const c_void, length: usize);
        pub fn sfhash_hashset_builder_write(bctx: *mut RawBuildCtx, err: *mut *mut RawError) -> u64;
        pub fn sfhash_hashset_builder_destroy(bctx: *mut RawBuildCtx);
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

    /// `sfhash_tlsh_embed`: the lower-bound Euclidean embedding.
    pub fn embed(&self) -> [f32; TLSH_EMBEDDING_DIMS] {
        let mut out = [0f32; TLSH_EMBEDDING_DIMS];
        unsafe { ffi::sfhash_tlsh_embed(self.0.as_ptr().cast(), out.as_mut_ptr()) };
        out
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

    /// Forgets everything fed so far.
    pub fn reset(&mut self) {
        unsafe { ffi::sfhash_reset_hasher(self.raw) }
    }

    /// Resets, hashes `data`, and returns its digest.
    pub fn hash(&mut self, data: &[u8]) -> TlshDigest {
        self.reset();
        self.update(data);
        self.digest()
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

/// An error reported by libhasher through `SFHASH_Error`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashsetError(pub String);

impl fmt::Display for HashsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HashsetError {}

impl From<std::io::Error> for HashsetError {
    fn from(e: std::io::Error) -> Self {
        HashsetError(e.to_string())
    }
}

/// Converts and frees a `SFHASH_Error*` set by a C call (null means no error).
fn take_error(err: *mut RawError, fallback: &str) -> HashsetError {
    if err.is_null() {
        return HashsetError(fallback.to_owned());
    }
    let msg = unsafe {
        let m = (*err).message;
        let s = if m.is_null() {
            fallback.to_owned()
        } else {
            CStr::from_ptr(m).to_string_lossy().into_owned()
        };
        ffi::sfhash_free_error(err);
        s
    };
    HashsetError(msg)
}

fn c_string(s: &str, what: &str) -> Result<CString, HashsetError> {
    CString::new(s).map_err(|_| HashsetError(format!("{what} contains a NUL byte")))
}

fn path_c_string(p: &Path, what: &str) -> Result<CString, HashsetError> {
    let s = p
        .to_str()
        .ok_or_else(|| HashsetError(format!("{what} is not valid UTF-8")))?;
    c_string(s, what)
}

/// A loaded hash set (`SFHASH_Hashset`). Owns the file bytes, which libhasher
/// reads in place, for as long as the handle lives.
pub struct Hashset {
    raw: *mut RawHashset,
    // 8-byte aligned so that the float32 TVEC matrix (page aligned in the
    // file) stays at least 8-byte aligned in memory; `len` is the byte count.
    _bytes: Vec<u64>,
    len: usize,
}

// The handle is only read after construction; the file bytes are immutable.
unsafe impl Send for Hashset {}
unsafe impl Sync for Hashset {}

impl Hashset {
    /// Reads an hset file and loads it.
    pub fn open(path: impl AsRef<Path>) -> Result<Hashset, HashsetError> {
        let data = fs::read(path.as_ref())?;
        Hashset::from_bytes(&data)
    }

    /// Loads an hset from its bytes (copied into an aligned buffer).
    pub fn from_bytes(data: &[u8]) -> Result<Hashset, HashsetError> {
        let len = data.len();
        let mut words = vec![0u64; len.div_ceil(8)];
        let bytes: &mut [u8] =
            unsafe { slice::from_raw_parts_mut(words.as_mut_ptr().cast(), words.len() * 8) };
        bytes[..len].copy_from_slice(data);

        let beg = words.as_ptr().cast::<u8>();
        let mut err: *mut RawError = ptr::null_mut();
        let raw = unsafe { ffi::sfhash_load_hashset(beg.cast(), beg.add(len).cast(), &mut err) };
        if raw.is_null() {
            return Err(take_error(err, "sfhash_load_hashset failed"));
        }
        debug_assert!(err.is_null());
        Ok(Hashset { raw, _bytes: words, len })
    }

    /// The size of the hset file in bytes.
    pub fn file_len(&self) -> usize {
        self.len
    }

    /// `sfhash_hashset_index_for_type`: the hash set index for a hash type.
    pub fn index_for_type(&self, htype: u32) -> Option<usize> {
        let i = unsafe { ffi::sfhash_hashset_index_for_type(self.raw, htype) };
        usize::try_from(i).ok()
    }

    /// The index of the TLSH hash set, if there is one.
    pub fn tlsh_index(&self) -> Option<usize> {
        self.index_for_type(SFHASH_TLSH)
    }

    /// `sfhash_hashset_count`: rows in hash set `tidx`.
    pub fn count(&self, tidx: usize) -> u64 {
        unsafe { ffi::sfhash_hashset_count(self.raw, tidx) }
    }

    /// `sfhash_hashset_hash`: the idx-th (bytewise sorted) TLSH row.
    pub fn hash(&self, tidx: usize, idx: usize) -> TlshDigest {
        assert!((idx as u64) < self.count(tidx), "row {idx} out of range");
        let p = unsafe { ffi::sfhash_hashset_hash(self.raw, tidx, idx) };
        assert!(!p.is_null());
        let mut d = TlshDigest::NULL;
        unsafe { ptr::copy_nonoverlapping(p.cast::<u8>(), d.0.as_mut_ptr(), TLSH_DIGEST_LENGTH) };
        d
    }

    /// All TLSH rows of hash set `tidx`, in file order.
    pub fn tlsh_rows(&self, tidx: usize) -> Vec<TlshDigest> {
        let n = self.count(tidx) as usize;
        (0..n).map(|i| self.hash(tidx, i)).collect()
    }

    /// `sfhash_hashset_tlsh_knn_strategies`: OR of `TLSH_KNN_*`.
    pub fn tlsh_knn_strategies(&self, tidx: usize) -> u32 {
        unsafe { ffi::sfhash_hashset_tlsh_knn_strategies(self.raw, tidx) }
    }

    /// k nearest neighbours within `max_distance`, written to `out` (resized
    /// to the number found), nearest first, ties by ascending index.
    /// `strategy` is `TLSH_KNN_BRUTE`, `TLSH_KNN_INDEX`, or `None` for
    /// `sfhash_hashset_tlsh_knn` (the index when the file has one).
    #[allow(clippy::too_many_arguments)]
    pub fn tlsh_knn_into(
        &self,
        tidx: usize,
        digest: &TlshDigest,
        k: usize,
        max_distance: u32,
        include_length: bool,
        strategy: Option<u32>,
        out: &mut Vec<TlshMatch>,
    ) -> usize {
        out.clear();
        out.resize(k, TlshMatch::default());
        let n = unsafe {
            match strategy {
                None => ffi::sfhash_hashset_tlsh_knn(
                    self.raw,
                    tidx,
                    digest.0.as_ptr().cast(),
                    k,
                    max_distance,
                    include_length,
                    out.as_mut_ptr(),
                ),
                Some(s) => ffi::sfhash_hashset_tlsh_knn_with(
                    self.raw,
                    tidx,
                    digest.0.as_ptr().cast(),
                    k,
                    max_distance,
                    include_length,
                    s,
                    out.as_mut_ptr(),
                ),
            }
        };
        assert!(n <= k, "kNN wrote {n} matches for k={k}");
        out.truncate(n);
        n
    }

    /// `tlsh_knn_into` as `(index, distance)` pairs.
    pub fn tlsh_knn(
        &self,
        tidx: usize,
        digest: &TlshDigest,
        k: usize,
        max_distance: u32,
        include_length: bool,
        strategy: Option<u32>,
    ) -> Vec<(u64, u32)> {
        let mut out = Vec::with_capacity(k);
        self.tlsh_knn_into(tidx, digest, k, max_distance, include_length, strategy, &mut out);
        out.iter().map(|m| (m.index, m.distance)).collect()
    }

    /// `sfhash_hashset_tlsh_vectors`: the n x 264 row-major float32
    /// embedding matrix, or `None` when the file has no TVEC section.
    pub fn tlsh_vectors(&self, tidx: usize) -> Option<&[f32]> {
        let mut dims = 0usize;
        let p = unsafe { ffi::sfhash_hashset_tlsh_vectors(self.raw, tidx, &mut dims) };
        if p.is_null() {
            return None;
        }
        assert_eq!(dims, TLSH_EMBEDDING_DIMS);
        let n = self.count(tidx) as usize;
        Some(unsafe { slice::from_raw_parts(p, n * dims) })
    }
}

impl Drop for Hashset {
    fn drop(&mut self) {
        unsafe { ffi::sfhash_destroy_hashset(self.raw) }
    }
}

/// Writes a TLSH-only hset (record order `[SFHASH_TLSH]`, hash sets only, no
/// records) of `digests` to `path` through the builder API, with the
/// optional sections selected by `options` (OR of `HSET_TLSH_*`). Null
/// digests are skipped; rows are sorted and deduplicated by the writer. The
/// builder's temporary files go in the output file's directory. Returns the
/// size of the file written.
pub fn build_tlsh_hset(
    path: impl AsRef<Path>,
    digests: &[TlshDigest],
    options: u32,
) -> Result<u64, HashsetError> {
    let path = path.as_ref();
    let temp_dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => Path::new(".").to_path_buf(),
    };

    let name = c_string("tlsh-bench", "name")?;
    let desc = c_string("synthetic TLSH corpus", "description")?;
    let out_c = path_c_string(path, "output path")?;
    let tmp_c = path_c_string(&temp_dir, "temp dir")?;
    let order = [SFHASH_TLSH];

    let mut err: *mut RawError = ptr::null_mut();
    let bctx = unsafe {
        ffi::sfhash_hashset_builder_open(
            name.as_ptr(),
            desc.as_ptr(),
            order.as_ptr(),
            order.len(),
            false,
            true,
            out_c.as_ptr(),
            tmp_c.as_ptr(),
            &mut err,
        )
    };
    if bctx.is_null() {
        return Err(take_error(err, "sfhash_hashset_builder_open failed"));
    }

    struct Guard(*mut RawBuildCtx);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { ffi::sfhash_hashset_builder_destroy(self.0) }
        }
    }
    let guard = Guard(bctx);

    unsafe {
        ffi::sfhash_hashset_builder_set_tlsh_options(bctx, options);
        for d in digests {
            if !d.is_null() {
                ffi::sfhash_hashset_builder_add_hash(bctx, d.0.as_ptr().cast(), TLSH_DIGEST_LENGTH);
            }
        }
    }

    let mut err: *mut RawError = ptr::null_mut();
    let written = unsafe { ffi::sfhash_hashset_builder_write(bctx, &mut err) };
    drop(guard);
    if !err.is_null() {
        return Err(take_error(err, "sfhash_hashset_builder_write failed"));
    }
    Ok(written)
}

/// Brute-force kNN with the hash set API's contract: rows with
/// `diff <= max_distance`, nearest first, ties by ascending index, at most
/// k, as `(index, distance)`. Null rows (diff -1) never match.
pub fn knn_brute_with(
    corpus: &[TlshDigest],
    query: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
) -> Vec<(u64, u32)> {
    if k == 0 {
        return Vec::new();
    }
    let mut heap: BinaryHeap<(u32, u64)> = BinaryHeap::with_capacity(k + 1);
    for (i, d) in corpus.iter().enumerate() {
        let dist = query.diff(d, include_length);
        if dist < 0 || dist as u32 > max_distance {
            continue;
        }
        let dist = dist as u32;
        if heap.len() < k {
            heap.push((dist, i as u64));
        } else if dist < heap.peek().map(|t| t.0).unwrap_or(u32::MAX) {
            heap.pop();
            heap.push((dist, i as u64));
        }
    }
    heap.into_sorted_vec().into_iter().map(|(d, i)| (i, d)).collect()
}

/******************************************************************************
 Family corpus: hashed content, like test/tlsh_corpus.cpp
******************************************************************************/

/// A base digest and the digests of mutated copies of the same content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlshFamily {
    pub base: TlshDigest,
    pub variants: Vec<TlshDigest>,
}

impl SplitMix64 {
    /// log-uniform in [lo, hi], like file sizes
    pub fn log_uniform(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        let l = (lo as f64).ln();
        let h = (hi as f64).ln();
        let v = (l + self.unit() * (h - l)).exp() as usize;
        v.clamp(lo, hi)
    }
}

#[derive(Clone, Debug)]
enum Alphabet {
    /// uniform bytes
    Full,
    /// 4-24 distinct byte values
    Small(Vec<u8>),
    /// words of skewed lowercase letters, whitespace, punctuation
    Text,
    /// run-length structured binary
    Runs,
}

// letters weighted roughly by English frequency
const TEXT_LETTERS: &[u8] =
    b"eeeeeeettttttaaaaaaooooooiiiiiinnnnnnsssssshhhhhhrrrrrrdddduuullllccmmwwffggyyppbbvkjxqz";

fn pick_alphabet(rng: &mut SplitMix64) -> Alphabet {
    match rng.below(4) {
        0 => Alphabet::Full,
        1 => {
            let n = rng.between(4, 24) as usize;
            let mut symbols: Vec<u8> = Vec::with_capacity(n);
            while symbols.len() < n {
                let b = rng.below(256) as u8;
                if !symbols.contains(&b) {
                    symbols.push(b);
                }
            }
            Alphabet::Small(symbols)
        }
        2 => Alphabet::Text,
        _ => Alphabet::Runs,
    }
}

fn random_symbol(rng: &mut SplitMix64, a: &Alphabet) -> u8 {
    match a {
        Alphabet::Small(s) => s[rng.below(s.len() as u64) as usize],
        Alphabet::Text => TEXT_LETTERS[rng.below(TEXT_LETTERS.len() as u64) as usize],
        _ => rng.below(256) as u8,
    }
}

fn make_content(rng: &mut SplitMix64, a: &Alphabet, len: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(len + 64);
    match a {
        Alphabet::Full => {
            while v.len() < len {
                v.extend_from_slice(&rng.next_u64().to_le_bytes());
            }
        }
        Alphabet::Small(_) => {
            while v.len() < len {
                v.push(random_symbol(rng, a));
            }
        }
        Alphabet::Text => {
            while v.len() < len {
                let wlen = rng.between(1, 11);
                for _ in 0..wlen {
                    v.push(random_symbol(rng, a));
                }
                match rng.below(16) {
                    0 => v.extend_from_slice(b".\n"),
                    1 => v.extend_from_slice(b", "),
                    _ => v.push(b' '),
                }
            }
        }
        Alphabet::Runs => {
            while v.len() < len {
                let rlen = rng.between(1, 16) as usize;
                let b = rng.below(256) as u8;
                v.extend(std::iter::repeat_n(b, rlen));
            }
        }
    }
    v.truncate(len);
    v
}

/// Byte flips over 0.5-5% of the content, a few small insertions and
/// deletions, and sometimes a duplicated or moved block.
fn mutate(rng: &mut SplitMix64, base: &[u8], a: &Alphabet) -> Vec<u8> {
    let mut v = base.to_vec();

    let rate = 0.005 + rng.unit() * 0.045;
    let flips = ((rate * v.len() as f64) as usize).max(1);
    for _ in 0..flips {
        let i = rng.below(v.len() as u64) as usize;
        v[i] = random_symbol(rng, a);
    }

    let edits = rng.below(5);
    for _ in 0..edits {
        let pos = rng.below(v.len() as u64 + 1) as usize;
        let n = rng.between(1, 64) as usize;
        if rng.chance(0.5) {
            let ins: Vec<u8> = (0..n).map(|_| random_symbol(rng, a)).collect();
            v.splice(pos..pos, ins);
        } else if pos + n <= v.len() && v.len() - n >= 64 {
            v.drain(pos..pos + n);
        }
    }

    if v.len() >= 16 && rng.chance(0.3) {
        let n = rng.between(1, (v.len() / 8).max(1) as u64) as usize;
        let src = rng.below((v.len() - n + 1) as u64) as usize;
        let block: Vec<u8> = v[src..src + n].to_vec();
        if rng.chance(0.5) {
            v.drain(src..src + n); // move rather than copy
        }
        let dst = rng.below(v.len() as u64 + 1) as usize;
        v.splice(dst..dst, block);
    }

    v
}

/// For each family: random base content of a log-uniform length in
/// `[min_len, max_len]` over a per-family alphabet (full 256, a small
/// alphabet, text-like words, run-length binary), then `variants_per_family`
/// mutated copies, all hashed with libhasher's TLSH hasher. Null digests are
/// skipped and families with a null base dropped. Deterministic per seed.
pub fn make_families(
    seed: u64,
    families: usize,
    variants_per_family: usize,
    min_len: usize,
    max_len: usize,
) -> Vec<TlshFamily> {
    let mut rng = SplitMix64::new(seed);
    let mut hasher = TlshHasher::new();
    let mut out = Vec::with_capacity(families);

    for _ in 0..families {
        let a = pick_alphabet(&mut rng);
        let len = rng.log_uniform(min_len, max_len);
        let base = make_content(&mut rng, &a, len);

        let base_digest = hasher.hash(&base);
        if base_digest.is_null() {
            continue;
        }

        let mut variants = Vec::with_capacity(variants_per_family);
        for _ in 0..variants_per_family {
            let d = hasher.hash(&mutate(&mut rng, &base, &a));
            if !d.is_null() {
                variants.push(d);
            }
        }
        out.push(TlshFamily { base: base_digest, variants });
    }
    out
}

/// `make_families` with the C++ defaults (1 KiB - 64 KiB), flattened: base
/// then variants, family by family.
pub fn make_family_corpus(seed: u64, families: usize, variants_per_family: usize) -> Vec<TlshDigest> {
    let mut out = Vec::with_capacity(families * (variants_per_family + 1));
    for fam in make_families(seed, families, variants_per_family, 1024, 65536) {
        out.push(fam.base);
        out.extend(fam.variants);
    }
    out
}

/// The counterpart of `make_tlsh_corpus` in `test/tlsh_corpus.cpp`: a family
/// corpus of ~min(n, 20000) hashed digests (families of 10), perturbed in
/// digest space up to exactly `n` digests.
pub fn make_hashed_corpus(seed: u64, n: usize) -> Vec<TlshDigest> {
    const VARIANTS_PER_FAMILY: usize = 9;
    const MAX_HASHED: usize = 20_000;

    let hashed = n.min(MAX_HASHED);
    let families = hashed.div_ceil(VARIANTS_PER_FAMILY + 1);

    let mut corpus = make_family_corpus(seed, families, VARIANTS_PER_FAMILY);
    if corpus.len() > n {
        corpus.truncate(n);
    } else if corpus.len() < n {
        let extra = perturb_corpus(seed ^ 0x9E37_79B9_7F4A_7C15, &corpus, n - corpus.len(), 0.05);
        corpus.extend(extra);
    }
    corpus
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

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!("tlsh-bench-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn unique_sorted(v: &[TlshDigest]) -> Vec<TlshDigest> {
        let mut u: Vec<TlshDigest> = v.iter().copied().filter(|d| !d.is_null()).collect();
        u.sort_unstable();
        u.dedup();
        u
    }

    #[test]
    fn hset_build_load_knn_vectors() {
        let corpus = make_corpus(21, 2000);
        let expected = unique_sorted(&corpus);

        let dir = TempDir::new("test");
        let path = dir.0.join("corpus.hset");
        let written = build_tlsh_hset(&path, &corpus, HSET_TLSH_VECTORS | HSET_TLSH_INDEX).unwrap();
        assert_eq!(written, fs::metadata(&path).unwrap().len());

        let hset = Hashset::open(&path).unwrap();
        assert_eq!(hset.file_len() as u64, written);
        let tidx = hset.tlsh_index().expect("TLSH hash set");
        assert_eq!(hset.index_for_type(1), None); // no MD5

        // count and sorted, deduplicated rows
        assert_eq!(hset.count(tidx), expected.len() as u64);
        let rows = hset.tlsh_rows(tidx);
        assert_eq!(rows, expected);
        assert!(rows.windows(2).all(|w| w[0] < w[1]));

        // both strategies are available and agree with a pure-Rust brute force
        assert_eq!(hset.tlsh_knn_strategies(tidx), TLSH_KNN_BRUTE | TLSH_KNN_INDEX);
        let mut rng = SplitMix64::new(22);
        for _ in 0..20 {
            let pick = &corpus[rng.below(corpus.len() as u64) as usize];
            let q = perturb(&mut rng, pick, 0.05);
            for k in [1usize, 10] {
                for maxd in [30u32, 144, 1000] {
                    for incl in [true, false] {
                        let want = knn_brute_with(&rows, &q, k, maxd, incl);
                        let brute = hset.tlsh_knn(tidx, &q, k, maxd, incl, Some(TLSH_KNN_BRUTE));
                        let index = hset.tlsh_knn(tidx, &q, k, maxd, incl, Some(TLSH_KNN_INDEX));
                        let dflt = hset.tlsh_knn(tidx, &q, k, maxd, incl, None);
                        assert_eq!(brute, want, "brute k={k} maxd={maxd} incl={incl}");
                        assert_eq!(index, want, "index k={k} maxd={maxd} incl={incl}");
                        assert_eq!(dflt, want, "default k={k} maxd={maxd} incl={incl}");
                        assert!(want.len() <= k);
                        assert!(want.iter().all(|&(_, d)| d <= maxd));
                    }
                }
            }
        }

        // an exact row is its own nearest neighbour at distance 0
        let hits = hset.tlsh_knn(tidx, &rows[17], 1, 0, true, None);
        assert_eq!(hits, vec![(17, 0)]);
        assert!(hset.tlsh_knn(tidx, &TlshDigest::NULL, 10, 1000, true, None).is_empty());
        assert!(hset.tlsh_knn(tidx, &rows[0], 10, 1000, true, Some(TLSH_KNN_BRUTE | TLSH_KNN_INDEX)).is_empty());

        // vectors: n x 264, row r is the embedding of row r
        let vec = hset.tlsh_vectors(tidx).expect("TVEC section");
        assert_eq!(vec.len(), rows.len() * TLSH_EMBEDDING_DIMS);
        assert_eq!(&vec[..TLSH_EMBEDDING_DIMS], &rows[0].embed()[..]);
        let last = rows.len() - 1;
        assert_eq!(&vec[last * TLSH_EMBEDDING_DIMS..], &rows[last].embed()[..]);
    }

    #[test]
    fn hset_without_optional_sections() {
        let corpus = make_corpus(23, 500);
        let dir = TempDir::new("plain");
        let path = dir.0.join("plain.hset");
        build_tlsh_hset(&path, &corpus, 0).unwrap();

        let hset = Hashset::open(&path).unwrap();
        let tidx = hset.tlsh_index().unwrap();
        assert_eq!(hset.count(tidx), unique_sorted(&corpus).len() as u64);
        assert_eq!(hset.tlsh_knn_strategies(tidx), TLSH_KNN_BRUTE);
        assert!(hset.tlsh_vectors(tidx).is_none());

        let rows = hset.tlsh_rows(tidx);
        let q = perturb(&mut SplitMix64::new(1), &corpus[3], 0.05);
        let want = knn_brute_with(&rows, &q, 10, 144, true);
        assert_eq!(hset.tlsh_knn(tidx, &q, 10, 144, true, None), want);
        assert_eq!(hset.tlsh_knn(tidx, &q, 10, 144, true, Some(TLSH_KNN_BRUTE)), want);
        // the index is not available
        assert!(hset.tlsh_knn(tidx, &q, 10, 144, true, Some(TLSH_KNN_INDEX)).is_empty());
    }

    #[test]
    fn hset_errors() {
        assert!(Hashset::from_bytes(b"not an hset file at all").is_err());
        assert!(Hashset::open("/nonexistent/dir/x.hset").is_err());
        let r = build_tlsh_hset("/nonexistent/dir/x.hset", &make_corpus(1, 10), 0);
        assert!(r.is_err());
    }

    #[test]
    fn families_are_deterministic_and_clustered() {
        let fams = make_families(31, 8, 4, 1024, 8192);
        assert_eq!(fams, make_families(31, 8, 4, 1024, 8192));
        assert_ne!(fams, make_families(32, 8, 4, 1024, 8192));
        assert!(!fams.is_empty());

        let mut within = Vec::new();
        let mut between = Vec::new();
        for (i, f) in fams.iter().enumerate() {
            assert!(!f.base.is_null());
            assert!(f.variants.iter().all(|v| !v.is_null()));
            for v in &f.variants {
                within.push(f.base.diff(v, true));
            }
            for g in fams.iter().skip(i + 1) {
                between.push(f.base.diff(&g.base, true));
            }
        }
        // variants of one content are far closer than unrelated content
        let mean = |v: &[i32]| v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64;
        assert!(!within.is_empty() && !between.is_empty());
        assert!(mean(&within) < mean(&between) / 2.0, "within {within:?} between {between:?}");

        let flat = make_family_corpus(31, 3, 2);
        assert!(flat.len() <= 9 && flat.len() >= 3);

        let c = make_hashed_corpus(33, 250);
        assert_eq!(c.len(), 250);
        assert_eq!(c, make_hashed_corpus(33, 250));
        assert!(c.iter().all(|d| !d.is_null()));
        let small = make_hashed_corpus(33, 25);
        assert_eq!(small.len(), 25);
    }

    #[test]
    fn knn_brute_with_contract() {
        let corpus = make_corpus(41, 1000);
        let q = perturb(&mut SplitMix64::new(42), &corpus[5], 0.05);

        let all = knn_brute_with(&corpus, &q, 1000, u32::MAX, true);
        let mut by_sort: Vec<(u32, u64)> = corpus
            .iter()
            .enumerate()
            .map(|(i, d)| (q.diff(d, true) as u32, i as u64))
            .collect();
        by_sort.sort_unstable();
        assert_eq!(all, by_sort.into_iter().map(|(d, i)| (i, d)).collect::<Vec<_>>());

        let top = knn_brute_with(&corpus, &q, 10, u32::MAX, true);
        assert_eq!(top, all[..10].to_vec());
        let near = knn_brute_with(&corpus, &q, 1000, 50, true);
        assert!(near.iter().all(|&(_, d)| d <= 50));
        assert_eq!(near.len(), all.iter().filter(|&&(_, d)| d <= 50).count());
        assert!(knn_brute_with(&corpus, &q, 0, 1000, true).is_empty());
        assert!(knn_brute_with(&[TlshDigest::NULL], &q, 5, 1000, true).is_empty());

        // the old (unfiltered, include_length) kNN agrees
        let legacy: Vec<(u64, u32)> = knn_brute(&corpus, &q, 10).into_iter().map(|(d, i)| (i as u64, d as u32)).collect();
        assert_eq!(legacy, top);
    }
}
