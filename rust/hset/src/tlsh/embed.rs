//! TLSH embeddings: the 256-dimension `i8` body embedding the BISECT build
//! clusters on, and the full 264-dimension `f32` lower-bound embedding
//! (`sfhash_tlsh_embed`, `sfhash_tlsh_embed_dist2`).
//!
//! Bucket `i` of the body occupies dims `2i, 2i+1`, its code mapped to a
//! corner of a staircase (`docs/TLSH_EMBEDDING.md` section 1):
//!
//! ```text
//! code 0 -> ( 1, 0)   1 -> (0, 0)   2 -> (0, 1)   3 -> (-1, 1)
//! ```
//!
//! C++: `include/tlsh_embedding.h`, `src/lib/tlsh_embedding.cpp`.

use super::digest::{BUCKETS, DIGEST_LENGTH, TlshDigest};

/// Dimensions of the body embedding (dims 0..256 of the full embedding).
pub const EMBED_BODY_DIMS: usize = 256;

/// Body embedding coordinates by code: `(x, y)` and the squared norm
/// `x^2 + y^2`.
const BODY_X: [i8; 4] = [1, 0, 0, -1];
const BODY_Y: [i8; 4] = [0, 0, 1, 1];
const BODY_NORM2: [u32; 4] = [1, 0, 1, 2];

/// Write the body embedding of `row` as integers, each coordinate in
/// {-1, 0, 1}, and return its squared norm (at most 256: 1 per bucket of
/// code 0 or 2, 2 per bucket of code 3). The norm is the squared
/// body-embedding distance to the all-code-1 body, the zero vector
/// (C++ `tlsh_embed_body_i8`).
pub fn embed_body_i8(row: &[u8; DIGEST_LENGTH], out: &mut [i8; EMBED_BODY_DIMS]) -> u32 {
    let d = TlshDigest(*row);
    let mut norm2 = 0;
    for i in 0..BUCKETS {
        let c = usize::from(d.bucket(i));
        out[2 * i] = BODY_X[c];
        out[2 * i + 1] = BODY_Y[c];
        norm2 += BODY_NORM2[c];
    }
    norm2
}
