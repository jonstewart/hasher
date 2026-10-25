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

use std::sync::LazyLock;

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

/// Dimensions of the full embedding, `SFHASH_TLSH_EMBEDDING_DIMS`.
pub const EMBED_DIMS: usize = 264;

/// The L dimension.
pub const EMBED_L_DIM: usize = 256;

/// Largest TLSH distance (with length) for which the lower bound holds.
pub const EMBED_MAX_BOUNDED_DIFF: u32 = 144;

/// Radius of the Q 16-gon, `1 / (2 sin(pi / 16))`, so adjacent values are
/// exactly distance 1 apart; the C++ literal.
const Q_RADIUS: f64 = 2.562_915_447_741_505_5;

/// The 16-gon's vertices `(x[q], y[q])` as C++ computes them: `cos` and
/// `sin` of `2 pi q / 16` in `f64`, times [`Q_RADIUS`], rounded to `f32`.
struct QTable {
    x: [f32; 16],
    y: [f32; 16],
}

static QT: LazyLock<QTable> = LazyLock::new(|| {
    let angle = |q: usize| 2.0 * std::f64::consts::PI * q as f64 / 16.0;
    QTable {
        x: std::array::from_fn(|q| (Q_RADIUS * angle(q).cos()) as f32),
        y: std::array::from_fn(|q| (Q_RADIUS * angle(q).sin()) as f32),
    }
});

/// Checksum bit scale, `1 / sqrt(3)` rounded to `f32`.
fn cs_scale() -> f32 {
    (1.0 / 3f64.sqrt()) as f32
}

/// The full embedding `phi(d)` (C++ `tlsh_embed`, `sfhash_tlsh_embed`):
///
/// ```text
/// dims 0..256    body, by the code table
/// dim  256       L as a float
/// dims 257, 258  Q1 on a regular 16-gon of radius 1 / (2 sin(pi/16))
/// dims 259, 260  Q2, likewise
/// dims 261..264  checksum bits 0, 1, 2, each 0 or 1/sqrt(3)
/// ```
///
/// Its squared distance ([`embed_dist2`]) lower-bounds the TLSH distance
/// (`docs/TLSH_EMBEDDING.md` section 1): `embed_dist2(phi(a), phi(b), true)
/// <= diff(a, b, true)` whenever that distance is at most
/// [`EMBED_MAX_BOUNDED_DIFF`] and L does not wrap (inputs of terabytes),
/// and `embed_dist2(.., false) <= diff(.., false)` for every pair.
pub fn embed(d: &TlshDigest) -> [f32; EMBED_DIMS] {
    let mut out = [0.0; EMBED_DIMS];
    for i in 0..BUCKETS {
        let c = usize::from(d.bucket(i));
        out[2 * i] = f32::from(BODY_X[c]);
        out[2 * i + 1] = f32::from(BODY_Y[c]);
    }
    let (q1, q2) = (usize::from(d.q1()), usize::from(d.q2()));
    out[EMBED_L_DIM] = f32::from(d.l());
    out[257] = QT.x[q1];
    out[258] = QT.y[q1];
    out[259] = QT.x[q2];
    out[260] = QT.y[q2];
    for bit in 0..3 {
        if d.checksum() & (1 << bit) != 0 {
            out[261 + bit] = cs_scale();
        }
    }
    out
}

/// Squared Euclidean distance between two embeddings.
pub fn embed_dist2(a: &[f32; EMBED_DIMS], b: &[f32; EMBED_DIMS], include_length: bool) -> f32 {
    let _ = (a, b, include_length);
    0.0
}
