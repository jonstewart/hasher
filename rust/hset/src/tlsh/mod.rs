//! TLSH digests in libhasher's canonical 36-byte form, their distance, and
//! the search structures built over TLSH hash sets.
//!
//! * [`digest`]: [`TlshDigest`], the canonical form, and its `T1` hex
//!   transport encoding.
//! * [`distance`]: the reference implementation's `totalDiff`, split into
//!   header and body costs, and the popcount body kernel [`BodyQuery`].
//! * [`cells`], [`order`], [`knn`]: the `0x7400` cell index, the header
//!   cost order, and brute-force and cell kNN ([`knn_brute`]).
//! * [`ivf`]: the `TIVF` index: its model ([`TlshIvf`], [`TivfView`],
//!   [`ValidIvf`]), indexed kNN ([`knn_ivf`]), the BISECT build
//!   ([`build_tlsh_ivf`]) and the merge ([`merge_tlsh_ivf`]).
//!
//! A loaded file searches its TLSH sections through
//! [`Hashset::tlsh_knn`](crate::Hashset::tlsh_knn) and its siblings, and
//! the builder writes the index ([`BuildOptions::tlsh_index`](crate::BuildOptions::tlsh_index)).
//!
//! # Differences from the C++ library
//!
//! * [`TlshDigest::from_hex`] is strict: the whole string must be the
//!   digest. `tlsh_from_hex` / `sfhash_tlsh_from_hex` stop after the 70th
//!   hex digit and accept any non-hex character after it (`"T1…70 hex… x"`
//!   or a trailing newline parse); Rust rejects them.
//! * [`TlshDigest::from_bytes`] rejects a non-zero reserved byte (offset
//!   35); C++ copies raw digests without looking at it.
//! * [`diff`] returns `None` where `sfhash_tlsh_diff` returns -1 (either
//!   digest null).

pub mod cells;
pub mod digest;
pub mod distance;
pub mod embed;
pub mod ivf;
pub mod knn;
pub mod mt64;
pub mod order;

pub use digest::{DIGEST_LENGTH, HEX_LENGTH, TlshDigest};
pub use distance::{
    BodyQuery, body_diff, diff, emb_body_dist2, header_diff, l_cost, mod_diff, q_cost,
};
pub use ivf::{
    IvfBuildOptions, IvfIndex, TivfView, TlshIvf, ValidIvf, build_tlsh_ivf, knn_ivf, list_bound,
    merge_tlsh_ivf,
};
pub use knn::{KnnStats, TlshMatch, TopK, knn_brute, knn_cells};
pub use order::HeaderOrder;

/// Number of cells: one per (L, Q) header, `cell = (L << 8) | Q`.
pub const CELL_COUNT: usize = 65536;

/// HINT type of the TLSH cell index (`hint_type u16 BE` in the HINT chunk).
pub const CELL_HINT_TAG: u16 = 0x7400;
