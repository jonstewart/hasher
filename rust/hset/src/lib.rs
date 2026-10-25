//! `hset`: the sorted hash-set file format of libhasher, in Rust.
//!
//! * [`mod@format`] decodes and encodes the chunked `.hset` container.
//! * [`lookup`] provides exact membership queries over the sorted hash arrays,
//!   accelerated by on-disk hint tables; the default hint fits a line per
//!   block of the key space using convex hulls (see [`lookup::hull`]).
//! * [`Hashset`] ties a decoded file to its lookup strategies.
//! * [`Builder`] creates files from records or text, and [`merge`] writes
//!   the union, intersection, or difference of two files by merging them
//!   ([`SetOp`], [`MergeOptions`]).
//!
//! ```
//! use hset::{Builder, BuildOptions, HashType, Hashset};
//!
//! let mut b = Builder::new(&[HashType::Sha1]).unwrap();
//! b.add_text_line("0053e9b602c2fa8473262b590f6d24a406ae1cc3").unwrap();
//! b.add_text_line("ff36a8ea9b657f9c068d91a67195dd0764fd75ff").unwrap();
//! let bytes = b.build(&BuildOptions::new("demo", "two hashes")).unwrap();
//!
//! let hs = Hashset::load(&bytes).unwrap();
//! let idx = hs.index_for_type(HashType::Sha1).unwrap();
//! let h = hset::hex::decode("ff36a8ea9b657f9c068d91a67195dd0764fd75ff").unwrap();
//! assert!(hs.contains(idx, &h));
//! assert!(!hs.contains(idx, &[0u8; 20]));
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod builder;
pub mod error;
pub mod format;
pub mod hash_type;
pub mod hashset;
pub mod hex;
pub mod key;
pub mod lookup;
pub mod merge;
pub mod synth;
pub mod tlsh;

pub use builder::{BuildOptions, Builder};
pub use error::{Error, Result};
pub use hash_type::HashType;
pub use hashset::{Hashset, VerifyReport};
pub use lookup::{BatchMode, BitsPolicy, HintSpec, Lookup, SearchConfig, SingleMode};
pub use merge::{MergeOptions, SetOp, TlshIndexPolicy};
