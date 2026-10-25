//! The chunked `.hset` on-disk format.
//!
//! ```text
//! offset  0  magic "SetOHash"
//! offset  8  SHA-256 of everything from offset 40 to end of file
//! offset 40  FTOC chunk, then the chunks it lists, ending with FEND
//! ```
//!
//! Every chunk is `type: u32 BE`, `length: u64 LE`, `data[length]`. The
//! `FTOC` lists `(offset: u64 LE, type: u32 BE)` for every chunk including
//! itself. Chunk types:
//!
//! | tag    | contents |
//! |--------|----------|
//! | `FTOC` | table of contents |
//! | `FHDR` | `version u64`, then pstrings `name`, `timestamp`, `description` |
//! | `RHDR` | `record_length u64`, `record_count u64`, then per field: `log2(type) u16`, pstring `name`, `length u64` |
//! | `RDAT` | `record_count` fixed-width records; each field is a presence byte followed by its value |
//! | `HHnn` | one hash set header for type `1 << nn`: pstring `name`, `hash_length u64`, `hash_count u64` |
//! | `HINT` | lookup acceleration table: `hint_type u16 BE`, then type-specific data |
//! | `HDAT` | `hash_count` sorted fixed-width hashes |
//! | `RIDX` | `hash_count` record indices (`u64 LE`), parallel to `HDAT` |
//! | `TIVF` | TLSH sections only: the inverted-file kNN index (see [`crate::tlsh::ivf`]); exposed raw as [`Section::tivf`] |
//! | `FLTR` | optional filter (skipped) |
//! | `FEND` | end marker, no data |
//!
//! A pstring is a `u16 LE` length followed by UTF-8 bytes.
//!
//! A section is `HHnn [HINT] [FLTR] HDAT [RIDX] [TIVF]`; `HDAT` starts on
//! a 4096-byte boundary, the chunks after it follow unpadded. Hint types:
//! `0x62nn` flat block table and `0x68nn` hull table over the top `nn` bits
//! (`0x6208` is the C++ library's legacy table), and `0x7400` the TLSH cell
//! index ([`crate::tlsh::cells`]), `65537` `u64 LE` row offsets, one per
//! `(L << 8) | Q` cell plus the row count.
//!
//! TLSH (`HH\x00\x0f`, 36-byte rows) is held stricter than the C++ decoder
//! holds it: a `0x7400` hint must be a valid cell index and is accepted
//! only on a 36-byte TLSH section, `TIVF` only on a TLSH section, and a
//! `TVEC` chunk (TLSH embedding vectors, which older C++ builds wrote and
//! the format has dropped) is rejected by name.

pub mod chunk;
pub mod decode;
pub mod encode;
pub mod structs;

pub use decode::decode;
pub use encode::{Document, HashsetIn, RecordsIn, encode};
pub use structs::*;
