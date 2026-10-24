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
//! | `FLTR` | optional filter (skipped) |
//! | `FEND` | end marker, no data |
//!
//! A pstring is a `u16 LE` length followed by UTF-8 bytes.

pub mod chunk;
pub mod decode;
pub mod encode;
pub mod structs;

pub use decode::decode;
pub use encode::{Document, HashsetIn, RecordsIn, encode};
pub use structs::*;
