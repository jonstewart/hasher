//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation.

pub mod bisect;
pub mod merge;
pub mod search;
