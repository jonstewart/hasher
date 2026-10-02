//! Shared test support for the `hset` workspace: a model of an input
//! document and oracles computed independently of `hset`'s builder. Used
//! only from `tests/` directories and the fuzz crate.

pub mod arb;
pub mod checks;
pub mod doc;
pub mod oracle;
pub mod strategies;
