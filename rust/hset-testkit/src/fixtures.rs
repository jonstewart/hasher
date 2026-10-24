//! Locating the C++ reference fixtures (the `test/*.hset` files at the
//! repository root) from a test binary.
//!
//! The default path is relative to this crate's own manifest directory
//! (`rust/hset-testkit`), not the calling crate's: `CARGO_MANIFEST_DIR` is
//! baked in at the testkit's compile time via `env!`, so it is always
//! `.../rust/hset-testkit`, and `../../test` from there lands on the same
//! `test/` directory as `../../test` does from `rust/hset` or
//! `rust/hset-cli` today, since all three sit one level under `rust/`.
//!
//! `cargo-mutants` copies only the Cargo workspace (`rust/`) into a tempdir
//! to build and test each mutant, so the fixtures (which live outside the
//! workspace, at the repository root) are not there. `HSET_FIXTURES_DIR` is
//! read at runtime (not baked in with `env!`) so the `mutants` and
//! `mutants-diff` recipes can point the copied tree back at the real
//! `test/` directory by its absolute path.
use std::env;
use std::path::PathBuf;

/// Directory holding the reference fixtures, honouring `HSET_FIXTURES_DIR`
/// when set to a non-empty value and falling back to `test/` two levels
/// above this crate otherwise. An empty `HSET_FIXTURES_DIR` (e.g. `VAR=`
/// with no value, as opposed to unset) is treated the same as unset, rather
/// than resolving to the current directory.
pub fn fixtures_dir() -> PathBuf {
    if let Some(dir) = env::var_os("HSET_FIXTURES_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test")
}
