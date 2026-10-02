//! Error type shared by the whole crate.

use std::fmt;

/// Errors produced while decoding, encoding, or building hash sets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed or truncated on-disk data.
    #[error("format error: {0}")]
    Format(String),
    /// Invalid caller input (bad hex, unknown hash type, wrong column count, ...).
    #[error("invalid input: {0}")]
    Input(String),
    /// Wrapped I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn format(msg: impl fmt::Display) -> Self {
        Error::Format(msg.to_string())
    }

    pub(crate) fn input(msg: impl fmt::Display) -> Self {
        Error::Input(msg.to_string())
    }
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
