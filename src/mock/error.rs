//! Mock error type.

use core::{error, fmt, result};

/// Alias for [`core::result::Result<T, Error>`].
pub type Result<T> = result::Result<T, Error>;

/// Mock error carrying a static description of which check failed.
#[derive(Clone, Copy, Debug)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl error::Error for Error {}
