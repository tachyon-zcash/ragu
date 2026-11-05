#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<'a> {
    Unencodable,
    Length {
        expected: usize,
        actual: usize,
    },
    Truncated {
        offset: usize,
        requested: usize,
        bytes: &'a [u8],
    },
    Invalid {
        offset: usize,
        bytes: &'a [u8],
        reason: &'static str,
    },
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unencodable => f.write_str("the value has no encoding"),
            Self::Length { expected, actual } => write!(
                f,
                "incorrect encoded length: expected {expected} bytes, got {actual}"
            ),
            Self::Truncated {
                offset,
                requested,
                bytes,
            } => write!(
                f,
                "truncated input at byte {offset}: need {requested} bytes, have {}",
                bytes.len()
            ),
            Self::Invalid { offset, reason, .. } => {
                write!(f, "invalid encoding at byte {offset}: {reason}")
            }
        }
    }
}

impl core::error::Error for Error<'_> {}

pub(crate) const MAX_RANK: u32 = 32;
pub(crate) const MAX_HEADER_SIZE: usize = 1 << 12;

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error<'a>> {
        let bytes = self.input[self.offset..]
            .get(..length)
            .ok_or(Error::Truncated {
                offset: self.offset,
                requested: length,
                bytes: &self.input[self.offset..],
            })?;
        self.offset += length;
        Ok(bytes)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error<'a>> {
        Ok(self.take(N)?.try_into().expect("fixed-size chunk"))
    }
}
