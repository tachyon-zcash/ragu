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
pub(crate) const ENVELOPE_SIZE: usize = 28;
const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 3;
const PROOF_SCHEMA_VERSION: u16 = 2;
const COMPRESSED_SCHEMA_VERSION: u16 = 2;
const PCD_SCHEMA_VERSION: u16 = 2;
const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy)]
pub(crate) enum PayloadKind {
    Proof = 1,
    Compressed = 2,
    Pcd = 4,
}

pub(crate) fn write_envelope(
    kind: PayloadKind,
    rank: u32,
    header_size: usize,
    bytes: &mut Vec<u8>,
) {
    bytes.extend_from_slice(MAGIC);
    let schema = match kind {
        PayloadKind::Proof => PROOF_SCHEMA_VERSION,
        PayloadKind::Compressed => COMPRESSED_SCHEMA_VERSION,
        PayloadKind::Pcd => PCD_SCHEMA_VERSION,
    };
    for word in [ENVELOPE_VERSION, kind as u16, schema, PROTOCOL_VERSION] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&rank.to_le_bytes());
    bytes.extend_from_slice(&(header_size as u64).to_le_bytes());
}

use alloc::vec::Vec;

mod pcd;
pub use pcd::WireHeader;

#[cfg(feature = "serde")]
mod serde;

pub(crate) fn open(
    bytes: &[u8],
    kind: PayloadKind,
    expected_rank: Option<u32>,
) -> Result<(Reader<'_>, u32, usize), Error<'_>> {
    let mut reader = Reader::new(bytes);
    let envelope = reader.take(ENVELOPE_SIZE)?;
    let mut known = Vec::with_capacity(ENVELOPE_SIZE);
    write_envelope(kind, 0, 0, &mut known);
    for (start, end, reason) in [
        (0, 8, "invalid proof magic"),
        (8, 10, "unsupported proof envelope version"),
        (10, 12, "proof payload kind mismatch"),
        (12, 14, "unsupported proof schema version"),
        (14, 16, "unsupported proof protocol version"),
    ] {
        if envelope[start..end] != known[start..end] {
            return Err(Error::Invalid {
                offset: start,
                bytes: &envelope[start..end],
                reason,
            });
        }
    }
    let rank = u32::from_le_bytes(envelope[16..20].try_into().expect("four-byte rank"));
    if rank > MAX_RANK || expected_rank.is_some_and(|expected| rank != expected) {
        return Err(Error::Invalid {
            offset: 16,
            bytes: &envelope[16..20],
            reason: "invalid proof rank",
        });
    }
    let header_size =
        u64::from_le_bytes(envelope[20..28].try_into().expect("eight-byte header size"));
    if header_size > MAX_HEADER_SIZE as u64 {
        return Err(Error::Invalid {
            offset: 20,
            bytes: &envelope[20..28],
            reason: "proof header size exceeds the limit",
        });
    }
    Ok((reader, rank, header_size as usize))
}

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
