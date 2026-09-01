//! Reassembly of the `CHANNEL_PDU_HEADER` records returned by WTS DVC reads.

use std::fmt;

use crate::rdp::protocol::{HEADER_LEN, MAX_FRAME_PAYLOAD};

const PDU_HEADER_LEN: usize = 8;
const CHANNEL_FLAG_FIRST: u32 = 0x01;
const CHANNEL_FLAG_LAST: u32 = 0x02;
const KNOWN_FLAGS: u32 = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;

/// A DVC `Write` never needs to carry more than one largest ALRD frame.
const MAX_MESSAGE_LEN: usize = HEADER_LEN + MAX_FRAME_PAYLOAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    HeaderTooShort(usize),
    UnknownFlags(u32),
    MissingFirst,
    UnexpectedFirst,
    LengthChanged { expected: usize, actual: usize },
    MessageTooLarge(usize),
    LengthExceeded { expected: usize, actual: usize },
    LastLengthMismatch { expected: usize, actual: usize },
}

impl fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort(len) => write!(f, "DVC PDU header is truncated ({len} bytes)"),
            Self::UnknownFlags(flags) => write!(f, "DVC PDU contains unknown flags 0x{flags:08x}"),
            Self::MissingFirst => write!(f, "DVC fragment arrived without FIRST"),
            Self::UnexpectedFirst => write!(f, "DVC FIRST arrived while a message was in progress"),
            Self::LengthChanged { expected, actual } => write!(
                f,
                "DVC declared length changed from {expected} to {actual} between fragments"
            ),
            Self::MessageTooLarge(len) => {
                write!(f, "DVC declared message length {len} exceeds the limit")
            }
            Self::LengthExceeded { expected, actual } => write!(
                f,
                "DVC fragments contain {actual} bytes, exceeding declared length {expected}"
            ),
            Self::LastLengthMismatch { expected, actual } => write!(
                f,
                "DVC LAST completed {actual} bytes but declared {expected}"
            ),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// Strict, bounded reassembler for the 8-byte WTS `CHANNEL_PDU_HEADER`.
#[derive(Debug, Default)]
pub struct DvcReassembler {
    buffer: Vec<u8>,
    expected_len: Option<usize>,
}

impl DvcReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expected_len = None;
    }

    /// Adds one complete WTS read. A completed DVC write is returned on LAST.
    /// Any malformed sequence resets the partial message before returning.
    pub fn push(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>, ReassemblyError> {
        let result = self.push_inner(input);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn push_inner(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>, ReassemblyError> {
        if input.len() < PDU_HEADER_LEN {
            return Err(ReassemblyError::HeaderTooShort(input.len()));
        }
        let declared = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
        let flags = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
        if flags & !KNOWN_FLAGS != 0 {
            return Err(ReassemblyError::UnknownFlags(flags));
        }
        if declared > MAX_MESSAGE_LEN {
            return Err(ReassemblyError::MessageTooLarge(declared));
        }

        let first = flags & CHANNEL_FLAG_FIRST != 0;
        let last = flags & CHANNEL_FLAG_LAST != 0;
        match (first, self.expected_len) {
            (true, Some(_)) => return Err(ReassemblyError::UnexpectedFirst),
            (false, None) => return Err(ReassemblyError::MissingFirst),
            (true, None) => {
                self.expected_len = Some(declared);
                self.buffer.reserve(declared);
            }
            (false, Some(expected)) if expected != declared => {
                return Err(ReassemblyError::LengthChanged {
                    expected,
                    actual: declared,
                });
            }
            _ => {}
        }

        self.buffer.extend_from_slice(&input[PDU_HEADER_LEN..]);
        if self.buffer.len() > declared {
            return Err(ReassemblyError::LengthExceeded {
                expected: declared,
                actual: self.buffer.len(),
            });
        }
        if !last {
            return Ok(None);
        }
        if self.buffer.len() != declared {
            return Err(ReassemblyError::LastLengthMismatch {
                expected: declared,
                actual: self.buffer.len(),
            });
        }

        self.expected_len = None;
        Ok(Some(std::mem::take(&mut self.buffer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdu(length: usize, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PDU_HEADER_LEN + payload.len());
        out.extend_from_slice(&(length as u32).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn single_and_fragmented_messages_reassemble() {
        let mut r = DvcReassembler::new();
        assert_eq!(
            r.push(&pdu(3, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"abc"))
                .unwrap(),
            Some(b"abc".to_vec())
        );

        assert_eq!(r.push(&pdu(5, CHANNEL_FLAG_FIRST, b"ab")).unwrap(), None);
        assert_eq!(r.push(&pdu(5, 0, b"c")).unwrap(), None);
        assert_eq!(
            r.push(&pdu(5, CHANNEL_FLAG_LAST, b"de")).unwrap(),
            Some(b"abcde".to_vec())
        );
    }

    #[test]
    fn malformed_sequences_reset_and_recover() {
        let mut r = DvcReassembler::new();
        assert_eq!(
            r.push(&pdu(1, CHANNEL_FLAG_LAST, b"x")),
            Err(ReassemblyError::MissingFirst)
        );
        assert_eq!(r.push(&pdu(4, CHANNEL_FLAG_FIRST, b"a")).unwrap(), None);
        assert_eq!(
            r.push(&pdu(4, CHANNEL_FLAG_FIRST, b"b")),
            Err(ReassemblyError::UnexpectedFirst)
        );
        assert_eq!(
            r.push(&pdu(1, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"z"))
                .unwrap(),
            Some(b"z".to_vec())
        );
    }

    #[test]
    fn lengths_flags_and_bounds_are_strict() {
        let mut r = DvcReassembler::new();
        assert_eq!(r.push(&[0; 7]), Err(ReassemblyError::HeaderTooShort(7)));
        assert_eq!(
            r.push(&pdu(0, 0x80, b"")),
            Err(ReassemblyError::UnknownFlags(0x80))
        );
        assert_eq!(
            r.push(&pdu(MAX_MESSAGE_LEN + 1, CHANNEL_FLAG_FIRST, b"")),
            Err(ReassemblyError::MessageTooLarge(MAX_MESSAGE_LEN + 1))
        );
        assert_eq!(
            r.push(&pdu(1, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"xx")),
            Err(ReassemblyError::LengthExceeded {
                expected: 1,
                actual: 2
            })
        );
        assert_eq!(
            r.push(&pdu(2, CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, b"x")),
            Err(ReassemblyError::LastLengthMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn declared_length_must_stay_constant() {
        let mut r = DvcReassembler::new();
        r.push(&pdu(4, CHANNEL_FLAG_FIRST, b"a")).unwrap();
        assert_eq!(
            r.push(&pdu(5, CHANNEL_FLAG_LAST, b"bcd")),
            Err(ReassemblyError::LengthChanged {
                expected: 4,
                actual: 5
            })
        );
    }
}
